//! Exercise the shipped executable, including the CSR round-trip and real mTLS.
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use std::{
    fs,
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

fn invoke(dir: &Path, args: &[&str], success: bool) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_qkd-stub"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert_eq!(
        output.status.success(),
        success,
        "{args:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn csr_provisioning_is_resumable_and_preserves_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let config = root.join("qkd-stub-data");
    invoke(root, &["configure", "--non-interactive"], true);
    invoke(root, &["configure"], false);
    invoke(root, &["check"], false);
    invoke(
        root,
        &["tls", "csr", "--dns", "localhost", "--ip", "127.0.0.1"],
        true,
    );
    let key = fs::read(config.join("server.key.pem")).unwrap();
    let original = fs::read(config.join("server.csr.pem")).unwrap();
    invoke(root, &["tls", "csr", "--dns", "localhost"], false);
    assert_eq!(fs::read(config.join("server.csr.pem")).unwrap(), original);
    invoke(
        root,
        &["tls", "csr", "--ip", "127.0.0.1", "--out", "renewal.pem"],
        true,
    );
    assert_eq!(fs::read(config.join("server.key.pem")).unwrap(), key);

    // Sign the actual generated CSR as an external CA would.
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let csr =
        CertificateSigningRequestParams::from_pem(std::str::from_utf8(&original).unwrap()).unwrap();
    let cert = csr.signed_by(&issuer).unwrap();
    fs::write(root.join("signed.pem"), cert.pem()).unwrap();
    fs::write(root.join("ca.pem"), ca.pem()).unwrap();
    invoke(
        root,
        &["tls", "install", "signed.pem", "--chain", "ca.pem"],
        true,
    );
    let installed = fs::read(config.join("server.pem")).unwrap();
    // A mismatching certificate or non-CA trust input must not replace good state.
    let other_key = KeyPair::generate().unwrap();
    let other = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&other_key, &issuer)
        .unwrap();
    fs::write(root.join("wrong.pem"), other.pem()).unwrap();
    invoke(root, &["tls", "install", "wrong.pem"], false);
    assert_eq!(fs::read(config.join("server.pem")).unwrap(), installed);
    invoke(root, &["tls", "trust", "add", "signed.pem"], false);
    invoke(root, &["tls", "trust", "add", "ca.pem"], true);
    invoke(root, &["tls", "trust", "add", "ca.pem"], true);
    let trust = fs::read(config.join("client-ca.pem")).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&trust)
            .matches("BEGIN CERTIFICATE")
            .count(),
        1
    );

    invoke(root, &["psk", "generate"], true);
    let secret = fs::read(config.join("shared.psk")).unwrap();
    assert_eq!(secret.len(), 32);
    invoke(root, &["psk", "generate"], false);
    invoke(root, &["psk", "import", "ca.pem"], false);
    invoke(
        root,
        &["configure", "--non-interactive", "--kme-id", "renamed"],
        true,
    );
    assert_eq!(fs::read(config.join("shared.psk")).unwrap(), secret);
    assert_eq!(fs::read(config.join("server.key.pem")).unwrap(), key);
    invoke(
        root,
        &["sae", "add", "A", "--code", "1", "--cert", "signed.pem"],
        false,
    );
    invoke(
        root,
        &[
            "sae",
            "add",
            "A",
            "--code",
            "1",
            "--cert",
            "signed.pem",
            "--selector",
            "1",
        ],
        true,
    );
    invoke(root, &["sae", "add", "B", "--code", "2"], true);
    let registry = fs::read(config.join("sae-map.toml")).unwrap();
    invoke(root, &["sae", "add", "C", "--code", "2"], false);
    assert_eq!(fs::read(config.join("sae-map.toml")).unwrap(), registry);
    invoke(root, &["check"], true);
    // Config-relative paths must work from a different working directory.
    invoke(
        root.parent().unwrap(),
        &[
            "--config",
            config.join("config.toml").to_str().unwrap(),
            "check",
        ],
        true,
    );

    let fingerprint: String = ring::digest::digest(&ring::digest::SHA256, ca.der().as_ref())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    invoke(root, &["tls", "trust", "remove", &fingerprint], true);
    invoke(root, &["check"], false);
    invoke(root, &["tls", "trust", "add", "ca.pem"], true);
    invoke(root, &["check"], true);

    // The peer imports the same secret rather than generating an unrelated one.
    invoke(
        root,
        &[
            "--config",
            "peer/config.toml",
            "configure",
            "--non-interactive",
        ],
        true,
    );
    invoke(
        root,
        &[
            "--config",
            "peer/config.toml",
            "psk",
            "import",
            "qkd-stub-data/shared.psk",
        ],
        true,
    );
    assert_eq!(fs::read(root.join("peer/shared.psk")).unwrap(), secret);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(config.join("server.key.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(config.join("shared.psk"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(root: &Path, name: &str) -> (Server, u16) {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = root.join(format!("demo/{name}.toml"));
    let mut value: toml::Value = toml::from_str(&fs::read_to_string(&config).unwrap()).unwrap();
    value["listen"] = format!("127.0.0.1:{port}").into();
    fs::write(&config, toml::to_string(&value).unwrap()).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_qkd-stub"))
        .current_dir(root)
        .args(["--config", config.to_str().unwrap(), "serve"])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut server = Server(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "server exited before listening"
        );
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "server did not start");
        thread::sleep(Duration::from_millis(20));
    }
    (server, port)
}

#[test]
fn standalone_demo_roundtrip_and_wrong_psk_detection() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    invoke(root, &["demo", "init", "--dir", "demo"], true);
    invoke(root, &["demo", "init", "--dir", "demo"], false);
    let (_a, port_a) = start(root, "a");
    let (b, port_b) = start(root, "b");
    let url_a = format!("https://localhost:{port_a}");
    let url_b = format!("https://localhost:{port_b}");
    let verify = [
        "demo", "verify", "--dir", "demo", "--url-a", &url_a, "--url-b", &url_b,
    ];
    invoke(root, &verify, true);
    drop(b);
    let config = root.join("demo/b.toml");
    let mut value: toml::Value = toml::from_str(&fs::read_to_string(&config).unwrap()).unwrap();
    value["psk_file"] = "wrong.psk".into();
    fs::write(&config, toml::to_string(&value).unwrap()).unwrap();
    fs::write(root.join("demo/wrong.psk"), [42; 32]).unwrap();
    let (_b, port_b) = start(root, "b");
    let url_b = format!("https://localhost:{port_b}");
    invoke(
        root,
        &[
            "demo", "verify", "--dir", "demo", "--url-a", &url_a, "--url-b", &url_b,
        ],
        false,
    );
}
