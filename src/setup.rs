//! Self-contained provisioning. No external cryptographic programs are invoked.
use crate::{
    auth::{Registry, Selector, certificate_selectors},
    keys::Psk,
    tls,
};
use clap::{Args, Subcommand};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fs,
    io::{self, IsTerminal, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};
use x509_parser::prelude::{FromDer, X509Certificate};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Subcommand)]
pub enum Command {
    /// Guided setup; preserves existing secrets and can resume after CA signing.
    Configure(Configure),
    /// Start the endpoint using saved configuration.
    Serve,
    /// Validate local provisioning without starting a listener.
    Check,
    /// Generate a CSR, install certificates, or manage trusted client CAs.
    Tls {
        #[command(subcommand)]
        command: TlsCommand,
    },
    /// Inspect an X.509 certificate and its SAE identity selectors.
    Cert {
        #[command(subcommand)]
        command: CertCommand,
    },
    /// Provision the shared secret. Generate once per endpoint pair.
    Psk {
        #[command(subcommand)]
        command: PskCommand,
    },
    /// Manage SAE IDs, stable numeric codes, and certificate selectors.
    Sae {
        #[command(subcommand)]
        command: SaeCommand,
    },
    /// Create a complete local two-endpoint test environment.
    Demo {
        #[command(subcommand)]
        command: DemoCommand,
    },
}

#[derive(Args)]
pub struct Configure {
    /// Write configuration without prompting; provision credentials with subcommands.
    #[arg(long)]
    non_interactive: bool,
    #[arg(long)]
    listen: Option<SocketAddr>,
    #[arg(long)]
    kme_id: Option<String>,
    #[arg(long)]
    peer_kme_id: Option<String>,
}

#[derive(Subcommand)]
pub enum TlsCommand {
    /// Create a PEM CSR using the existing private key, or generate a new key.
    Csr {
        #[arg(long, required_unless_present = "ip")]
        dns: Vec<String>,
        #[arg(long, required_unless_present = "dns")]
        ip: Vec<IpAddr>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Install a signed PEM leaf certificate and optional intermediate chain.
    Install {
        certificate: PathBuf,
        #[arg(long)]
        chain: Option<PathBuf>,
    },
    /// Manage trusted client CA bundles (separate from the server certificate chain).
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
}

#[derive(Subcommand)]
pub enum TrustCommand {
    Add {
        file: PathBuf,
    },
    List,
    /// Remove a CA by its SHA-256 fingerprint, as shown by list.
    Remove {
        fingerprint: String,
    },
}

#[derive(Subcommand)]
pub enum CertCommand {
    Inspect { file: PathBuf },
}

#[derive(Subcommand)]
pub enum PskCommand {
    Generate,
    Import { file: PathBuf },
}

#[derive(Subcommand)]
pub enum SaeCommand {
    Add {
        id: String,
        #[arg(long)]
        code: u16,
        /// Extract an identity selector from this certificate (does not establish trust).
        #[arg(long)]
        cert: Option<PathBuf>,
        /// One-based selector number from `cert inspect`; required if ambiguous.
        #[arg(long, requires = "cert")]
        selector: Option<usize>,
    },
    List,
    Remove {
        id: String,
    },
}

#[derive(Subcommand)]
pub enum DemoCommand {
    /// Generate two configurations, shared PSK, test CA, and client credentials.
    Init {
        #[arg(long, default_value = "qkd-demo")]
        dir: PathBuf,
    },
    /// Verify both running demo endpoints using their client certificates.
    Verify {
        #[arg(long, default_value = "qkd-demo")]
        dir: PathBuf,
        #[arg(long, default_value = "https://localhost:8443")]
        url_a: String,
        #[arg(long, default_value = "https://localhost:8444")]
        url_b: String,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub listen: SocketAddr,
    pub kme_id: String,
    pub peer_kme_id: String,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub tls_client_ca: PathBuf,
    pub psk_file: PathBuf,
    pub sae_map: PathBuf,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8443".parse().unwrap(),
            kme_id: "KME-A".into(),
            peer_kme_id: "KME-B".into(),
            tls_cert: "server.pem".into(),
            tls_key: "server.key.pem".into(),
            tls_client_ca: "client-ca.pem".into(),
            psk_file: "shared.psk".into(),
            sae_map: "sae-map.toml".into(),
        }
    }
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

impl Settings {
    pub fn load(path: &Path) -> Result<Self> {
        let config: Self = toml::from_str(&fs::read_to_string(path).map_err(|e| {
            format!(
                "cannot read {}: {e}; run `qkd-stub configure` first",
                path.display()
            )
        })?)?;
        if config.kme_id.trim().is_empty() || config.peer_kme_id.trim().is_empty() {
            return Err("KME IDs must not be empty".into());
        }
        Ok(config)
    }

    pub fn resolved(mut self, path: &Path) -> Self {
        let base = parent(path);
        for file in [
            &mut self.tls_cert,
            &mut self.tls_key,
            &mut self.tls_client_ca,
            &mut self.psk_file,
            &mut self.sae_map,
        ] {
            *file = base.join(&*file);
        }
        self
    }
}

/// Create private directories before writing any secrets. Existing directories
/// retain their administrator-selected permissions.
fn private_dir(path: &Path) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    private_dir(parent(path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    #[cfg(windows)]
    {
        use std::{os::windows::ffi::OsStrExt, ptr};
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::{
                Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SECURITY_ATTRIBUTES,
            },
            Storage::FileSystem::CreateDirectoryW,
        };
        let sddl: Vec<u16> = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)\0"
            .encode_utf16()
            .collect();
        let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut descriptor = ptr::null_mut();
        // The protected, inheritable DACL grants access only to owner and SYSTEM.
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error().into());
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let ok = CreateDirectoryW(name.as_ptr(), &attributes);
            let error = io::Error::last_os_error();
            LocalFree(descriptor);
            if ok == 0 {
                return Err(error.into());
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    fs::create_dir(path)?;
    Ok(())
}

/// Atomic writes, with exclusive creation for secrets and first-time outputs.
fn write_file(path: &Path, contents: &[u8], replace: bool) -> Result<()> {
    private_dir(parent(path))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent(path))?;
    temp.write_all(contents)?;
    temp.as_file().sync_all()?;
    if replace {
        temp.persist(path)?;
    } else {
        temp.persist_noclobber(path)?;
    }
    Ok(())
}

fn save_settings(path: &Path, settings: &Settings) -> Result<()> {
    write_file(path, toml::to_string_pretty(settings)?.as_bytes(), true)
}

fn certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let result =
        CertificateDer::pem_file_iter(path)?.collect::<std::result::Result<Vec<_>, _>>()?;
    if result.is_empty() {
        return Err(format!("no PEM certificates in {}", path.display()).into());
    }
    Ok(result)
}

fn fingerprint(cert: &CertificateDer<'_>) -> String {
    ring::digest::digest(&ring::digest::SHA256, cert.as_ref())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn pem_bundle(certificates: &[CertificateDer<'_>]) -> String {
    use base64::Engine;
    let mut out = String::new();
    for cert in certificates {
        out.push_str("-----BEGIN CERTIFICATE-----\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(cert.as_ref());
        for chunk in encoded.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
    }
    out
}

/// Displayable facts about one certificate. Contains no private material.
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub sha256: String,
    /// Identity selectors as inline TOML, in the order `sae add --selector` numbers them.
    pub selectors: Vec<String>,
}

/// Describe every certificate in a PEM file.
pub fn cert_info(path: &Path) -> Result<Vec<CertInfo>> {
    certs(path)?
        .iter()
        .map(|der| {
            let (_, cert) = X509Certificate::from_der(der)?;
            Ok(CertInfo {
                subject: cert.subject().to_string(),
                issuer: cert.issuer().to_string(),
                not_before: cert.validity().not_before.to_string(),
                not_after: cert.validity().not_after.to_string(),
                sha256: fingerprint(der),
                selectors: certificate_selectors(der)?
                    .iter()
                    .map(|s| s.to_toml_inline())
                    .collect::<std::result::Result<_, _>>()?,
            })
        })
        .collect()
}

fn inspect(path: &Path) -> Result<()> {
    for (index, info) in cert_info(path)?.iter().enumerate() {
        println!("Certificate {}: {}", index + 1, info.subject);
        println!(
            "  Issuer: {}\n  Valid: {} to {}\n  SHA-256: {}",
            info.issuer, info.not_before, info.not_after, info.sha256
        );
        for (i, selector) in info.selectors.iter().enumerate() {
            println!("  Selector {}: {}", i + 1, selector);
        }
    }
    Ok(())
}

/// Trusted client CAs, or an empty list when no bundle is provisioned.
pub fn trusted_cas(config: &Settings) -> Result<Vec<CertInfo>> {
    if config.tls_client_ca.exists() {
        cert_info(&config.tls_client_ca)
    } else {
        Ok(Vec::new())
    }
}

/// The server certificate chain, leaf first.
pub fn server_certificates(config: &Settings) -> Result<Vec<CertInfo>> {
    cert_info(&config.tls_cert)
}

fn params(names: Vec<String>, common_name: &str, client: bool) -> Result<CertificateParams> {
    let mut params = CertificateParams::new(names)?;
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![if client {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    }];
    Ok(params)
}

fn csr(config: &Settings, names: Vec<String>, out: &Path) -> Result<()> {
    if out.exists() {
        return Err(format!("{} already exists; choose a new --out path", out.display()).into());
    }
    if names.is_empty() {
        return Err("at least one server DNS name or IP address is required".into());
    }
    let params = params(names, &config.kme_id, false)?;
    let key = if config.tls_key.exists() {
        KeyPair::from_pem(&fs::read_to_string(&config.tls_key)?)?
    } else {
        let key = KeyPair::generate()?;
        write_file(&config.tls_key, key.serialize_pem().as_bytes(), false)?;
        key
    };
    write_file(
        out,
        params.serialize_request(&key)?.pem()?.as_bytes(),
        false,
    )?;
    println!(
        "CSR: {}\nPrivate key remains in: {}",
        out.display(),
        config.tls_key.display()
    );
    println!("Ask your CA for a server-authentication certificate, then run `tls install`.");
    Ok(())
}

fn validate_server(certificates: &[CertificateDer<'static>], key_path: &Path) -> Result<()> {
    let (_, leaf) = X509Certificate::from_der(&certificates[0])?;
    if !leaf.validity().is_valid() {
        return Err("server certificate is expired or not yet valid".into());
    }
    if leaf.is_ca() {
        return Err("server leaf certificate must not be a CA".into());
    }
    let san = leaf
        .subject_alternative_name()?
        .ok_or("server certificate needs DNS/IP subject alternative names")?;
    if !san.value.general_names.iter().any(|name| {
        matches!(
            name,
            x509_parser::extensions::GeneralName::DNSName(_)
                | x509_parser::extensions::GeneralName::IPAddress(_)
        )
    }) {
        return Err("server certificate needs a DNS/IP SAN".into());
    }
    if let Some(eku) = leaf.extended_key_usage()?
        && !eku.value.server_auth
        && !eku.value.any
    {
        return Err("certificate does not permit server authentication".into());
    }
    // Rustls verifies that the certificate's public key matches the private key.
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            certificates.to_vec(),
            PrivateKeyDer::from_pem_file(key_path)?,
        )?;
    for der in certificates.iter().skip(1) {
        validate_ca(der)?;
    }
    for pair in certificates.windows(2) {
        let (_, child) = X509Certificate::from_der(&pair[0])?;
        let (_, issuer) = X509Certificate::from_der(&pair[1])?;
        if child.issuer() != issuer.subject() {
            return Err("server certificate chain must be in leaf-to-issuer order".into());
        }
        child.verify_signature(Some(issuer.public_key()))?;
    }
    Ok(())
}

fn validate_ca(der: &CertificateDer<'_>) -> Result<()> {
    let (_, cert) = X509Certificate::from_der(der)?;
    if !cert.is_ca() {
        return Err(format!("{} is not a CA certificate", cert.subject()).into());
    }
    if !cert.validity().is_valid() {
        return Err(format!("CA {} is expired or not yet valid", cert.subject()).into());
    }
    if let Some(usage) = cert.key_usage()?
        && !usage.value.key_cert_sign()
    {
        return Err("CA does not permit certificate signing".into());
    }
    Ok(())
}

fn install(config: &Settings, certificate: &Path, chain: Option<&Path>) -> Result<()> {
    let mut bundle = certs(certificate)?;
    if let Some(chain) = chain {
        bundle.extend(certs(chain)?);
    }
    validate_server(&bundle, &config.tls_key)?;
    write_file(&config.tls_cert, pem_bundle(&bundle).as_bytes(), true)?;
    println!(
        "Installed server certificate: {}",
        config.tls_cert.display()
    );
    Ok(())
}

fn trust(config: &Settings, command: TrustCommand) -> Result<()> {
    let path = &config.tls_client_ca;
    let mut bundle = if path.exists() {
        certs(path)?
    } else {
        Vec::new()
    };
    match command {
        TrustCommand::Add { file } => {
            for cert in certs(&file)? {
                validate_ca(&cert)?;
                if !bundle.contains(&cert) {
                    bundle.push(cert);
                }
            }
            write_file(path, pem_bundle(&bundle).as_bytes(), true)?;
            println!("Trusted client CA bundle: {}", path.display());
        }
        TrustCommand::List => {
            if bundle.is_empty() {
                println!("No trusted client CAs configured.");
            } else {
                inspect(path)?;
            }
        }
        TrustCommand::Remove { fingerprint: value } => {
            let value = value.replace(':', "").to_ascii_lowercase();
            let before = bundle.len();
            bundle.retain(|cert| fingerprint(cert) != value);
            if before == bundle.len() {
                return Err("CA fingerprint not found".into());
            }
            if bundle.is_empty() {
                fs::remove_file(path)?;
            } else {
                write_file(path, pem_bundle(&bundle).as_bytes(), true)?;
            }
            println!("Removed trusted CA.");
        }
    }
    Ok(())
}

fn psk(config: &Settings, command: PskCommand) -> Result<()> {
    let bytes = match command {
        PskCommand::Generate => {
            let mut bytes = vec![0; 32];
            getrandom::fill(&mut bytes).map_err(|e| format!("random generator: {e}"))?;
            bytes
        }
        PskCommand::Import { file } => fs::read(file)?,
    };
    Psk::new(&bytes)?;
    write_file(&config.psk_file, &bytes, false)?;
    println!(
        "PSK stored in {}. Provision this same file on the peer; do not generate a second PSK.",
        config.psk_file.display()
    );
    Ok(())
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SaeFile {
    #[serde(default)]
    sae: Vec<Sae>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Sae {
    id: String,
    code: u16,
    #[serde(default)]
    identities: Vec<Selector>,
}

/// A configured SAE for display.
pub struct SaeEntry {
    pub id: String,
    pub code: u16,
    /// Certificate identity selectors as inline TOML.
    pub identities: Vec<String>,
}

/// SAEs from the configured registry, or an empty list when none is provisioned.
pub fn sae_entries(config: &Settings) -> Result<Vec<SaeEntry>> {
    if !config.sae_map.exists() {
        return Ok(Vec::new());
    }
    let file: SaeFile = toml::from_str(&fs::read_to_string(&config.sae_map)?)?;
    file.sae
        .into_iter()
        .map(|sae| {
            Ok(SaeEntry {
                id: sae.id,
                code: sae.code,
                identities: sae
                    .identities
                    .iter()
                    .map(|s| s.to_toml_inline())
                    .collect::<std::result::Result<_, _>>()?,
            })
        })
        .collect()
}

fn sae(config: &Settings, command: SaeCommand) -> Result<()> {
    let path = &config.sae_map;
    let mut registry: SaeFile = if path.exists() {
        toml::from_str(&fs::read_to_string(path)?)?
    } else {
        SaeFile::default()
    };
    match command {
        SaeCommand::List => {
            print!("{}", toml::to_string_pretty(&registry)?);
            return Ok(());
        }
        SaeCommand::Add {
            id,
            code,
            cert,
            selector,
        } => {
            if registry
                .sae
                .iter()
                .any(|sae| sae.id == id || sae.code == code)
            {
                return Err("SAE ID or code already exists; remove explicitly before replacing (codes must remain stable for existing key IDs)".into());
            }
            let identities = if let Some(cert) = cert {
                let certificates = certs(&cert)?;
                let selectors = certificate_selectors(&certificates[0])?;
                let index = match selector {
                    Some(index) if index > 0 && index <= selectors.len() => index - 1,
                    Some(_) => return Err("selector number out of range; see `cert inspect`".into()),
                    None if selectors.len() == 1 => 0,
                    None => return Err("certificate has multiple selectors; use `cert inspect` then --selector NUMBER".into()),
                };
                vec![selectors[index].clone()]
            } else {
                Vec::new()
            };
            registry.sae.push(Sae {
                id,
                code,
                identities,
            });
        }
        SaeCommand::Remove { id } => {
            let before = registry.sae.len();
            registry.sae.retain(|sae| sae.id != id);
            if before == registry.sae.len() {
                return Err("SAE ID not found".into());
            }
        }
    }
    let text = toml::to_string_pretty(&registry)?;
    if !registry.sae.is_empty() {
        Registry::from_toml(&text)?;
    }
    write_file(path, text.as_bytes(), true)?;
    println!(
        "Saved {}. Use identical SAE codes on both endpoints.",
        path.display()
    );
    Ok(())
}

/// One local provisioning check.
pub struct CheckItem {
    pub name: &'static str,
    pub result: std::result::Result<(), String>,
}

/// Run the local provisioning checks without printing.
pub fn check_report(config: &Settings) -> Vec<CheckItem> {
    fn item(name: &'static str, result: Result<()>) -> CheckItem {
        CheckItem {
            name,
            result: result.map_err(|e| e.to_string()),
        }
    }
    vec![
        item(
            "shared PSK",
            (|| {
                Psk::new(&fs::read(&config.psk_file)?)?;
                Ok(())
            })(),
        ),
        item(
            "server certificate and private key",
            (|| validate_server(&certs(&config.tls_cert)?, &config.tls_key))(),
        ),
        item(
            "trusted client CAs",
            (|| {
                for cert in certs(&config.tls_client_ca)? {
                    validate_ca(&cert)?;
                }
                Ok(())
            })(),
        ),
        item(
            "SAE registry",
            (|| {
                let text = fs::read_to_string(&config.sae_map)?;
                Registry::from_toml(&text)?;
                let registry: SaeFile = toml::from_str(&text)?;
                if !registry.sae.iter().any(|sae| !sae.identities.is_empty()) {
                    return Err("no local client certificate identities configured".into());
                }
                Ok(())
            })(),
        ),
    ]
}

fn check(config: &Settings) -> Result<()> {
    let mut errors = Vec::new();
    for item in check_report(config) {
        match item.result {
            Ok(()) => println!("OK  {}", item.name),
            Err(error) => {
                println!("MISSING/INVALID  {}: {error}", item.name);
                errors.push(item.name);
            }
        }
    }
    if !errors.is_empty() {
        return Err(format!("setup incomplete: {}", errors.join(", ")).into());
    }
    tls::config(
        &config.tls_cert,
        &config.tls_key,
        Some(&config.tls_client_ca),
    )?;
    println!(
        "Local setup is ready at {}. Peer PSK/code agreement and CA chain trust must be checked separately.",
        config.listen
    );
    Ok(())
}

fn prompt(label: &str, default: &str) -> Result<String> {
    print!("{label} [{default}]: ");
    io::stdout().flush()?;
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        return Err("input closed; saved configuration can be resumed with `configure`".into());
    }
    let line = line.trim();
    Ok(if line.is_empty() {
        default.to_owned()
    } else {
        line.to_owned()
    })
}

fn configure(path: &Path, args: Configure) -> Result<()> {
    if !args.non_interactive && !io::stdin().is_terminal() {
        return Err(
            "interactive setup requires a terminal; use --non-interactive for scripts".into(),
        );
    }
    let mut config = if path.exists() {
        Settings::load(path)?
    } else {
        Settings::default()
    };
    if let Some(listen) = args.listen {
        config.listen = listen;
    }
    if let Some(id) = args.kme_id {
        config.kme_id = id;
    }
    if let Some(id) = args.peer_kme_id {
        config.peer_kme_id = id;
    }
    if !args.non_interactive {
        config.kme_id = prompt("KME ID", &config.kme_id)?;
        config.peer_kme_id = prompt("Peer KME ID", &config.peer_kme_id)?;
        config.listen = prompt("Listen address", &config.listen.to_string())?.parse()?;
    }
    if config.kme_id.trim().is_empty() || config.peer_kme_id.trim().is_empty() {
        return Err("KME IDs must not be empty".into());
    }
    save_settings(path, &config)?;
    println!("Configuration: {}", path.display());
    if args.non_interactive {
        return Ok(());
    }
    let config = config.resolved(path);
    if !config.tls_cert.exists() {
        let signed = prompt(
            "Signed server certificate PEM (leave blank to create/reuse CSR)",
            "",
        )?;
        if !signed.is_empty() {
            if !config.tls_key.exists() {
                let key = prompt("Existing private key PEM to import", "")?;
                let pem = fs::read_to_string(key)?;
                KeyPair::from_pem(&pem)?;
                write_file(&config.tls_key, pem.as_bytes(), false)?;
            }
            let chain = prompt("Intermediate chain PEM (optional)", "")?;
            install(
                &config,
                Path::new(&signed),
                if chain.is_empty() {
                    None
                } else {
                    Some(Path::new(&chain))
                },
            )?;
        } else {
            let out = parent(path).join("server.csr.pem");
            if out.exists() {
                println!("CSR awaiting CA signing: {}", out.display());
            } else {
                let names = prompt(
                    "Server DNS names/IPs, comma-separated",
                    "localhost,127.0.0.1",
                )?;
                csr(
                    &config,
                    names.split(',').map(|s| s.trim().to_owned()).collect(),
                    &out,
                )?;
            }
        }
    }
    if !config.psk_file.exists() {
        let choice = prompt("PSK: generate, import, or later", "later")?;
        match choice.as_str() {
            "generate" => psk(&config, PskCommand::Generate)?,
            "import" => psk(
                &config,
                PskCommand::Import {
                    file: prompt("Peer PSK file", "")?.into(),
                },
            )?,
            "later" => {}
            _ => return Err("choose generate, import, or later".into()),
        }
    }
    if !config.tls_client_ca.exists() {
        let ca = prompt("Trusted client CA PEM (blank to provision later)", "")?;
        if !ca.is_empty() {
            trust(&config, TrustCommand::Add { file: ca.into() })?;
        }
    }
    loop {
        let id = prompt("Add SAE ID (blank to finish)", "")?;
        if id.is_empty() {
            break;
        }
        let code = prompt("Stable numeric SAE code (same on peer)", "")?.parse()?;
        let cert = prompt("Client certificate PEM (blank for remote-only SAE)", "")?;
        let selector = if cert.is_empty() {
            None
        } else {
            inspect(Path::new(&cert))?;
            Some(prompt("Identity selector number", "1")?.parse()?)
        };
        sae(
            &config,
            SaeCommand::Add {
                id,
                code,
                cert: if cert.is_empty() {
                    None
                } else {
                    Some(cert.into())
                },
                selector,
            },
        )?;
    }
    if let Err(error) = check(&config) {
        println!("{error}\nResume with `configure`, or use the provisioning subcommands.");
    }
    Ok(())
}

fn demo(dir: &Path) -> Result<()> {
    if dir.exists() {
        return Err(
            "demo directory already exists; choose a new --dir to preserve existing credentials"
                .into(),
        );
    }
    private_dir(dir)?;
    let ca_key = KeyPair::generate()?;
    let mut ca_params = params(Vec::new(), "QKD stub demo CA", false)?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.extended_key_usages.clear();
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    write_file(&dir.join("ca.pem"), ca_cert.pem().as_bytes(), false)?;
    // The demo CA private key is intentionally not retained.
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).map_err(|e| format!("random generator: {e}"))?;
    write_file(&dir.join("shared.psk"), &secret, false)?;
    for (name, client) in [
        ("server-a", false),
        ("server-b", false),
        ("client-a", true),
        ("client-b", true),
    ] {
        let key = KeyPair::generate()?;
        let names = if client {
            vec![]
        } else {
            vec!["localhost".into(), "127.0.0.1".into(), "::1".into()]
        };
        let cert = params(names, name, client)?.signed_by(&key, &issuer)?;
        write_file(
            &dir.join(format!("{name}.pem")),
            cert.pem().as_bytes(),
            false,
        )?;
        write_file(
            &dir.join(format!("{name}.key.pem")),
            key.serialize_pem().as_bytes(),
            false,
        )?;
    }
    let registry = SaeFile {
        sae: vec![
            Sae {
                id: "A".into(),
                code: 1,
                identities: vec![Selector::SubjectDn("CN=client-a".into())],
            },
            Sae {
                id: "B".into(),
                code: 2,
                identities: vec![Selector::SubjectDn("CN=client-b".into())],
            },
        ],
    };
    write_file(
        &dir.join("sae-map.toml"),
        toml::to_string_pretty(&registry)?.as_bytes(),
        false,
    )?;
    for (name, peer, port) in [("a", "B", 8443), ("b", "A", 8444)] {
        let config = Settings {
            listen: format!("127.0.0.1:{port}").parse()?,
            kme_id: format!("KME-{}", name.to_uppercase()),
            peer_kme_id: format!("KME-{peer}"),
            tls_cert: format!("server-{name}.pem").into(),
            tls_key: format!("server-{name}.key.pem").into(),
            tls_client_ca: "ca.pem".into(),
            ..Settings::default()
        };
        let path = dir.join(format!("{name}.toml"));
        save_settings(&path, &config)?;
        check(&config.resolved(&path))?;
    }
    println!(
        "Demo created. Start in separate terminals:\n  qkd-stub --config \"{}\" serve\n  qkd-stub --config \"{}\" serve",
        dir.join("a.toml").display(),
        dir.join("b.toml").display()
    );
    println!(
        "Client credentials: client-a.pem/client-a.key.pem and client-b.pem/client-b.key.pem. Trust ca.pem. Test CA expires in one year."
    );
    Ok(())
}

async fn demo_verify(dir: &Path, url_a: &str, url_b: &str) -> Result<()> {
    let ca = reqwest::Certificate::from_pem(&fs::read(dir.join("ca.pem"))?)?;
    let client = |name: &str| -> Result<reqwest::Client> {
        let mut identity = fs::read(dir.join(format!("client-{name}.pem")))?;
        identity.extend(fs::read(dir.join(format!("client-{name}.key.pem")))?);
        Ok(reqwest::Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca.clone())
            .identity(reqwest::Identity::from_pem(&identity)?)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()?)
    };
    let a = client("a")?;
    let b = client("b")?;
    for (sender, receiver, sender_url, receiver_url, master, slave) in [
        (&a, &b, url_a, url_b, "A", "B"),
        (&b, &a, url_b, url_a, "B", "A"),
    ] {
        let issued: serde_json::Value = sender
            .get(format!(
                "{}/api/v1/keys/{slave}/enc_keys",
                sender_url.trim_end_matches('/')
            ))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let key = &issued["keys"][0];
        let id = key["key_ID"]
            .as_str()
            .ok_or("issuance response has no key ID")?;
        let material = key["key"].as_str().ok_or("issuance response has no key")?;
        let retrieved: serde_json::Value = receiver
            .get(format!(
                "{}/api/v1/keys/{master}/dec_keys",
                receiver_url.trim_end_matches('/')
            ))
            .query(&[("key_ID", id)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if retrieved["keys"][0]["key"].as_str() != Some(material)
            || retrieved["keys"][0]["key_ID"].as_str() != Some(id)
        {
            return Err("endpoints returned different keys or IDs".into());
        }
        println!("OK  {master} -> {slave}: matching key retrieved over authenticated TLS");
    }
    Ok(())
}

pub async fn run(command: Command, path: &Path) -> Result<Option<Settings>> {
    match command {
        Command::Configure(args) => configure(path, args)?,
        Command::Demo {
            command: DemoCommand::Init { dir },
        } => demo(&dir)?,
        Command::Demo {
            command: DemoCommand::Verify { dir, url_a, url_b },
        } => demo_verify(&dir, &url_a, &url_b).await?,
        Command::Cert {
            command: CertCommand::Inspect { file },
        } => inspect(&file)?,
        command => {
            let config = Settings::load(path)?.resolved(path);
            eprintln!("Configuration: {}", path.display());
            match command {
                Command::Serve => {
                    check(&config)?;
                    return Ok(Some(config));
                }
                Command::Check => check(&config)?,
                Command::Tls { command } => match command {
                    TlsCommand::Csr { mut dns, ip, out } => {
                        dns.extend(ip.iter().map(ToString::to_string));
                        csr(
                            &config,
                            dns,
                            &out.unwrap_or_else(|| parent(path).join("server.csr.pem")),
                        )?;
                    }
                    TlsCommand::Install { certificate, chain } => {
                        install(&config, &certificate, chain.as_deref())?
                    }
                    TlsCommand::Trust { command } => trust(&config, command)?,
                },
                Command::Psk { command } => psk(&config, command)?,
                Command::Sae { command } => sae(&config, command)?,
                _ => unreachable!(),
            }
        }
    }
    Ok(None)
}
