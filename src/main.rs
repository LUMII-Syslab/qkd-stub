use axum_server::Handle;
use clap::Parser;
use qkd_stub::{
    Config, app,
    auth::{Registry, certificate_selectors},
    keys::Psk,
    tls::{self, IdentityAcceptor},
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

#[derive(Parser)]
#[command(
    version,
    about = "HTTPS ETSI QKD 014 test stub. PSK-derived keys and certificate-based SAE authorization by default."
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    #[arg(long, required_unless_present = "inspect_cert")]
    tls_cert: Option<PathBuf>,
    #[arg(long, required_unless_present = "inspect_cert")]
    tls_key: Option<PathBuf>,
    /// PEM CA bundle for verifying client certificates (required unless --no-sae-binding).
    #[arg(long, requires = "sae_map", required_unless_present_any = ["no_sae_binding", "inspect_cert"], conflicts_with = "no_sae_binding")]
    tls_client_ca: Option<PathBuf>,
    /// JSON SAE registry and certificate identity mapping (requires mutual TLS).
    #[arg(long, requires = "tls_client_ca", required_unless_present_any = ["no_sae_binding", "inspect_cert"], conflicts_with = "no_sae_binding")]
    sae_map: Option<PathBuf>,
    /// Shared secret file containing exactly 32 raw random bytes.
    #[arg(long, required_unless_present = "inspect_cert")]
    psk_file: Option<PathBuf>,
    /// Explicitly disable client authentication and SAE authorization.
    #[arg(long)]
    no_sae_binding: bool,
    /// Print certificate identity selectors for use in an SAE mapping, then exit.
    #[arg(long, conflicts_with_all = ["tls_cert", "tls_key", "tls_client_ca", "sae_map", "psk_file", "no_sae_binding"])]
    inspect_cert: Option<PathBuf>,
    #[arg(long, default_value = "sae-local")]
    sae_id: String,
    #[arg(long, default_value = "kme-local")]
    kme_id: String,
    #[arg(long, default_value = "kme-peer")]
    peer_kme_id: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if let Some(path) = &args.inspect_cert {
        let cert = CertificateDer::pem_file_iter(path)?
            .next()
            .ok_or("certificate PEM file is empty")??;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"identities": certificate_selectors(cert.as_ref())?})
            )?
        );
        return Ok(());
    }
    let psk_path = args.psk_file.as_ref().ok_or("--psk-file is required")?;
    let bytes = std::fs::read(psk_path).map_err(|e| format!("cannot read PSK file: {e}"))?;
    let psk = Arc::new(Psk::new(&bytes)?);
    let registry = args
        .sae_map
        .as_ref()
        .map(|path| -> Result<_, Box<dyn std::error::Error>> {
            Ok(Arc::new(Registry::from_json(&std::fs::read_to_string(
                path,
            )?)?))
        })
        .transpose()?;
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "could not install TLS crypto provider")?;
    let tls = tls::config(
        args.tls_cert.as_deref().ok_or("--tls-cert is required")?,
        args.tls_key.as_deref().ok_or("--tls-key is required")?,
        args.tls_client_ca.as_deref(),
    )
    .map_err(|e| format!("cannot load TLS configuration: {e}"))?;
    let handle = Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("install SIGTERM handler");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        shutdown.graceful_shutdown(Some(Duration::from_secs(5)));
    });
    eprintln!(
        "QKD test stub at https://{} (PSK-derived keys; {})",
        args.listen,
        if registry.is_some() {
            "certificate-based SAE authorization enabled"
        } else {
            "no client authentication"
        }
    );
    axum_server::bind(args.listen)
        .acceptor(IdentityAcceptor::new(tls, registry.clone()))
        .handle(handle)
        .serve(
            app(Config {
                auth: registry,
                psk,
                sae_id: args.sae_id,
                kme_id: args.kme_id,
                peer_kme_id: args.peer_kme_id,
            })
            .into_make_service(),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn require_psk_and_explicit_sae_opt_out() {
        let base = ["qkd-stub", "--tls-cert", "cert", "--tls-key", "key"];
        let parse = |extra: &[&str]| Args::try_parse_from(base.iter().chain(extra));
        assert!(parse(&[]).is_err());
        assert!(parse(&["--no-sae-binding"]).is_err());
        assert!(parse(&["--psk-file", "psk"]).is_err());
        assert!(
            parse(&[
                "--psk-file",
                "psk",
                "--tls-client-ca",
                "ca",
                "--sae-map",
                "map"
            ])
            .is_ok()
        );
        assert!(parse(&["--psk-file", "psk", "--no-sae-binding"]).is_ok());
        assert!(parse(&["--no-psk", "--no-sae-binding"]).is_err());
        assert!(parse(&["--psk-file", "psk", "--no-psk", "--no-sae-binding"]).is_err());
        assert!(
            parse(&[
                "--psk-file",
                "psk",
                "--no-sae-binding",
                "--tls-client-ca",
                "ca",
                "--sae-map",
                "map"
            ])
            .is_err()
        );
        assert!(Args::try_parse_from(["qkd-stub", "--inspect-cert", "cert"]).is_ok());
    }
}
