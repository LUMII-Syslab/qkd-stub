use axum_server::Handle;
use clap::Parser;
use qkd_stub::{
    Config, app,
    auth::Registry,
    keys::Psk,
    tls::{self, IdentityAcceptor},
};
use std::{path::PathBuf, sync::Arc, time::Duration};

mod setup;

#[derive(Parser)]
#[command(
    version,
    arg_required_else_help = true,
    about = "HTTPS ETSI QKD 014 test stub. PSK-derived keys and certificate-based SAE authorization.",
    after_help = "Getting started:\n  qkd-stub configure     Guided device-style provisioning\n  qkd-stub demo init     Create a complete local two-endpoint demo\n  qkd-stub <command> --help"
)]
struct Args {
    #[command(subcommand)]
    command: setup::Command,
    /// Saved configuration (relative file paths are resolved beside this file).
    #[arg(long, global = true, default_value = "qkd-stub-data/config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "could not install TLS crypto provider")?;
    let Some(settings) = setup::run(args.command, &args.config).await? else {
        return Ok(());
    };
    let bytes =
        std::fs::read(&settings.psk_file).map_err(|e| format!("cannot read PSK file: {e}"))?;
    let psk = Psk::new(&bytes)?;
    let registry = Arc::new(Registry::from_toml(&std::fs::read_to_string(
        &settings.sae_map,
    )?)?);
    let tls = tls::config(
        &settings.tls_cert,
        &settings.tls_key,
        Some(&settings.tls_client_ca),
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
        #[cfg(windows)]
        {
            let mut ctrl_break =
                tokio::signal::windows::ctrl_break().expect("install Ctrl-Break handler");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = ctrl_break.recv() => {} }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        shutdown.graceful_shutdown(Some(Duration::from_secs(5)));
    });
    eprintln!(
        "QKD test stub at https://{} (PSK-derived keys; certificate-based SAE authorization enabled)",
        settings.listen
    );
    let mut config = Config::new(psk);
    config.auth = Some(registry.clone());
    config.kme_id = settings.kme_id;
    config.peer_kme_id = settings.peer_kme_id;
    axum_server::bind(settings.listen)
        .acceptor(IdentityAcceptor::new(tls, Some(registry)))
        .handle(handle)
        .serve(app(config).into_make_service())
        .await?;
    Ok(())
}
