use axum_server::{Handle, tls_rustls::RustlsConfig};
use clap::Parser;
use qkd_stub::{Config, app};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    version,
    about = "HTTPS ETSI QKD 014 test stub. Keys are publicly reproducible; no authentication."
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    #[arg(long)]
    tls_cert: PathBuf,
    #[arg(long)]
    tls_key: PathBuf,
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
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "could not install TLS crypto provider")?;
    let tls = RustlsConfig::from_pem_file(&args.tls_cert, &args.tls_key)
        .await
        .map_err(|e| format!("cannot load TLS certificate/key: {e}"))?;
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
        "QKD test stub at https://{} (publicly reproducible keys; no client authentication)",
        args.listen
    );
    axum_server::bind_rustls(args.listen, tls)
        .handle(handle)
        .serve(
            app(Config {
                sae_id: args.sae_id,
                kme_id: args.kme_id,
                peer_kme_id: args.peer_kme_id,
            })
            .into_make_service(),
        )
        .await?;
    Ok(())
}
