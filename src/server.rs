//! Start the HTTPS endpoint from saved settings; shared by the CLI and the GUI.
use crate::{
    Config, app,
    auth::Registry,
    events::EventSender,
    keys::Psk,
    setup::Settings,
    tls::{self, IdentityAcceptor},
};
use axum_server::Handle;
use std::{fs, sync::Arc};

/// Serve until `handle` shuts the listener down. Settings must have resolved paths.
/// The caller must already have installed a rustls crypto provider.
pub async fn serve(
    settings: Settings,
    handle: Handle<std::net::SocketAddr>,
    events: Option<EventSender>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Load everything up front so configuration errors are reported before binding.
    let (config, acceptor) = prepare(&settings, events).map_err(|e| e.to_string())?;
    axum_server::bind(settings.listen)
        .acceptor(acceptor)
        .handle(handle)
        .serve(app(config).into_make_service())
        .await?;
    Ok(())
}

fn prepare(
    settings: &Settings,
    events: Option<EventSender>,
) -> Result<(Config, IdentityAcceptor), Box<dyn std::error::Error>> {
    let bytes = fs::read(&settings.psk_file).map_err(|e| format!("cannot read PSK file: {e}"))?;
    let psk = Psk::new(&bytes)?;
    let registry = Arc::new(Registry::from_toml(&fs::read_to_string(
        &settings.sae_map,
    )?)?);
    let tls = tls::config(
        &settings.tls_cert,
        &settings.tls_key,
        Some(&settings.tls_client_ca),
    )
    .map_err(|e| format!("cannot load TLS configuration: {e}"))?;
    let mut config = Config::new(psk);
    config.auth = Some(registry.clone());
    config.kme_id = settings.kme_id.clone();
    config.peer_kme_id = settings.peer_kme_id.clone();
    config.events = events;
    Ok((config, IdentityAcceptor::new(tls, Some(registry))))
}
