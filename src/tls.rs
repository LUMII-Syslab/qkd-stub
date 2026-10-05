//! Attach the verified TLS leaf certificate's identity to each HTTP connection.
use crate::auth::{PeerIdentity, Registry};
use axum::{Extension, middleware::AddExtension};
use axum_server::{
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use std::{future::Future, io, path::Path, pin::Pin, sync::Arc};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tower::Layer;

pub fn config(
    cert: &Path,
    key: &Path,
    client_ca: Option<&Path>,
) -> Result<RustlsConfig, Box<dyn std::error::Error>> {
    let certificates = CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?;
    let private_key = PrivateKeyDer::from_pem_file(key)?;
    let builder = ServerConfig::builder();
    let builder = if let Some(path) = client_ca {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter(path)? {
            roots.add(cert?)?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let mut config = builder.with_single_cert(certificates, private_key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(config)))
}

#[derive(Clone)]
pub struct IdentityAcceptor {
    inner: RustlsAcceptor,
    registry: Option<Arc<Registry>>,
}
impl IdentityAcceptor {
    pub fn new(config: RustlsConfig, registry: Option<Arc<Registry>>) -> Self {
        Self {
            inner: RustlsAcceptor::new(config),
            registry,
        }
    }
}
impl<S: Send + 'static> Accept<TcpStream, S> for IdentityAcceptor {
    type Stream = TlsStream<TcpStream>;
    type Service = AddExtension<S, PeerIdentity>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;
    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let future = self.inner.accept(stream, service);
        let registry = self.registry.clone();
        Box::pin(async move {
            // Rustls validates the chain, validity, usage, and proof of possession
            // before exposing a peer certificate here.
            let (stream, service) = future.await?;
            let identity = registry.as_ref().and_then(|r| {
                let cert = stream.get_ref().1.peer_certificates()?.first()?;
                r.identify(cert.as_ref()).ok()
            });
            Ok((stream, Extension(PeerIdentity(identity)).layer(service)))
        })
    }
}
