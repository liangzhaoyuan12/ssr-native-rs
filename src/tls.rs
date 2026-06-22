use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use std::sync::Arc;
use tokio_rustls::TlsConnector;

pub fn create_tls_connector() -> crate::error::Result<TlsConnector> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

pub fn server_name(domain: &str) -> crate::error::Result<ServerName<'_>> {
    ServerName::try_from(domain)
        .map_err(|e| crate::error::Error::Tls(format!("invalid server name: {}", e)))
}
