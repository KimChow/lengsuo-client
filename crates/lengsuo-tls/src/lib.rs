#![forbid(unsafe_code)]
//! Authenticated TLS transport with a deadline spanning connect and handshake.
//! This is standard TLS, not a browser ClientHello fingerprint implementation.
//! Application protocol authentication remains mandatory above this layer.

pub use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TLS deadline must be positive")]
    InvalidDeadline,
    #[error("TLS requires at least one trust anchor")]
    EmptyTrustStore,
    #[error("invalid TLS server name")]
    InvalidServerName,
    #[error("TLS connection deadline exceeded")]
    Timeout,
    #[error("TLS configuration rejected: {0}")]
    Configuration(#[from] rustls::Error),
    #[error("TLS connection failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone)]
pub struct TlsClient {
    name: ServerName<'static>,
    connector: TlsConnector,
    deadline: Duration,
}

impl TlsClient {
    pub fn new(
        name: &str,
        roots: impl IntoIterator<Item = CertificateDer<'static>>,
        deadline: Duration,
    ) -> Result<Self, Error> {
        if deadline.is_zero() {
            return Err(Error::InvalidDeadline);
        }
        let name = ServerName::try_from(name.to_owned()).map_err(|_| Error::InvalidServerName)?;
        let mut store = RootCertStore::empty();
        for certificate in roots {
            store.add(certificate)?;
        }
        if store.is_empty() {
            return Err(Error::EmptyTrustStore);
        }
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(store)
                .with_no_client_auth();
        Ok(Self {
            name,
            connector: TlsConnector::from(Arc::new(config)),
            deadline,
        })
    }

    /// The endpoint may be an IP while certificate identity is checked against name.
    /// No plaintext socket is returned if TLS authentication or handshake fails.
    pub async fn connect(
        &self,
        endpoint: SocketAddr,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Error> {
        timeout(self.deadline, async {
            let socket = TcpStream::connect(endpoint).await?;
            Ok(self.connector.connect(self.name.clone(), socket).await?)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}

#[derive(Clone)]
pub struct TlsServer {
    acceptor: TlsAcceptor,
    deadline: Duration,
}

impl TlsServer {
    pub fn new(
        certificates: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        deadline: Duration,
    ) -> Result<Self, Error> {
        if deadline.is_zero() {
            return Err(Error::InvalidDeadline);
        }
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(certificates, key)?;
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            deadline,
        })
    }

    pub async fn accept(
        &self,
        socket: TcpStream,
    ) -> Result<tokio_rustls::server::TlsStream<TcpStream>, Error> {
        timeout(self.deadline, self.acceptor.accept(socket))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)
    }
}
