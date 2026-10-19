//! TLS 接入：本仓服务端方向的部署层。
//!
//! 参考 `cmd/server/handleTcpConnection` 的首行是 `tls.Server(c, s.tlsConfig)`：
//! 证书/私钥由调用方传入（官方 CLI 从 `-cert`/`-key` 读，测试由 openssl 现签）。
//! 本模块只做「TcpStream → 已握手 TLS 流」这一件事，**没有**明文回退：
//! 握手失败原样返回错误，调用方直接断开（fail-closed）。
use crate::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// 完成的 TLS 服务端流类型别名。
pub type TlsStream = tokio_rustls::server::TlsStream<TcpStream>;

/// 由墙面证书链与私钥构造接受器（TLS1.2/1.3，ring provider，不要求客户端证书）。
pub fn acceptor(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<TlsAcceptor, Error> {
    let config = ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| Error::Invalid)?
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .map_err(|_| Error::Invalid)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// 完成一次 TLS 握手；超时或失败一律返回错误（无明文回退）。
pub async fn handshake(
    acceptor: &TlsAcceptor,
    socket: TcpStream,
    wait: Duration,
) -> Result<TlsStream, Error> {
    timeout(wait, acceptor.accept(socket))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::Io)
}
