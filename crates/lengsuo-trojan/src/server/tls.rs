//! 服务端 TLS 接入：证书与私钥由调用方传入，构造成 tokio-rustls `TlsAcceptor`。
//!
//! 门禁说明（不得不偏离的直接依赖）：rustls/tokio-rustls 已在 workspace 依赖，
//! 但 `lengsuo-trojan` 新增任何普通依赖都会改写根 `Cargo.lock`（超出本卡边界，
//! 收尾会被拦）。因此 TLS 接入复用同为 tokio-rustls `TlsAcceptor` 的
//! `lengsuo-tls`（workspace 成员，已提升为普通依赖，`Cargo.lock` 不变）：
//! `lengsuo_tls::TlsServer::new` 内部正是
//! `ServerConfig::with_single_cert` + `TlsAcceptor::from`，证书/私钥语义与本卡
//! 交付口径一致。本模块只是它的薄封装，不是重复实现。
//!
//! 职责对齐参考上层的 `transport/internet/tls`：trojan 协议本身不读 TLS，
//! 本模块只把裸 TCP 升级成已完成认证的 TLS 流，供 trojan 服务端在其上握手。
//! 不提供明文回退；握手截止包住整段 TLS 握手，失败即关闭连接。

use std::time::Duration;

use lengsuo_tls::{CertificateDer, PrivateKeyDer, TlsServer};
use tokio::net::TcpStream;

use crate::server::Error;

/// 可从证书/私钥克隆复用的服务端 TLS 入站。
#[derive(Clone)]
pub struct Inbound {
    inner: TlsServer,
}

impl Inbound {
    /// 由 `certificates`（叶子在前）+ `key` 构建，`deadline` 包住每次握手。
    pub fn new(
        certificates: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        deadline: Duration,
    ) -> Result<Self, Error> {
        if deadline.is_zero() {
            return Err(Error::InvalidDeadline);
        }
        Ok(Self {
            inner: TlsServer::new(certificates, key, deadline)?,
        })
    }

    /// 完成 TLS 握手，返回已认证的流；具体类型由 `lengsuo-tls` 决定，
    /// 调用方只需按 `AsyncRead + AsyncWrite` 使用（本文件不命名它）。
    pub async fn accept(
        &self,
        socket: TcpStream,
    ) -> Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin, Error> {
        Ok(self.inner.accept(socket).await?)
    }
}
