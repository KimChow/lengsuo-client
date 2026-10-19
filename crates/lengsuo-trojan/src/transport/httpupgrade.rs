//! HTTPUpgrade 外层传输（client 侧），对齐参考
//! `transport/internet/httpupgrade/{dialer,connection}.go`。
//!
//! 参考把它叫“fake websocket upgrade”：请求就是一个普通 HTTP/1.1 Upgrade
//! （`GET <path>` + `Connection: Upgrade` + `Upgrade: websocket`），与 WS 握手
//! **完全一样**；区别只在升级点之后——**没有 WebSocket 帧**，升级点之后的每个
//! 字节直接是应用流量。参考 `ConnRF.Read`：首次读时用 `http.ReadResponse` 消费
//! 101 响应头，把同一 reader 里已缓冲的剩余字节（`reader.Buffered()`）一次性交回，
//! 之后 `ConnRF` 直接透传底层 `Conn`。
//!
//! 因此本模块的 `Client::upgrade` 只做两件事：
//!
//! 1. 写升级请求（与 WS 相同的三元组；参考的 httpupgrade dialer **不**发送
//!    `Sec-WebSocket-Key`/`Version`，本模块也不发——线上字节对齐参考）；
//! 2. 读到 `\r\n\r\n` 为止（`101 + Connection: Upgrade + Upgrade: websocket`），
//!    **不消费其后任何字节**，直接把底层流交给 trojan。
//!
//! 与参考 `ConnRF` 的等价性：参考的首读会同时吞掉 101 头与其后缓冲到的字节，
//! 再返回缓冲字节。本模块把“其后字节留在流上”交给后续读，读到的是同一串字节，
//! 只是**消费时机**不同（参考在首读一并交出，本模块按需读取）——对上层字节流
//! 语义完全等价，因为 `read_response` 逐字节读、恰好停在 `\r\n\r\n` 之后，
//! 不会多读一个字节。

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use crate::transport::http;
use crate::transport::{check_deadline, Error};

/// HTTPUpgrade 客户端配置。
#[derive(Debug, Clone)]
pub struct Client {
    path: String,
    host: String,
    server_name: String,
}

impl Client {
    /// `path` 允许不带前导 `/`（对齐 `GetNormalizedPath`）；`host` 为空时回退
    /// 到 `server_name`，仍为空则回退到连接目标字面量。
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        host: impl Into<String>,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            host: host.into(),
            server_name: server_name.into(),
        }
    }
}

impl Client {
    /// 在 `stream`（已完成认证 TLS）上完成 HTTPUpgrade 升级握手，返回裸字节流。
    /// `wait` 覆盖整个握手（请求写出 + 响应读取）。
    pub async fn upgrade<S>(&self, stream: S, wait: Duration) -> Result<Upgraded<S>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        check_deadline(wait)?;
        timeout(wait, self.handshake(stream))
            .await
            .map_err(|_| Error::Timeout)?
    }

    async fn handshake<S>(&self, mut stream: S) -> Result<Upgraded<S>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let authority = self.host.clone();
        // 参考 httpupgrade dialer 只设 Connection/Upgrade（外加 net/http 自动的
        // Host）；不发 Sec-WebSocket-* 头。
        let headers = vec![
            (
                "Host".to_owned(),
                http::host_header(&self.host, &self.server_name, &authority),
            ),
            ("Connection".to_owned(), "Upgrade".to_owned()),
            ("Upgrade".to_owned(), "websocket".to_owned()),
        ];
        let path = http::normalize_path(&self.path);
        let outer = Duration::from_secs(86_400);
        http::write_request(&mut stream, &path, &headers, outer).await?;
        let response = http::read_response(&mut stream, outer).await?;
        response.is_switching_protocols()?;
        Ok(Upgraded { inner: stream })
    }
}

/// 升级后的裸字节流：trojan 直接在其上收发，无帧层。
///
/// 参考 `connection`/`ConnRF` 在升级后就是透传；这里同样只做透明转发，
/// 不做任何分帧或改写。
pub struct Upgraded<S> {
    inner: S,
}

impl<S> Upgraded<S> {
    /// 由已完成 HTTPUpgrade 升级握手的底层流构造（服务端侧由
    /// `transport::server::accept_httpupgrade` 调用）。升级点之后无任何帧层。
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Upgraded<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Upgraded<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
