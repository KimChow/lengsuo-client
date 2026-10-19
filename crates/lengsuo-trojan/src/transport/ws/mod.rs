//! WebSocket 外层传输（client 侧），对齐参考
//! `transport/internet/websocket/{dialer,connection}.go`（gorilla/websocket）。
//!
//! 线上时序：
//!
//! 1. 客户端在已认证 TLS 流上写 `GET <path> HTTP/1.1` 升级请求，带
//!    `Host` / `Connection: Upgrade` / `Upgrade: websocket` /
//!    `Sec-WebSocket-Version: 13` / `Sec-WebSocket-Key`（16 字节随机数 base64）。
//! 2. 服务端回 `101 Switching Protocols`，`Sec-WebSocket-Accept` 必须是
//!    `base64(SHA1(key + GUID))`；不匹配即拒绝——对齐 gorilla 的
//!    `VerifyServerResponse`（参考 `dialer.DialContext` 内部完成）。
//! 3. 其后是 RFC 6455 帧。参考 `connection.Write` 每次写一个**二进制帧**；
//!    `connection.Read` 逐帧取载荷，某帧读尽后取下一帧（`getReader` 的
//!    `NextReader` 语义）。客户端方向所有帧**必须掩码**（RFC 6455 §5.3），
//!    服务端方向**必须不掩码**——读到掩码帧按协议错误拒绝。
//!
//! 本模块只做客户端；这是本卡“Rust 客户端 → Xray 服务端”方向所需的一侧。
//! 控制帧：`Close` 按参考 `Read` 语义结束读侧（EOF），`Ping` 经内部写侧回
//! `Pong`（gorilla 默认读循环行为），`Pong` 忽略；分片（continuation）帧按 RFC
//! 拼接。掩码载荷逐字节 XOR，与参考一致。
//!
//! 读侧用显式状态机（`ReadState`）驱动 `poll_read`，**不**在连接里做任何
//! `unsafe` 自引用；写侧 `poll_write` 一次发一个二进制帧，帧头与掩码载荷用
//! 一个小 `WriteState` 分步推进，保证 `Pending` 时不丢字节。

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use crate::transport::http;
use crate::transport::sha1::{accept_key, base64_encode};
use crate::transport::{check_deadline, Error};

/// 客户端 `Sec-WebSocket-Key` 的随机数长度（RFC 6455 §4.1：16 字节）。
pub(crate) const KEY_LEN: usize = 16;

/// 帧头位掩码。
pub(crate) const FIN: u8 = 0x80;
pub(crate) const OPCODE_MASK: u8 = 0x0f;
pub(crate) const MASK_BIT: u8 = 0x80;
pub(crate) const LEN_16: u8 = 126;
pub(crate) const LEN_64: u8 = 127;

/// RFC 6455 opcode。
pub(crate) const OP_CONTINUATION: u8 = 0x0;
pub(crate) const OP_TEXT: u8 = 0x1;
pub(crate) const OP_BINARY: u8 = 0x2;
pub(crate) const OP_CLOSE: u8 = 0x8;
pub(crate) const OP_PING: u8 = 0x9;
pub(crate) const OP_PONG: u8 = 0xa;

/// 单帧载荷上限：宽裕上限防无界分配（4 MiB）；trojan 头部与中继分片都远小于此。
pub(crate) const MAX_FRAME_PAYLOAD: usize = 4 * 1024 * 1024;

/// WebSocket 客户端配置。
#[derive(Debug, Clone)]
pub struct Client {
    path: String,
    host: String,
    server_name: String,
}

impl Client {
    /// `path` 允许不带前导 `/`（对齐 `GetNormalizedPath`）；`host` 为空时回退
    /// 到 `server_name`，仍为空则回退到连接目标字面量（握手时传入的 authority）。
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
    /// 在 `stream`（已完成认证 TLS）上完成 WebSocket 升级握手，返回 WS 连接。
    /// `wait` 覆盖整个握手（请求写出 + 响应读取 + Accept 校验）。
    pub async fn upgrade<S>(&self, stream: S, wait: Duration) -> Result<Connection<S>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        check_deadline(wait)?;
        timeout(wait, self.handshake(stream))
            .await
            .map_err(|_| Error::Timeout)?
    }

    async fn handshake<S>(&self, mut stream: S) -> Result<Connection<S>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let key = base64_encode(&random_key());
        let authority = self.host.clone();
        let headers = vec![
            (
                "Host".to_owned(),
                http::host_header(&self.host, &self.server_name, &authority),
            ),
            ("Connection".to_owned(), "Upgrade".to_owned()),
            ("Upgrade".to_owned(), "websocket".to_owned()),
            ("Sec-WebSocket-Version".to_owned(), "13".to_owned()),
            ("Sec-WebSocket-Key".to_owned(), key.clone()),
        ];
        let path = http::normalize_path(&self.path);
        // 外层 `upgrade` 的 timeout 已覆盖整个握手；内层传大值避免双重计时。
        let outer = Duration::from_secs(86_400);
        http::write_request(&mut stream, &path, &headers, outer).await?;
        let response = http::read_response(&mut stream, outer).await?;
        response.is_switching_protocols()?;
        let accept = response.header("sec-websocket-accept").unwrap_or("");
        if accept != accept_key(&key) {
            return Err(Error::UpgradeRejected(
                "Sec-WebSocket-Accept 校验失败".to_owned(),
            ));
        }
        Ok(Connection::new(stream))
    }
}

/// 16 字节随机 key。`std` 无稳定 CSPRNG，`getrandom` 不在本 crate 直接依赖中
/// （新增会改写 Cargo.lock，超出本卡边界）。`RandomState` 由系统熵播种，用于产生
/// “不可被客户端预知”的握手 key 足够（RFC 6455 只要求随机、不可预知）。
pub(crate) fn random_key() -> [u8; KEY_LEN] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut key = [0u8; KEY_LEN];
    let mut filled = 0;
    while filled < key.len() {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u64(filled as u64);
        let word = hasher.finish().to_le_bytes();
        let take = word.len().min(key.len() - filled);
        key[filled..filled + take].copy_from_slice(&word[..take]);
        filled += take;
    }
    key
}

mod frame;

pub use frame::Frames;

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::ReadBuf;

/// 升级后的**客户端** WebSocket 连接：发掩码帧、收不掩码帧。
pub struct Connection<S> {
    frames: Frames<S>,
}

impl<S> Connection<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            frames: Frames::new(inner, true),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Connection<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().frames).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Connection<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().frames).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().frames).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().frames).poll_shutdown(cx)
    }
}

/// 升级后的**服务端** WebSocket 连接：收掩码帧、发不掩码帧（RFC 6455 §5.1）。
pub struct ServerConnection<S> {
    frames: Frames<S>,
}

impl<S> ServerConnection<S> {
    /// 由已完成升级握手、且方向为服务端的底层流构造。
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            frames: Frames::new(inner, false),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ServerConnection<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().frames).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ServerConnection<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().frames).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().frames).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().frames).poll_shutdown(cx)
    }
}
