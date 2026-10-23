//! 本地入站：SOCKS5（**仅回环**）。
//!
//! 本模块只做**协议面**：完成 SOCKS5 握手并解析出目标地址，把已握手的
//! 客户端连接交给上层拼接数据面。**不在此处拨号**（拨号见 [`crate::outbound`]）。
//!
//! 实现范围是 RFC 1928 的 CONNECT 子集 + RFC 1929 用户名/口令子协商：
//! - greeting：方法协商（VER/NMETHODS/METHODS）
//! - auth：用户名/口令子协商
//! - request：CONNECT 请求与应答
//!
//! UDP ASSOCIATE / BIND 一律回 `05 07` 后断开，绝不静默接受。
//! ⛔ 仅允许绑定回环地址：非回环绑定必须 fail-closed 拒绝。

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

use ss_core::target::TargetAddr;

/// 整体握手时限。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const SOCKS_VERSION: u8 = 0x05;
const AUTH_VERSION: u8 = 0x01;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// 一次读入的上限；多读到的字节会留在 [`Buffered`] 中，最终成为 `residual`。
const READ_CHUNK: usize = 4096;

/// 用户名/口令（RFC 1929）。
#[derive(Clone)]
pub struct Auth {
    pub username: String,
    pub password: String,
}

/// 监听配置。
pub struct Socks5Config {
    pub bind: SocketAddr,
    pub auth: Option<Auth>,
}

/// 握手完成后的客户端连接。
pub struct Accepted {
    /// 客户端请求的目标地址。
    pub target: TargetAddr,
    /// 已握手的客户端连接。
    pub client: TcpStream,
    /// 握手期间已读入、属于后续载荷的字节；上层必须先写进隧道。
    pub residual: Vec<u8>,
}

/// 入站协议错误。
#[derive(Debug, thiserror::Error)]
pub enum InboundError {
    #[error("bind address must be loopback")]
    NotLoopback,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(&'static str),

    #[error("unsupported SOCKS5 command {0:#04x}")]
    UnsupportedCommand(u8),

    #[error("unsupported SOCKS5 address type {0:#04x}")]
    UnsupportedAddressType(u8),

    #[error("authentication failed")]
    AuthFailed,

    #[error("SOCKS5 handshake timed out")]
    HandshakeTimeout,
}

impl InboundError {
    /// 建议回给客户端的 REP 码；`None` 表示不应再回任何字节（或已经回过）。
    #[must_use]
    pub fn reply_code(&self) -> Option<u8> {
        match self {
            Self::Protocol(_) | Self::Io(_) => Some(0x01),
            Self::UnsupportedCommand(_) => Some(0x07),
            Self::UnsupportedAddressType(_) => Some(0x08),
            Self::NotLoopback | Self::AuthFailed | Self::HandshakeTimeout => None,
        }
    }
}

/// SOCKS5 监听器（只允许回环）。
pub struct Socks5Listener {
    listener: TcpListener,
    auth: Option<Auth>,
}

impl Socks5Listener {
    /// 绑定并监听；非回环地址直接拒绝，不做地址替换。
    pub async fn bind(config: Socks5Config) -> Result<Self, InboundError> {
        if !config.bind.ip().is_loopback() {
            return Err(InboundError::NotLoopback);
        }
        let listener = TcpListener::bind(config.bind).await?;
        Ok(Self {
            listener,
            auth: config.auth,
        })
    }

    /// 实际监听地址（`bind` 传 0 端口时用于取回分配到的端口）。
    pub fn local_addr(&self) -> Result<SocketAddr, InboundError> {
        Ok(self.listener.local_addr()?)
    }

    /// 接受一个连接并完成握手；整体限时 [`HANDSHAKE_TIMEOUT`]。
    pub async fn accept(&self) -> Result<Accepted, InboundError> {
        let (stream, _peer) = self.listener.accept().await?;
        match timeout(HANDSHAKE_TIMEOUT, handshake(stream, self.auth.as_ref())).await {
            Ok(result) => result,
            Err(_elapsed) => Err(InboundError::HandshakeTimeout),
        }
    }
}

/// 带缓冲的连接读取器：允许一次读入多于当前阶段所需的字节，
/// 供最后一个阶段检查是否有人提前发送了载荷。
struct Buffered {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Buffered {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buf: Vec::new(),
        }
    }

    /// 保证 `buf` 至少有 `n` 字节；EOF 视为握手失败。
    async fn fill(&mut self, n: usize) -> Result<(), InboundError> {
        let mut tmp = [0u8; READ_CHUNK];
        while self.buf.len() < n {
            let got = self.stream.read(&mut tmp).await?;
            if got == 0 {
                return Err(InboundError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed during SOCKS5 handshake",
                )));
            }
            self.buf.extend_from_slice(&tmp[..got]);
        }
        Ok(())
    }

    /// 取走头部 `n` 字节（调用前须先 `fill(n)`）。
    fn take(&mut self, n: usize) -> Vec<u8> {
        self.buf.drain(..n).collect()
    }
}

async fn send_reply(stream: &mut TcpStream, code: u8) -> Result<(), InboundError> {
    stream
        .write_all(&[SOCKS_VERSION, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn handshake(stream: TcpStream, auth: Option<&Auth>) -> Result<Accepted, InboundError> {
    let mut conn = Buffered::new(stream);

    // greeting: VER | NMETHODS | METHODS
    conn.fill(2).await?;
    let head = conn.take(2);
    if head[0] != SOCKS_VERSION {
        // 不是 SOCKS5，按约定不回任何字节。
        return Err(InboundError::Protocol("bad greeting version"));
    }
    let nmethods = head[1] as usize;
    if nmethods == 0 {
        conn.stream
            .write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
            .await?;
        return Err(InboundError::Protocol("zero methods offered"));
    }

    conn.fill(nmethods).await?;
    let methods = conn.take(nmethods);
    let required = if auth.is_some() {
        METHOD_USERPASS
    } else {
        METHOD_NO_AUTH
    };
    if !methods.contains(&required) {
        conn.stream
            .write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
            .await?;
        return Err(InboundError::Protocol("no acceptable auth method"));
    }
    conn.stream.write_all(&[SOCKS_VERSION, required]).await?;

    if let Some(auth) = auth {
        authenticate(&mut conn, auth).await?;
    }

    // request: VER | RSV | CMD | ATYP | ADDR | PORT
    conn.fill(4).await?;
    let req = conn.take(4);
    let (ver, rsv, cmd, atyp) = (req[0], req[1], req[2], req[3]);
    if ver != SOCKS_VERSION || rsv != 0 {
        send_reply(&mut conn.stream, 0x01).await?;
        return Err(InboundError::Protocol("malformed request header"));
    }
    if cmd != CMD_CONNECT {
        send_reply(&mut conn.stream, 0x07).await?;
        return Err(InboundError::UnsupportedCommand(cmd));
    }

    let target = match atyp {
        ATYP_IPV4 => {
            conn.fill(4 + 2).await?;
            let b = conn.take(4 + 2);
            let ip = [b[0], b[1], b[2], b[3]];
            let port = u16::from_be_bytes([b[4], b[5]]);
            TargetAddr::V4(ip, port)
        }
        ATYP_DOMAIN => {
            conn.fill(1).await?;
            let len = conn.take(1)[0] as usize;
            if len == 0 {
                send_reply(&mut conn.stream, 0x01).await?;
                return Err(InboundError::Protocol("zero-length domain"));
            }
            conn.fill(len + 2).await?;
            let b = conn.take(len + 2);
            let host = match std::str::from_utf8(&b[..len]) {
                Ok(host) => host.to_string(),
                Err(_) => {
                    send_reply(&mut conn.stream, 0x01).await?;
                    return Err(InboundError::Protocol("domain is not valid UTF-8"));
                }
            };
            let port = u16::from_be_bytes([b[len], b[len + 1]]);
            TargetAddr::Domain(host, port)
        }
        ATYP_IPV6 => {
            conn.fill(16 + 2).await?;
            let b = conn.take(16 + 2);
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&b[..16]);
            let port = u16::from_be_bytes([b[16], b[17]]);
            TargetAddr::V6(ip, port)
        }
        other => {
            send_reply(&mut conn.stream, 0x08).await?;
            return Err(InboundError::UnsupportedAddressType(other));
        }
    };

    // BND.ADDR/BND.PORT 用 0.0.0.0:0 表示「绑定位由上层决定」。
    send_reply(&mut conn.stream, 0x00).await?;

    let Buffered { stream, buf } = conn;
    Ok(Accepted {
        target,
        client: stream,
        residual: buf,
    })
}

async fn authenticate(conn: &mut Buffered, auth: &Auth) -> Result<(), InboundError> {
    // VER | ULEN | UNAME | PLEN | PASSWD
    conn.fill(2).await?;
    let head = conn.take(2);
    if head[0] != AUTH_VERSION {
        conn.stream.write_all(&[AUTH_VERSION, 0x01]).await?;
        return Err(InboundError::Protocol("bad auth version"));
    }
    let ulen = head[1] as usize;
    if ulen == 0 {
        conn.stream.write_all(&[AUTH_VERSION, 0x01]).await?;
        return Err(InboundError::Protocol("zero-length username"));
    }

    conn.fill(ulen + 1).await?;
    let body = conn.take(ulen + 1);
    let username = &body[..ulen];
    let plen = body[ulen] as usize;
    if plen == 0 {
        conn.stream.write_all(&[AUTH_VERSION, 0x01]).await?;
        return Err(InboundError::Protocol("zero-length password"));
    }

    conn.fill(plen).await?;
    let password = conn.take(plen);

    // 两段都比较完再做判断（`&` 不短路）。
    let ok = ct_eq(username, auth.username.as_bytes()) & ct_eq(&password, auth.password.as_bytes());
    if ok {
        conn.stream.write_all(&[AUTH_VERSION, 0x00]).await?;
        Ok(())
    } else {
        conn.stream.write_all(&[AUTH_VERSION, 0x01]).await?;
        Err(InboundError::AuthFailed)
    }
}

/// 常量时间比较：长度差异也计入结果，内容逐字节 xor 累加，不提前返回。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = usize::from(a.len() != b.len());
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(x ^ y);
    }
    diff == 0
}
