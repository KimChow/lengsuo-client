//! Trojan 服务端运行时：TLS 接入 → 请求头认证 → CONNECT 双向中继。
//!
//! 服务端语义基线：Xray v26.3.27，完整 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，`proxy/trojan/server.go`、
//! `protocol.go`、`validator.go`。
//!
//! `Server::accept_loop` 是产品入口（TLS + trojan）；`Server::process` 只认
//! trojan 协议、transport 无关（参考的 `Process` 同样拿到的是已建好的流）。
//! 失败一律 fail-closed：认证/解析失败直接结束连接，不写任何应答字节——参考里
//! 没有成功响应首字节可写，拒绝的唯一表达就是关闭连接。
//!
//! 已实现：请求头多用户常量时间校验、CONNECT 目标解析与拨号、双向中继（半关闭
//! 传递）。未实现：UDP ASSOCIATE 转发——参考 `server.go` 的 `handleUDPPayload`
//! 依赖 `transport/internet/udp` 的会话化/cone 调度器，超出本卡四个 trojan 参考
//! 路径；本仓只保留命令识别与帧格式（见 `crate::stream`，已与 Xray 双向互通），
//! 收到 UDP 请求按 trojan 静默收尾（见 `Error::UdpUnsupported`）。

mod header;
mod relay;
mod tls;
mod validator;

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::codec::Command;
use crate::server::header::PrefixedReader;

pub use tls::Inbound;
pub use validator::{User, Validator};

/// 参考 `common/buf/buffer.go` 的 `Size = 8192`，服务端首读缓冲上限。
/// `Process` 用它决定一次 `read` 能拿到多少首块字节，随后交给 `PrefixedReader`
/// 回放；大于首块的载荷不会被吞，而是随中继继续转发。
pub const INITIAL_READ_SIZE: usize = 8192;

/// 服务端运行时错误。认证失败、协议错误、拨号/中继/IO 失败与超时分区上报；
/// Display/Debug 不含密码或哈希，凭据仍受隐私策略约束。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("截止时间必须大于零")]
    InvalidDeadline,
    #[error("协议操作超时")]
    Timeout,
    #[error("不是 trojan 协议（首块不足 58 字节或第 57 字节不是 CR）")]
    NotTrojanProtocol,
    #[error("密码哈希校验失败")]
    Authentication,
    #[error("非法命令字节：{0:#04x}")]
    InvalidCommand(u8),
    #[error("目标地址非法：{0}")]
    Address(#[from] ss_core::Error),
    #[error("请求头超过上限")]
    HeaderTooLarge,
    #[error("目标拨号失败：{0}")]
    Dial(#[source] std::io::Error),
    #[error("UDP ASSOCIATE 转发未实现，按 trojan 静默收尾")]
    UdpUnsupported,
    #[error("中继失败：{0}")]
    Relay(#[source] std::io::Error),
    #[error("连接 I/O 失败：{0}")]
    Io(#[from] std::io::Error),
    #[error("TLS 接入失败：{0}")]
    Tls(#[from] lengsuo_tls::Error),
    #[error("邮箱不能为空")]
    EmailRequired,
    #[error("邮箱已存在：{0}")]
    DuplicateEmail(String),
    #[error("用户不存在：{0}")]
    UserNotFound(String),
}

/// 对齐参考 `policy.Session.Timeouts` 的两个字段：握手截止与连接空闲截止。
/// 参考的 `UplinkOnly`/`DownlinkOnly` 是这两者的细化，运行时不单独建模（见文档）。
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    handshake: Duration,
    connection_idle: Duration,
}

impl Timeouts {
    pub fn new(handshake: Duration, connection_idle: Duration) -> Result<Self, Error> {
        if handshake.is_zero() || connection_idle.is_zero() {
            return Err(Error::InvalidDeadline);
        }
        Ok(Self {
            handshake,
            connection_idle,
        })
    }

    #[must_use]
    pub fn handshake(&self) -> Duration {
        self.handshake
    }

    #[must_use]
    pub fn connection_idle(&self) -> Duration {
        self.connection_idle
    }
}

/// Trojan 服务端。克隆成本低（内部是 `Arc` 与可复制的 acceptor），供每个连接复用。
#[derive(Clone)]
pub struct Server {
    validator: Validator,
    tls: Option<tls::Inbound>,
    timeouts: Timeouts,
}

impl Server {
    /// 纯 trojan 服务端（transport 由调用方负责；产品路径用 `with_tls`）。
    #[must_use]
    pub fn new(validator: Validator, timeouts: Timeouts) -> Self {
        Self {
            validator,
            tls: None,
            timeouts,
        }
    }

    /// TLS + trojan：先完成认证 TLS，再进入 trojan 握手。
    #[must_use]
    pub fn with_tls(validator: Validator, timeouts: Timeouts, tls: tls::Inbound) -> Self {
        Self {
            validator,
            tls: Some(tls),
            timeouts,
        }
    }

    #[must_use]
    pub fn validator(&self) -> &Validator {
        &self.validator
    }

    #[must_use]
    pub fn timeouts(&self) -> Timeouts {
        self.timeouts
    }

    /// 产品入口：不断 accept，每条连接并发处理。单连接的失败只结束该连接。
    pub async fn accept_loop(&self, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (socket, _) = listener.accept().await?;
            let server = self.clone();
            tokio::spawn(async move {
                let _ = server.handle_tcp(socket).await;
            });
        }
    }

    /// 处理一条 TCP 连接：有 TLS 先握手，再进入 trojan 处理。
    pub async fn handle_tcp(&self, socket: TcpStream) -> Result<(), Error> {
        match &self.tls {
            Some(tls) => {
                let stream = tls.accept(socket).await?;
                self.process(stream).await
            }
            None => self.process(socket).await,
        }
    }

    /// 在已建好的流上处理一条 trojan 连接（对齐 `proxy/trojan/server.go` 的
    /// `Process`，transport 无关）。
    pub(crate) async fn process<C>(&self, conn: C) -> Result<(), Error>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut reader, writer) = tokio::io::split(conn);

        let initial = read_initial(&mut reader, self.timeouts.handshake).await?;
        // 参考 `server.go` 的协议判定线：首块不足 58 字节或第 57 字节不是 CR。
        if initial.len() < 58 || initial[56] != b'\r' {
            return Err(Error::NotTrojanProtocol);
        }

        let mut prefixed = PrefixedReader::new(initial, reader);
        let (request, user) =
            header::accept(&mut prefixed, &self.validator, self.timeouts.handshake).await?;
        // 参考仅把 user.Email 用于 access 日志；本仓库无日志层，靠 Drop 语义不落凭据。
        let _ = user;

        match request.command {
            Command::Udp => Err(Error::UdpUnsupported),
            Command::Tcp => {
                let upstream =
                    relay::connect_target(&request.target, self.timeouts.handshake).await?;
                let (upstream_reader, upstream_writer) = upstream.into_split();
                relay::relay(
                    prefixed,
                    writer,
                    upstream_reader,
                    upstream_writer,
                    self.timeouts.connection_idle,
                )
                .await
            }
        }
    }
}

/// 参考 `first.ReadFrom(conn)`：单次读取，最多 `INITIAL_READ_SIZE` 字节，握手截止包住。
async fn read_initial<R: AsyncRead + Unpin>(
    reader: &mut R,
    wait: Duration,
) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; INITIAL_READ_SIZE];
    let read = timeout(wait, reader.read(&mut buf))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::Io)?;
    // 参考：0 字节即 EOF，报“failed to read first request”；这里归类为 IO 失败。
    if read == 0 {
        return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
    }
    buf.truncate(read);
    Ok(buf)
}
