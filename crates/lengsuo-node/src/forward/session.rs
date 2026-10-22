//! 面向**真实目标**的出站会话：八个协议的可转发性判定与建会话。
//!
//! 与 `crate::outbound`（dry-run 用的探测会话）的区别：
//!
//! - dry-run 会话用 `probe_target`（缺省 `127.0.0.1:9`）做握手，写入的是探测
//!   载荷，**不能**拿来转发业务。
//! - 本模块的会话以**本次连接的真实目标**建连：trojan 请求头携带真实目标、
//!   shadowsocks 首段明文携带真实目标，其余协议同样以真实目标发起。
//!
//! ## 泛化：读侧 / 写侧从具体类型改为 trait object
//!
//! 旧实现里 [`LiveSession`] 的读侧 / 写侧是**具体类型**（trojan 的
//! `ReadHalf<NodeTlsStream>`、shadowsocks 的 `TcpReader` / `TcpWriter`），
//! 因此只承载 trojan / shadowsocks 两个协议，其余协议只能「只握手不转发」。
//! 本卡把两侧泛化成 `Box<dyn OutboundReader>` / `Box<dyn OutboundWriter>`：
//! 每个协议自己实现「读一段业务载荷 / 写一段业务载荷 / 半关闭写侧」，
//! 协议分帧（vmess 的 chunk、ss2022 的 AEAD chunk、anytls 的帧）全部留在
//! 协议 crate 内，`relay.rs` 的双向转发循环只依赖这两个 trait。
//!
//! ## 逐协议可转发性
//!
//! | 协议 | 转发层判定 | 原因 |
//! |---|---|---|
//! | trojan | Relay | TLS 之上是裸字节流 |
//! | shadowsocks | Relay | AEAD chunk 解/加密后是裸字节流 |
//! | vless | Relay | 请求头 / 响应头之后是裸字节流（TLS / REALITY / Vision 三种承载） |
//! | vmess | Relay | 数据段是 AEAD chunk，解/加密后是裸字节流 |
//! | ss2022 | Relay | 数据段是 AEAD chunk，解/加密后是裸字节流 |
//! | anytls | Relay | 流内是帧（SYN / PUSH / FIN），解帧后是裸字节流 |
//! | hysteria | Relay | QUIC 双向流的两半可独立读写（详见 `session/hysteria.rs`） |
//! | wireguard | 不可转发 | L3 隧道（收发 IP 包），转发层没有字节流 |
//!
//! wireguard **显式报错**（[`SessionError::Unsupported`]），调用方据此
//! fail-closed 断开，**绝不**回落到直连。

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::config::{Endpoint, NodeConfig, Protocol};
use crate::outbound::DialError;

mod anytls;
mod hysteria;
mod shadowsocks;
mod ss2022;
mod trojan;
mod vless;
mod vmess;

/// 中继缓冲大小。对齐参考 `common/buf/buffer.go` 的 `Size = 8192`
/// （参考按 8 KiB MultiBuffer 拷贝）；本端每方向一个固定缓冲，无缓冲池。
pub const COPY_BUF: usize = 8192;

/// 会话错误。Display 不含口令、密钥或明文载荷。
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("出站 I/O 失败：{0}")]
    Io(#[from] std::io::Error),
    #[error("trojan 协议错误：{0}")]
    Trojan(#[from] lengsuo_trojan::stream::Error),
    #[error("shadowsocks 协议错误：{0}")]
    Shadowsocks(#[from] lengsuo_shadowsocks::TcpError),
    #[error("vmess 协议错误：{0}")]
    Vmess(#[from] lengsuo_vmess::Error),
    #[error("ss2022 协议错误：{0}")]
    Ss2022(#[from] lengsuo_ss2022::Error),
    #[error("anytls 协议错误：{0}")]
    AnyTls(#[from] lengsuo_anytls::Error),
    /// anytls 客户端状态机拒绝（远端帧违反协议）。文案来自状态机，不含密钥。
    #[error("anytls 客户端状态机拒绝：{0}")]
    AnyTlsState(String),
    #[error("hysteria 协议错误：{0}")]
    Hysteria(#[from] lengsuo_hysteria::Error),
    #[error("出站建连失败：{0}")]
    Dial(#[from] DialError),
    #[error("空闲超时")]
    Idle,
    #[error("该协议在转发层不可转发：{0}")]
    Unsupported(&'static str),
}

/// 出站建连的结果。
///
/// `Relay` 的载荷用 `Box` 间接一层：会话结构体较大（内含读侧与写侧），
/// 不装箱会让整个枚举按最大变体对齐，白白占栈。
pub enum Opened {
    /// 可转发的会话。
    Relay(Box<LiveSession>),
}

/// 出站读侧（回程方向：出站 → 本地）。
///
/// 每个协议自己实现「读一段业务载荷」：裸字节流协议直接读，vmess / ss2022 /
/// anytls 则先做协议分帧（chunk 解密 / 解帧）再交出明文。
pub trait OutboundReader: Send {
    /// 读一段业务载荷。`Ok(0)` = 对端正常 EOF（**不是**失败）。
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<usize, SessionError>> + Send + 'a>>;
}

/// 出站写侧（请求方向：本地 → 出站）。
pub trait OutboundWriter: Send {
    /// 写一段业务载荷。
    fn send<'a>(
        &'a mut self,
        payload: &'a [u8],
        wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + Send + 'a>>;

    /// 半关闭写侧（发 FIN）。读侧仍可继续收数据。
    fn half_close<'a>(
        &'a mut self,
        wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + Send + 'a>>;
}

/// 一条可转发的出站会话（读侧 + 写侧）。
pub struct LiveSession {
    /// 回程方向（出站 → 本地）。
    pub reader: Box<dyn OutboundReader>,
    /// 请求方向（本地 → 出站）。
    pub writer: Box<dyn OutboundWriter>,
}

/// 打开一条出站会话。
///
/// - trojan / shadowsocks / vless / vmess / ss2022 / anytls / hysteria
///   ⇒ [`Opened::Relay`]。
/// - wireguard ⇒ [`SessionError::Unsupported`]（L3 隧道，转发层没有字节流；
///   原因见 `docs/node-forward-relay.md` 的偏离清单）。
///
/// 失败一律返回 `Err`（fail-closed）：调用方**不得**回落到直连。
pub async fn open(
    node: &NodeConfig,
    target: &TargetAddr,
    wait: Duration,
    observe: Duration,
) -> Result<Opened, SessionError> {
    // `observe` 是旧实现给 trojan 负向排除观察窗留的位置；本卡各协议的握手
    // 判据都在协议 crate 内自洽（正向证据），不再需要观察窗。
    let _ = observe;
    let session = match node.protocol {
        Protocol::Trojan => trojan::open(node, target, wait).await?,
        Protocol::Shadowsocks => shadowsocks::open(node, target, wait).await?,
        Protocol::Vless => vless::open(node, target, wait).await?,
        Protocol::Vmess => vmess::open(node, target, wait).await?,
        Protocol::Ss2022 => ss2022::open(node, target, wait).await?,
        Protocol::AnyTls => anytls::open(node, target, wait).await?,
        Protocol::Hysteria => hysteria::open(node, target, wait).await?,
        Protocol::Wireguard => {
            return Err(SessionError::Unsupported(
                "wireguard 是 L3 隧道（收发 IP 包），转发层没有可转发的字节流；\
                 等价能力在 lengsuo-tun 的用户态 TCP 栈",
            ))
        }
    };
    Ok(Opened::Relay(Box::new(session)))
}

/// 探测配置：把 `probe_target` 覆盖成真实目标。
///
/// 六个可转发协议的拨号实现都以 `probe_target` 作为「本次连接的目标」
/// （trojan 请求头、shadowsocks 首段明文、vless 请求头、vmess 请求头、
/// ss2022 变长头、hysteria TCPRequest），因此覆盖该字段即等价于「按真实
/// 目标建连」。
pub(crate) fn probe_config(node: &NodeConfig, target: &TargetAddr) -> NodeConfig {
    let mut probe = node.clone();
    probe.probe_target = Some(endpoint_of(target));
    probe
}

/// 目标地址 ⇒ 端点（供 `probe_target` 覆盖）。
pub(crate) fn endpoint_of(target: &TargetAddr) -> Endpoint {
    match target {
        TargetAddr::V4(ip, port) => Endpoint {
            host: std::net::Ipv4Addr::from(*ip).to_string(),
            port: *port,
        },
        TargetAddr::V6(ip, port) => Endpoint {
            host: std::net::Ipv6Addr::from(*ip).to_string(),
            port: *port,
        },
        TargetAddr::Domain(host, port) => Endpoint {
            host: host.clone(),
            port: *port,
        },
    }
}

/// 带截止时间的读。超时 ⇒ [`SessionError::Idle`]（等价参考的
/// `CancelAfterInactivity`：静默超过上限即断连）。
pub(crate) async fn read_within<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    wait: Duration,
) -> Result<usize, SessionError> {
    match timeout(wait, reader.read(buf)).await {
        Ok(Ok(read)) => Ok(read),
        Ok(Err(err)) => Err(SessionError::Io(err)),
        Err(_) => Err(SessionError::Idle),
    }
}

/// 带截止时间的写（`write_all` + `flush`）。超时 ⇒ [`SessionError::Idle`]。
pub(crate) async fn write_within<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
    wait: Duration,
) -> Result<(), SessionError> {
    match timeout(wait, async {
        writer.write_all(payload).await?;
        writer.flush().await
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(SessionError::Io(err)),
        Err(_) => Err(SessionError::Idle),
    }
}

/// 带截止时间的写半关闭（`flush` + `shutdown`，TCP 上是 `SHUT_WR`）。
///
/// 读侧仍可继续收对端数据——这是 `join!` 语义的核心：一侧 EOF 只半关闭
/// 另一侧写侧，**不等于**立刻断连。
pub(crate) async fn shutdown_within<W: AsyncWrite + Unpin>(
    writer: &mut W,
    wait: Duration,
) -> Result<(), SessionError> {
    match timeout(wait, async {
        writer.flush().await?;
        writer.shutdown().await
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(SessionError::Io(err)),
        Err(_) => Err(SessionError::Idle),
    }
}

/// 裸字节流读侧：请求头 / 响应头之后（或 chunk 解密之后）的字节即目标数据。
pub(crate) struct ByteReader<R> {
    inner: R,
}

impl<R> ByteReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R: AsyncRead + Unpin + Send> OutboundReader for ByteReader<R> {
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
        wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<usize, SessionError>> + Send + 'a>> {
        let inner = &mut self.inner;
        Box::pin(async move { read_within(inner, buf, wait).await })
    }
}

/// 裸字节流写侧。
pub(crate) struct ByteWriter<W> {
    inner: W,
}

impl<W> ByteWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<W: AsyncWrite + Unpin + Send> OutboundWriter for ByteWriter<W> {
    fn send<'a>(
        &'a mut self,
        payload: &'a [u8],
        wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + Send + 'a>> {
        let inner = &mut self.inner;
        Box::pin(async move { write_within(inner, payload, wait).await })
    }

    fn half_close<'a>(
        &'a mut self,
        wait: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<(), SessionError>> + Send + 'a>> {
        let inner = &mut self.inner;
        Box::pin(async move { shutdown_within(inner, wait).await })
    }
}
