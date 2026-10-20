//! 面向**真实目标**的出站会话：trojan / shadowsocks 可转发，其余协议只到握手。
//!
//! 与 `crate::outbound`（dry-run 用的探测会话）的区别：
//!
//! - dry-run 会话用 `probe_target`（缺省 `127.0.0.1:9`）做握手，写入的是探测
//!   载荷，**不能**拿来转发业务。
//! - 本模块的会话以**本次连接的真实目标**建连：trojan 请求头携带真实目标、
//!   shadowsocks 首段明文携带真实目标。
//!
//! 协议语义**全部复用**本仓协议 crate，本模块只做「按目标建会话」：
//! - trojan：TLS（`outbound::connect_tls`）+ `lengsuo_trojan::stream::send_request`
//!   写请求头（凭据哈希与头部编码都在 trojan crate 内）；载荷转发用同一 crate 的
//!   `forward_payload` / `receive_payload`，半关闭用 `shutdown_write`。
//! - shadowsocks：TCP + `lengsuo_shadowsocks::{TcpWriter, TcpReader}`（AEAD 派生、
//!   chunk 帧、salt 全部在该 crate 内）；首段明文是 `TargetAddr::encode_checked`。
//! - 其余六协议（anytls / vless / vmess / ss2022 / hysteria / wireguard）：复用
//!   `outbound::dial` 的现成握手路径（把 `probe_target` 换成真实目标，使 vless
//!   这类「目标建立成功才回执」的协议能真正握手成功），握手成功后**不转发**
//!   （`Opened::HandshakeOnly`）——本卡未实现它们的转发，调用方据此
//!   fail-closed 断开。

use std::time::Duration;

use lengsuo_shadowsocks::{TcpReader, TcpWriter};
use lengsuo_trojan::stream::{forward_payload, receive_payload, send_request, shutdown_write};
use lengsuo_trojan::{
    Command as TrojanCommand, Credential as TrojanCredential, Request as TrojanRequest,
};
use ss_core::target::TargetAddr;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use crate::config::{Endpoint, NodeConfig, Protocol};
use crate::outbound::{connect_tcp, connect_tls, DialError, NodeTlsStream};

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
    #[error("出站建连失败：{0}")]
    Dial(#[from] DialError),
    #[error("空闲超时")]
    Idle,
    #[error("该协议的会话类型不可跨线程共享（hysteria 的 QUIC 客户端含非 Sync 状态）")]
    NotCrossThread,
}

/// 出站建连的结果。
///
/// `Relay` 的载荷用 `Box` 间接一层：会话结构体较大（内含读侧与写侧），
/// 不装箱会让整个枚举按最大变体对齐，白白占栈。
pub enum Opened {
    /// 可转发的会话（trojan / shadowsocks）。
    Relay(Box<LiveSession>),
    /// 只完成握手，**未实现**转发（调用方必须 fail-closed 断开）。
    HandshakeOnly(&'static str),
}

/// 出站读侧：trojan 用裸读半；shadowsocks 用 chunk 解密读端（可能多出余量）。
///
/// shadowsocks 的解密读端内含 chunk 缓冲，体积远大于 trojan 读半 ⇒ 用 `Box`
/// 间接一层，避免枚举按最大变体对齐。
pub enum OutboundReader {
    /// trojan 读半（请求头之后的字节即目标数据）。
    Trojan(ReadHalf<NodeTlsStream>),
    /// shadowsocks 读端（AEAD chunk 解密）。
    Shadowsocks {
        /// 解密读端。
        reader: Box<TcpReader<ReadHalf<TcpStream>>>,
        /// 上一次解出的 chunk 里没被本次读走的余量。
        pending: Vec<u8>,
    },
}

/// 出站写侧。
pub enum OutboundWriter {
    /// trojan 写半。
    Trojan(WriteHalf<NodeTlsStream>),
    /// shadowsocks 写端（AEAD chunk 加密）。
    Shadowsocks(TcpWriter<WriteHalf<TcpStream>>),
}

impl OutboundReader {
    /// 读一段业务载荷。`Ok(0)` = 对端正常 EOF。
    pub async fn recv(&mut self, buf: &mut [u8], wait: Duration) -> Result<usize, SessionError> {
        match self {
            Self::Trojan(read) => Ok(receive_payload(read, buf, wait).await?),
            Self::Shadowsocks { reader, pending } => {
                if !pending.is_empty() {
                    let take = pending.len().min(buf.len());
                    buf[..take].copy_from_slice(&pending[..take]);
                    pending.drain(..take);
                    return Ok(take);
                }
                match reader.recv().await? {
                    Some(chunk) => {
                        let take = chunk.len().min(buf.len());
                        buf[..take].copy_from_slice(&chunk[..take]);
                        if take < chunk.len() {
                            pending.extend_from_slice(&chunk[take..]);
                        }
                        Ok(take)
                    }
                    None => Ok(0),
                }
            }
        }
    }
}

impl OutboundWriter {
    /// 写一段业务载荷。
    pub async fn send(&mut self, payload: &[u8], wait: Duration) -> Result<(), SessionError> {
        match self {
            Self::Trojan(write) => Ok(forward_payload(write, payload, wait).await?),
            Self::Shadowsocks(writer) => Ok(writer.send(payload).await?),
        }
    }

    /// 半关闭写侧（发 FIN）。读侧仍可继续收数据。
    pub async fn half_close(&mut self, wait: Duration) -> Result<(), SessionError> {
        match self {
            Self::Trojan(write) => Ok(shutdown_write(write, wait).await?),
            Self::Shadowsocks(writer) => Ok(writer.shutdown().await?),
        }
    }
}

/// 一条可转发的出站会话（读侧 + 写侧）。
pub struct LiveSession {
    /// 回程方向（出站 → 本地）。
    pub reader: OutboundReader,
    /// 请求方向（本地 → 出站）。
    pub writer: OutboundWriter,
}

/// 打开一条出站会话。
///
/// - trojan / shadowsocks ⇒ [`Opened::Relay`]（可转发）。
/// - anytls / vless / vmess / ss2022 / wireguard ⇒ 握手成功后
///   [`Opened::HandshakeOnly`]（**不转发**；本卡未实现它们的转发）。
/// - hysteria ⇒ [`SessionError::NotCrossThread`]（见该变体注释）。
///
/// 失败一律返回 `Err`（fail-closed）：调用方**不得**回落到直连。
pub async fn open(
    node: &NodeConfig,
    target: &TargetAddr,
    wait: Duration,
    observe: Duration,
) -> Result<Opened, SessionError> {
    match node.protocol {
        Protocol::Trojan => {
            let (reader, writer) = open_trojan(node, target, wait).await?;
            Ok(Opened::Relay(Box::new(LiveSession { reader, writer })))
        }
        Protocol::Shadowsocks => {
            let (reader, writer) = open_shadowsocks(node, target, wait).await?;
            Ok(Opened::Relay(Box::new(LiveSession { reader, writer })))
        }
        Protocol::Hysteria => Err(SessionError::NotCrossThread),
        other => {
            // 握手路径复用 `outbound` 各协议的拨号实现；把探测目标换成真实目标，
            // 使「目标建立成功才回执」的协议（vless）能真正握手成功。
            let probe = probe_config(node, target);
            handshake_only(other, &probe, wait, observe).await?;
            Ok(Opened::HandshakeOnly(protocol_name(other)))
        }
    }
}

/// 探测配置：把 `probe_target` 覆盖成真实目标。
fn probe_config(node: &NodeConfig, target: &TargetAddr) -> NodeConfig {
    let mut probe = node.clone();
    probe.probe_target = Some(endpoint_of(target));
    probe
}

/// 逐协议握手（**不含** hysteria：它的 QUIC 客户端类型不可跨线程，见
/// [`SessionError::NotCrossThread`]）。
///
/// 这里刻意**不用** `outbound::dial`：那个分发函数包含 hysteria 分支，其 future
/// 不是 `Send`，会把整个转发器的连接任务拖成非 `Send`。
async fn handshake_only(
    protocol: Protocol,
    probe: &NodeConfig,
    wait: Duration,
    observe: Duration,
) -> Result<(), SessionError> {
    match protocol {
        Protocol::AnyTls => {
            crate::outbound::dial_anytls(probe, wait).await?;
        }
        Protocol::Vless => {
            crate::outbound_vless::dial_vless(probe, wait).await?;
        }
        Protocol::Vmess => {
            crate::outbound_vmess::dial_vmess(probe, wait).await?;
        }
        Protocol::Ss2022 => {
            crate::outbound_ss2022::dial_ss2022(probe, wait).await?;
        }
        Protocol::Wireguard => {
            crate::outbound_wireguard::dial_wireguard(probe, wait).await?;
        }
        Protocol::Trojan | Protocol::Shadowsocks | Protocol::Hysteria => {
            return Err(SessionError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "该协议不进入握手专用路径",
            )));
        }
    }
    let _ = observe;
    Ok(())
}

/// 协议名（用于报告，不含凭据）。
#[must_use]
pub fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Trojan => "trojan",
        Protocol::AnyTls => "anytls",
        Protocol::Vless => "vless",
        Protocol::Vmess => "vmess",
        Protocol::Shadowsocks => "shadowsocks",
        Protocol::Ss2022 => "ss2022",
        Protocol::Hysteria => "hysteria",
        Protocol::Wireguard => "wireguard",
    }
}

/// 目标地址 ⇒ 探测端点（供 `probe_target` 覆盖）。
fn endpoint_of(target: &TargetAddr) -> Endpoint {
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

/// trojan 出站会话：TLS → 写请求头（携带真实目标）。
///
/// **不复用** `outbound::dial` 的 trojan 分支：它用 `probe_target` 且在观察窗里
/// **读掉 1 字节**（负向排除的代价），实时转发会吞掉回程首字节；且
/// `TrojanSession` 把读写两半私有封死，无法在请求方向 EOF 时只半关闭写侧而
/// 保留回程。这里用同一 crate 的 `stream` 原语（协议编码与凭据派生仍全部复用），
/// 与仓内 trojan 服务端中继（`lengsuo_trojan::server::relay`）的裸两半写法一致。
async fn open_trojan(
    node: &NodeConfig,
    target: &TargetAddr,
    wait: Duration,
) -> Result<(OutboundReader, OutboundWriter), DialError> {
    let stream = connect_tls(node, wait).await?;
    let (read, mut write) = tokio::io::split(stream);
    let credential = TrojanCredential::new(&node.auth.password);
    let request = TrojanRequest {
        command: TrojanCommand::Tcp,
        target: target.clone(),
    };
    // 请求头完整写出并 flush 之后才算会话建立（对齐 trojan 客户端的顺序约束）。
    send_request(&mut write, &request, &credential, wait).await?;
    Ok((OutboundReader::Trojan(read), OutboundWriter::Trojan(write)))
}

/// shadowsocks 出站会话：TCP → 写首段明文（真实目标地址）。
///
/// 首段明文**只含地址**：SS 线格式要求地址在前、载荷随后，地址与首批载荷
/// 同批到达时服务端会把余量当载荷——这里首批载荷为空，避免多写一次。
async fn open_shadowsocks(
    node: &NodeConfig,
    target: &TargetAddr,
    wait: Duration,
) -> Result<(OutboundReader, OutboundWriter), DialError> {
    let suite = crate::outbound_ss::suite_from_method(node.method.as_deref())?;
    let password = node
        .auth
        .secret_key
        .as_deref()
        .ok_or_else(|| DialError::Rejected("shadowsocks 缺少 auth.secret_key".to_owned()))?;
    let stream = connect_tcp(node, wait).await?;
    let (read, write) = tokio::io::split(stream);
    let mut writer = TcpWriter::new(write, suite, password.as_bytes(), wait)?;
    let reader = TcpReader::new(read, suite, password.as_bytes(), wait)?;
    let mut head = Vec::new();
    target
        .encode_checked(&mut head)
        .map_err(|err| DialError::Resolve(format!("目标地址编码失败：{err}")))?;
    writer.send(&head).await?;
    Ok((
        OutboundReader::Shadowsocks {
            reader: Box::new(reader),
            pending: Vec::new(),
        },
        OutboundWriter::Shadowsocks(writer),
    ))
}
