//! 装配层错误：**fail-closed**，且沿用 L1 的两级语义。
//!
//! # 分层纪律
//!
//! 本层**不吞错**、**不改写成功**：
//! - 握手失败（MAC 不符 / 长度非法 / 类型不符 / 认证失败）⇒
//!   [`AssemblyError::HandshakeRejected`]，⛔ **不回退明文**、⛔ **不静默重试到底**；
//! - socket 层失败 ⇒ [`AssemblyError::Wire`] 原样包着 [`UdpError`]，
//!   其 [`UdpError::severity`] 仍然可判「单包级 / 连接级」；
//! - peer 配置/查询失败 ⇒ [`AssemblyError::Peer`] 原样包着 [`PeerError`]。
//!
//! ⛔ 错误文本**不含密钥、不含载荷字节**：只出现角色名、状态名与固定短语。
//!
//! # 为什么手写 `Display`
//!
//! 上游的 [`PeerError`] **不**实现 `Display`/`Error`（`lengsuo-wireguard`
//! 的既有事实），所以本枚举**不能**用 `thiserror` 的 `#[error("{0}")]`
//! 展开它 ⇒ 改为手写 `Display`（并保留 `PeerError` 载荷本体，
//! 供上层按变体做程序化判定）。

use crate::udp::UdpError;
use lengsuo_wireguard::peers::PeerError;

/// 装配层错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssemblyError {
    /// 本端角色与操作不匹配（发起方不能收 initiation，反之亦然）。
    WrongRole {
        /// 该操作要求角色。
        expected: &'static str,
        /// 本端实际角色。
        actual: &'static str,
    },

    /// 握手被拒绝（**fail-closed**：不回退明文、不静默重试）。
    ///
    /// 触发：MAC1 不符、报文长度非法、类型不符、响应认证失败、未知对端、
    /// 重放或洪水。
    HandshakeRejected {
        /// 固定短语原因（不含任何报文内容）。
        reason: &'static str,
    },

    /// 握手状态机失步：在错误的时机调用（例如没有在途 initiation 就收 response）。
    HandshakeState(&'static str),

    /// 收到的报文**类型不对**（例如把数据帧当握手报文解）。
    UnexpectedMessage(&'static str),

    /// 会话尚未建立，拒绝收发数据 / 启动 keepalive。
    SessionNotEstablished,

    /// 没有可用于发送的 keypair：未安装、已过期、计数器用尽或封装失败。
    ///
    /// ⛔ 绝不回落到旧 keypair（对照 `keypair::KeypairSet::for_send` 的 fail-closed）。
    NoSendKeypair,

    /// 收到的数据报不是合法的 L3 帧（**单包级**：只丢这一包）。
    BadDatagram(&'static str),

    /// peer 配置或查询失败（`PeerError` 原样透出）。
    Peer(PeerError),

    /// 传输层错误（`UdpError` 原样透出，仍可判单包级 / 连接级）。
    Wire(UdpError),

    /// keepalive 无法启动（未配置间隔，或间隔为零 = busy loop）。
    KeepaliveDisabled(&'static str),

    /// keepalive 任务已在运行（重复启动）。
    KeepaliveAlreadyRunning,
}

impl core::fmt::Display for AssemblyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongRole { expected, actual } => {
                write!(formatter, "角色不符：本端是 {actual}，该操作要求 {expected}")
            }
            Self::HandshakeRejected { reason } => {
                write!(formatter, "握手被拒绝（fail-closed，不回退明文）：{reason}")
            }
            Self::HandshakeState(reason) => write!(formatter, "握手状态失步：{reason}"),
            Self::UnexpectedMessage(reason) => write!(formatter, "报文类型不符：{reason}"),
            Self::SessionNotEstablished => {
                formatter.write_str("会话尚未建立：拒绝该操作（先完成握手）")
            }
            Self::NoSendKeypair => formatter.write_str(
                "没有可用于发送的 keypair（未安装 / 已过期 / 计数器用尽 / 封装失败）",
            ),
            Self::BadDatagram(reason) => {
                write!(formatter, "数据报不是合法的帧（单包级）：{reason}")
            }
            Self::Peer(error) => write!(formatter, "peer 错误：{}", peer_reason(*error)),
            Self::Wire(error) => write!(formatter, "传输层错误：{error}"),
            Self::KeepaliveDisabled(reason) => write!(formatter, "keepalive 不可启动：{reason}"),
            Self::KeepaliveAlreadyRunning => {
                formatter.write_str("keepalive 任务已在运行：拒绝重复启动")
            }
        }
    }
}

impl std::error::Error for AssemblyError {}

impl From<PeerError> for AssemblyError {
    fn from(error: PeerError) -> Self {
        Self::Peer(error)
    }
}

impl From<UdpError> for AssemblyError {
    fn from(error: UdpError) -> Self {
        Self::Wire(error)
    }
}

/// `PeerError` 的**固定短语**（上游该类型没有 `Display`）。
fn peer_reason(error: PeerError) -> &'static str {
    match error {
        PeerError::DuplicatePublicKey => "对端公钥重复",
        PeerError::TooManyPeers => "peer 数量超过上限",
        PeerError::NotFound => "找不到该 peer",
    }
}
