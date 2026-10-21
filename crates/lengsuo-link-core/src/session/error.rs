//! L2 会话层的错误类型。
//!
//! 设计约束（照抄 `crate::frame::error` 的纪律）：
//! - **不把 `lengsuo_wireguard` 的内部错误枚举透传给上层**：握手层
//!   （`handshake::ResponderError`）与传输层（`transport::Error`）的错误
//!   在这里**逐项映射**成本 crate 自己的变体，语义保持可区分。
//! - **错误文本不含密钥字节、不含明文/密文内容**：只出现长度、计数器、
//!   状态名、角色名这类元数据。
//! - 全部 fail-closed：任何分支都不返回部分明文、不回退到未认证路径。

use lengsuo_wireguard::handshake::ResponderError;
use lengsuo_wireguard::transport::Error as TransportError;

use super::state::{SessionRole, SessionState};

/// 会话层错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    // ---- 状态机 ----
    /// 当前状态不允许该操作（例如未握手就收发）。
    #[error("会话状态 {state} 不允许该操作（角色 {role}）")]
    InvalidState {
        /// 当前状态名。
        state: &'static str,
        /// 当前角色名。
        role: &'static str,
    },

    /// 会话已失效：拒绝继续收发。
    #[error("会话已失效：拒绝继续收发（需要重连）")]
    Invalidated,

    /// 角色不匹配：例如让 responder 去产出 initiation。
    #[error("角色不匹配：当前是 {actual}，该操作要求 {expected}")]
    RoleMismatch {
        /// 当前角色名。
        actual: &'static str,
        /// 该操作要求的角色名。
        expected: &'static str,
    },

    // ---- 密钥材料 ----
    /// 注入的密钥材料非法（长度不对、全零等）。
    #[error("密钥材料非法：{0}")]
    InvalidKeyMaterial(&'static str),

    /// 构造握手上下文失败（对端公钥非法等）。
    #[error("握手上下文构造失败：{0}")]
    HandshakeSetup(&'static str),

    // ---- 握手（由 `ResponderError` 逐项映射） ----
    /// 握手报文长度不符。
    #[error("握手报文长度 {actual} 字节，要求 {expected} 字节")]
    HandshakeLength { actual: usize, expected: usize },

    /// 握手报文类型不符。
    #[error("握手报文类型不符：{0}")]
    HandshakeType(&'static str),

    /// 握手 AEAD 认证失败（静态段/时间戳段剥壳失败）。
    #[error("握手认证失败：未知对端或密文被篡改")]
    HandshakeAuthFailed,

    /// 握手报文 MAC1 校验失败（在剥壳之前就拒绝）。
    #[error("握手 MAC1 校验失败：报文被篡改或来源不明")]
    HandshakeMacFailed,

    /// 握手对端身份不匹配。
    #[error("握手未知对端：静态公钥与配置不符")]
    HandshakeUnknownPeer,

    /// 握手重放（时间戳不晚于已记录值）。
    #[error("握手重放：时间戳不晚于已记录值")]
    HandshakeReplay,

    /// 握手洪水（两次剥壳间隔过短）。
    #[error("握手洪水：两次握手间隔过短")]
    HandshakeFlood,

    /// 握手状态机失步。
    #[error("握手状态失步：{0}")]
    HandshakeState(&'static str),

    /// 发起方消费 response 失败（认证失败 / 长度不符 / 接收者不匹配）。
    #[error("发起方握手失败：{0}")]
    InitiatorFailed(&'static str),

    // ---- 传输层（由 `transport::Error` 逐项映射） ----
    /// 会话密钥长度不对。
    #[error("会话密钥长度 {actual} 字节，要求 {expected} 字节")]
    KeyLength { actual: usize, expected: usize },

    /// 整包长度超过传输层上限。
    #[error("整包长度 {actual} 字节超过上限 {limit} 字节")]
    TooLong { actual: usize, limit: usize },

    /// 发送侧计数器已用尽（不回绕复用）。
    #[error("计数器 {counter} 已用尽：不回绕复用")]
    CounterExhausted { counter: u64 },

    /// 传输上下文已永久 poison。
    #[error("传输上下文已永久 poison：拒绝继续封装或解封")]
    Poisoned,

    /// AEAD 认证解密失败：**不回退明文**，会话转入失效态。
    #[error("AEAD 认证失败：会话已失效，不回退明文")]
    AuthFailed,

    /// AEAD 封装失败（理论不可达）。
    #[error("AEAD 封装失败：会话已失效")]
    SealFailed,

    /// 载荷不是运输报文。
    #[error("载荷不是运输报文：{0}")]
    NotTransport(&'static str),

    /// 接收者标识不匹配。
    #[error("接收者标识不匹配：期望 {expected:#010x}，实际 {actual:#010x}")]
    ReceiverMismatch { expected: u32, actual: u32 },

    /// 重放窗口拒绝（重复/过旧/超上限）：**丢包**，会话仍然有效。
    #[error("重放窗口拒绝：丢包，会话仍有效")]
    ReplayRejected,

    // ---- 帧层 ----
    /// 帧编解码失败（切帧/帧头非法/长度超限等）。
    #[error("帧层错误：{0}")]
    Frame(String),
}

impl SessionError {
    /// 当前状态不允许某操作时的构造助手。
    pub(crate) fn invalid_state(state: SessionState, role: SessionRole) -> Self {
        Self::InvalidState {
            state: state.as_str(),
            role: role.as_str(),
        }
    }

    /// 角色不匹配时的构造助手。
    pub(crate) fn role_mismatch(actual: SessionRole, expected: SessionRole) -> Self {
        Self::RoleMismatch {
            actual: actual.as_str(),
            expected: expected.as_str(),
        }
    }

    /// 本错误是否代表**会话已经失效**（不可继续收发，必须重连）。
    ///
    /// 上层据此决定「丢弃当前会话」还是「只丢这一个包」。
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::Invalidated
                | Self::Poisoned
                | Self::AuthFailed
                | Self::SealFailed
                | Self::CounterExhausted { .. }
        )
    }
}

impl From<TransportError> for SessionError {
    /// 把传输层错误**逐项**映射到本 crate 的变体，保持语义可区分。
    ///
    /// 手写 `From`（而非 `#[from]`）：`#[from]` 每个源类型只能用一次，
    /// 而本 crate 需要把关键变体提升为**一等变体**（否则上层就得认识
    /// wireguard 的错误枚举，等于把内部结构透传给调用方）。
    /// 匹配是穷尽的——传输层新增变体会在编译期暴露。
    fn from(error: TransportError) -> Self {
        match error {
            TransportError::KeyLength { actual, expected } => Self::KeyLength { actual, expected },
            TransportError::TooLong { actual, limit } => Self::TooLong { actual, limit },
            TransportError::CounterExhausted { counter } => Self::CounterExhausted { counter },
            TransportError::Poisoned => Self::Poisoned,
            TransportError::AuthFailed => Self::AuthFailed,
            TransportError::SealFailed => Self::SealFailed,
            TransportError::NotTransport(reason) => Self::NotTransport(reason),
            TransportError::ReceiverMismatch { expected, actual } => {
                Self::ReceiverMismatch { expected, actual }
            }
            // 重放窗口的三种拒绝（重复/过旧/超上限）在会话层语义一致：丢包，
            // 不足以判定密钥失同步 ⇒ 不让会话失效。
            TransportError::Replay(_) => Self::ReplayRejected,
            TransportError::Wire(_) => Self::NotTransport("运输报文头非法"),
        }
    }
}

impl From<ResponderError> for SessionError {
    /// 把握手层错误**逐项**映射到本 crate 的变体。
    fn from(error: ResponderError) -> Self {
        match error {
            ResponderError::Length { actual, expected } => {
                Self::HandshakeLength { actual, expected }
            }
            ResponderError::NotInitiation => Self::HandshakeType("非握手初始化报文"),
            ResponderError::AuthFailed => Self::HandshakeAuthFailed,
            ResponderError::InvalidKey => Self::InvalidKeyMaterial("无效公钥或共享密钥为全零"),
            ResponderError::UnknownPeer => Self::HandshakeUnknownPeer,
            ResponderError::Replay => Self::HandshakeReplay,
            ResponderError::Flood => Self::HandshakeFlood,
            ResponderError::State(reason) => Self::HandshakeState(reason),
            ResponderError::Mac => Self::HandshakeAuthFailed,
        }
    }
}

impl From<crate::frame::FrameError> for SessionError {
    /// 把帧层错误映射到会话层。
    ///
    /// **fatal 的几类逐项提升为一等变体**（认证失败 / poison / 计数器用尽）——
    /// 它们决定「会话是否要作废」，必须让会话层看得见；
    /// 其余（帧头非法、长度不符、魔数不匹配……）只是「这一帧没解出来」，
    /// 压成一条 `Frame` 消息即可，避免上层同时认识两套帧错误枚举。
    fn from(error: crate::frame::FrameError) -> Self {
        use crate::frame::FrameError;
        match error {
            FrameError::AuthFailed => Self::AuthFailed,
            FrameError::Poisoned => Self::Poisoned,
            FrameError::CounterExhausted { counter } => Self::CounterExhausted { counter },
            FrameError::KeyLength { actual, expected } => Self::KeyLength { actual, expected },
            FrameError::TooLong { actual, limit } => Self::TooLong { actual, limit },
            FrameError::NotTransport(reason) => Self::NotTransport(reason),
            FrameError::ReceiverMismatch { expected, actual } => {
                Self::ReceiverMismatch { expected, actual }
            }
            FrameError::ReplayRejected => Self::ReplayRejected,
            other => Self::Frame(other.to_string()),
        }
    }
}
