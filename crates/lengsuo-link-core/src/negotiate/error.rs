//! L4 通道协商的错误类型与**稳定错误码目录**。
//!
//! 设计约束（照抄 `crate::frame::error` / `crate::session::error` 的纪律）：
//! - **错误码是数字 + 稳定字符串标签**，⛔ **不用 Rust `Debug` 文本当码**：
//!   移动端（Swift / Kotlin）要按**同样的码**显示与处理，`Debug` 文本随时可能变。
//! - **错误文本不含载荷内容、不含明文**：只出现长度、世代号、模式名这类元数据。
//! - 全部 **fail-closed**：任何失败分支都不返回「协商结果」、
//!   **绝不**回退到「默认 p2p」。
//!
//! # 码的稳定性承诺
//!
//! [`ErrorCode`] 的**数字码与标签一旦发布就不再改动**（只增不改）；
//! 新增失败场景**只能追加新码**，不得复用旧码表达新语义。
//! 这样移动端可以按码做分支，而不必解析本 crate 的错误文本。

use crate::session::SessionError;

/// L4 协商的**稳定错误码**。
///
/// 数字码与字符串标签都是**对外契约**（见 `docs/link-negotiate-spec.md` §6）。
/// `#[non_exhaustive]`：未来追加新码时，老的移动端代码仍能编译（匹配时需留兜底分支）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// 内部状态不一致（理论不可达）。出现即视为实现缺陷。
    Internal,
    /// 协商消息格式非法（长度不足、魔数不符、字段越界……）。
    MalformedMessage,
    /// 协商消息的协议版本不受支持（当前只接受版本 1）。
    UnsupportedVersion,
    /// 协商载荷超过密文通道的明文上限（**不截断**）。
    PayloadTooLarge,
    /// 世代号不匹配：对端带着**另一代**的连接来协商。
    GenerationMismatch,
    /// 通道模式无交集：双方没有**任何**共同可用的通道模式。
    NoCommonChannelMode,
    /// 对端选定的通道模式**本端不支持**（本端拒绝该结果）。
    ChannelModeNotAccepted,
    /// 请求的通道模式**本端自己就不支持**（调用方错误）。
    ChannelModeNotSupported,
    /// 协商状态机不允许该操作（重复发起、乱序应答……）。
    InvalidState,
    /// 角色不匹配：让响应方去发起、让发起方去应答。
    RoleMismatch,
    /// 载荷不是走控制帧来的（协商**只允许**走 `FrameType::Control`）。
    WrongFrameType,
    /// 密文通道失败（AEAD 认证失败 / 会话失效 / 帧层错误……）。
    TransportError,
}

impl ErrorCode {
    /// 稳定数字码（**跨端对齐用，永不复用**）。
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Internal => 0x0001,
            Self::MalformedMessage => 0x0002,
            Self::UnsupportedVersion => 0x0003,
            Self::PayloadTooLarge => 0x0004,
            Self::GenerationMismatch => 0x0005,
            Self::NoCommonChannelMode => 0x0006,
            Self::ChannelModeNotAccepted => 0x0007,
            Self::ChannelModeNotSupported => 0x000C,
            Self::InvalidState => 0x0008,
            Self::RoleMismatch => 0x0009,
            Self::WrongFrameType => 0x000A,
            Self::TransportError => 0x000B,
        }
    }

    /// 稳定字符串标签（与数字码一一对应，便于日志与跨端对齐）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "INTERNAL",
            Self::MalformedMessage => "MALFORMED_MESSAGE",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::GenerationMismatch => "GENERATION_MISMATCH",
            Self::NoCommonChannelMode => "NO_COMMON_CHANNEL_MODE",
            Self::ChannelModeNotAccepted => "CHANNEL_MODE_NOT_ACCEPTED",
            Self::ChannelModeNotSupported => "CHANNEL_MODE_NOT_SUPPORTED",
            Self::InvalidState => "INVALID_STATE",
            Self::RoleMismatch => "ROLE_MISMATCH",
            Self::WrongFrameType => "WRONG_FRAME_TYPE",
            Self::TransportError => "TRANSPORT_ERROR",
        }
    }
}

/// L4 协商错误。
///
/// 全部 fail-closed：**任何**变体都意味着「协商没成」，
/// 调用方**不得**据此回退到某个默认通道模式。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NegotiateError {
    /// 内部状态不一致（理论不可达）。
    #[error("协商内部状态不一致：{0}")]
    Internal(&'static str),

    /// 协商消息格式非法。
    #[error("协商消息格式非法：{reason}")]
    MalformedMessage {
        /// 失败原因（稳定的小写短语，不含载荷内容）。
        reason: &'static str,
    },

    /// 协商消息版本不受支持。
    #[error("协商消息版本不受支持：期望 {expected}，实际 {got}")]
    UnsupportedVersion {
        /// 本实现支持的版本。
        expected: u8,
        /// 收到的版本。
        got: u8,
    },

    /// 协商载荷超过明文上限（**不截断**）。
    #[error("协商载荷 {declared} 字节超过上限 {limit} 字节：拒绝，不截断")]
    PayloadTooLarge {
        /// 实际长度。
        declared: usize,
        /// 允许的上限。
        limit: usize,
    },

    /// 世代号不匹配：对端带着另一代连接来协商。
    #[error("世代号不匹配：期望 {local}，实际 {remote}：拒绝继续用旧连接")]
    GenerationMismatch {
        /// 本端世代号。
        local: u64,
        /// 对端声称的世代号。
        remote: u64,
    },

    /// 通道模式无交集。
    #[error("通道模式无交集：请求 {requested}，但双方没有共同可用的模式")]
    NoCommonChannelMode {
        /// 被请求的模式名。
        requested: &'static str,
    },

    /// 对端选定的模式本端不支持。
    #[error("对端选定的通道模式本端不支持：{mode}")]
    ChannelModeNotAccepted {
        /// 模式名。
        mode: &'static str,
    },

    /// 请求的模式本端自己就不支持（调用方错误）。
    #[error("本端不支持请求的通道模式：{mode}")]
    ChannelModeNotSupported {
        /// 模式名。
        mode: &'static str,
    },

    /// 协商状态机不允许该操作。
    #[error("协商状态 {state} 不允许该操作（角色 {role}）")]
    InvalidState {
        /// 当前状态名。
        state: &'static str,
        /// 当前角色名。
        role: &'static str,
    },

    /// 角色不匹配。
    #[error("角色不匹配：当前是 {actual}，该操作要求 {expected}")]
    RoleMismatch {
        /// 当前角色名。
        actual: &'static str,
        /// 该操作要求的角色名。
        expected: &'static str,
    },

    /// 载荷不是走控制帧来的。
    #[error("协商载荷必须走控制帧：实际帧类型 {got}")]
    WrongFrameType {
        /// 实际帧类型名。
        got: &'static str,
    },

    /// 密文通道失败。
    #[error("密文通道失败：{reason}")]
    Transport {
        /// 下层错误文本（不含密钥字节与载荷内容）。
        reason: String,
    },
}

impl NegotiateError {
    /// 本错误的**稳定错误码**。
    #[must_use]
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::Internal(_) => ErrorCode::Internal,
            Self::MalformedMessage { .. } => ErrorCode::MalformedMessage,
            Self::UnsupportedVersion { .. } => ErrorCode::UnsupportedVersion,
            Self::PayloadTooLarge { .. } => ErrorCode::PayloadTooLarge,
            Self::GenerationMismatch { .. } => ErrorCode::GenerationMismatch,
            Self::NoCommonChannelMode { .. } => ErrorCode::NoCommonChannelMode,
            Self::ChannelModeNotAccepted { .. } => ErrorCode::ChannelModeNotAccepted,
            Self::ChannelModeNotSupported { .. } => ErrorCode::ChannelModeNotSupported,
            Self::InvalidState { .. } => ErrorCode::InvalidState,
            Self::RoleMismatch { .. } => ErrorCode::RoleMismatch,
            Self::WrongFrameType { .. } => ErrorCode::WrongFrameType,
            Self::Transport { .. } => ErrorCode::TransportError,
        }
    }

    /// 本错误的**稳定数字码**（跨端对齐用）。
    #[must_use]
    pub const fn code(&self) -> u16 {
        self.error_code().code()
    }

    /// 载荷超限时的构造助手。
    pub(crate) fn payload_too_large(declared: usize, limit: usize) -> Self {
        Self::PayloadTooLarge { declared, limit }
    }

    /// 消息格式非法时的构造助手。
    pub(crate) fn malformed(reason: &'static str) -> Self {
        Self::MalformedMessage { reason }
    }
}

impl From<SessionError> for NegotiateError {
    /// 把会话层错误**逐项**映射到协商层的稳定错误码。
    ///
    /// 协商层**不向移动端透传** `SessionError` 的枚举形状：跨端只看
    /// [`ErrorCode`] 的数字码。下层文本保留在 `Transport` 变体里（供日志定位），
    /// 它只含长度、计数器、状态名这类元数据，**不含密钥字节与明文**。
    fn from(error: SessionError) -> Self {
        Self::Transport {
            reason: error.to_string(),
        }
    }
}
