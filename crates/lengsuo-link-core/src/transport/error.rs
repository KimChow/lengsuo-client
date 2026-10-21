//! L1 传输层的错误类型与**稳定错误码目录**。
//!
//! 设计约束（照抄 `crate::frame::error` / `crate::session::error` /
//! `crate::negotiate::error` 的纪律）：
//! - **错误码是数字 + 稳定字符串标签**，⛔ **不用 Rust `Debug` 文本当码**：
//!   移动端（Swift / Kotlin）要按**同样的码**显示与处理，`Debug` 文本随时可能变。
//! - **错误文本不含明文、不含密文内容**：只出现长度、上限、状态名这类元数据。
//! - 全部 **fail-closed**：任何分支都不返回部分明文、不回退到未认证路径。
//!
//! # 码的稳定性承诺
//!
//! [`ErrorCode`] 的**数字码与标签一旦发布就不再改动**（只增不改）；
//! 新增失败场景**只能追加新码**，不得复用旧码表达新语义。
//!
//! # 会话层错误**原样透出**
//!
//! 接线层（[`crate::transport::Link`）拿到的会话层错误**完整保留**
//! [`SessionError`]（见 [`TransportError::Session`] 与
//! [`TransportError::session_error`]）：⛔ 不改写、不压缩成字符串、
//! ⛔ 不吞掉当成功。错误码只是**粗分类**（给跨端分支用），
//! 精确语义仍以 [`SessionError`] 变体为准。

use crate::session::SessionError;

/// L1 传输层的**稳定错误码**。
///
/// 数字码与字符串标签都是**对外契约**（见 `docs/link-transport-spec.md`）。
/// 编号段 `0x0100`–`0x01FF` 专属于 L1 传输层，与 L4 协商层的 `0x0001`–`0x0FFF`
/// 段不重叠。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// 内部状态不一致（理论不可达）。出现即视为实现缺陷。
    Internal,
    /// 底层 IO 失败（发送/接收 syscall 报错）。
    Io,
    /// 暂时没有数据：调用方**稍后重试**即可（⛔ 不是错误，更不是失败）。
    WouldBlock,
    /// 链路已关闭：对端消失 / 端点不可达 / 显式关闭。
    Closed,
    /// 字节数超过单帧上限（**不截断**）。
    TooLong,
    /// 会话状态不允许该操作（例如未握手就收发）。
    SessionInvalidState,
    /// 会话已失效：拒绝继续收发。
    SessionInvalidated,
    /// AEAD 认证失败：**不回退明文**，会话转入失效态。
    SessionAuthFailed,
    /// 重放窗口拒绝：丢包，会话**仍有效**。
    SessionReplayRejected,
    /// 其它会话层 / 帧层失败（帧格式非法、长度不符、计数器用尽……）。
    SessionFrameError,
}

impl ErrorCode {
    /// 稳定数字码（**跨端对齐用，永不复用**）。
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Internal => 0x0101,
            Self::Io => 0x0102,
            Self::WouldBlock => 0x0103,
            Self::Closed => 0x0104,
            Self::TooLong => 0x0105,
            Self::SessionInvalidState => 0x0106,
            Self::SessionInvalidated => 0x0107,
            Self::SessionAuthFailed => 0x0108,
            Self::SessionReplayRejected => 0x0109,
            Self::SessionFrameError => 0x010A,
        }
    }

    /// 稳定字符串标签（与数字码一一对应，便于日志与跨端对齐）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "INTERNAL",
            Self::Io => "IO_ERROR",
            Self::WouldBlock => "WOULD_BLOCK",
            Self::Closed => "CLOSED",
            Self::TooLong => "TOO_LONG",
            Self::SessionInvalidState => "SESSION_INVALID_STATE",
            Self::SessionInvalidated => "SESSION_INVALIDATED",
            Self::SessionAuthFailed => "SESSION_AUTH_FAILED",
            Self::SessionReplayRejected => "SESSION_REPLAY_REJECTED",
            Self::SessionFrameError => "SESSION_FRAME_ERROR",
        }
    }
}

/// L1 传输层错误。
///
/// 全部 fail-closed：**任何**变体都意味着「这一帧没送出去 / 没解出来」，
/// 调用方**不得**据此回退到明文路径。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// 内部状态不一致（理论不可达）。出现即视为实现缺陷。
    #[error("传输层内部状态不一致：{0}")]
    Internal(&'static str),

    /// 底层 IO 失败（可重试）。
    #[error("传输层 IO 失败：{reason}")]
    Io {
        /// 失败原因（稳定短语，不含载荷内容）。
        reason: &'static str,
    },

    /// 暂时没有数据：调用方**稍后重试**。
    ///
    /// ⛔ 这**不是**失败：会话仍然有效，调用方应当退避后重试。
    #[error("传输层暂时无数据：稍后重试")]
    WouldBlock,

    /// 链路已关闭（对端消失 / 端点不可达 / 显式关闭）。
    #[error("传输层已关闭：{reason}")]
    Closed {
        /// 关闭原因（稳定短语，不含载荷内容）。
        reason: &'static str,
    },

    /// 字节数超过单帧上限（**不截断**、**不当合法帧往下传**）。
    #[error("字节长度 {actual} 超过上限 {limit}：拒绝，不截断")]
    TooLong {
        /// 实际长度。
        actual: usize,
        /// 允许的上限。
        limit: usize,
    },

    /// 会话层错误（**原样透出**：完整的 [`SessionError`] 就在里面）。
    #[error("会话层错误：{0}")]
    Session(#[from] SessionError),
}

impl TransportError {
    /// 本错误的**稳定错误码**。
    #[must_use]
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::Internal(_) => ErrorCode::Internal,
            Self::Io { .. } => ErrorCode::Io,
            Self::WouldBlock => ErrorCode::WouldBlock,
            Self::Closed { .. } => ErrorCode::Closed,
            Self::TooLong { .. } => ErrorCode::TooLong,
            Self::Session(error) => session_error_code(error),
        }
    }

    /// 本错误的**稳定数字码**（跨端对齐用）。
    #[must_use]
    pub const fn code(&self) -> u16 {
        self.error_code().code()
    }

    /// 本错误里的会话层错误（**原样透出**的那一个）。
    ///
    /// 调用方需要精确语义（重放 vs 认证失败 vs 状态不允许）时用它，
    /// 而不是去解析错误文本。
    #[must_use]
    pub const fn session_error(&self) -> Option<&SessionError> {
        match self {
            Self::Session(error) => Some(error),
            _ => None,
        }
    }
}

/// 会话层错误 → L1 稳定错误码的**粗分类**。
///
/// ⚠️ 这是**粗分类**：精确语义以 [`SessionError`] 变体为准
/// （`TransportError::session_error()` 给出原样的那个值）。
/// 分类只回答跨端最关心的三件事：会话还能不能用 / 是不是认证失败 / 是不是丢包。
const fn session_error_code(error: &SessionError) -> ErrorCode {
    match error {
        SessionError::InvalidState { .. } => ErrorCode::SessionInvalidState,
        SessionError::Invalidated => ErrorCode::SessionInvalidated,
        SessionError::AuthFailed => ErrorCode::SessionAuthFailed,
        SessionError::ReplayRejected => ErrorCode::SessionReplayRejected,
        _ => ErrorCode::SessionFrameError,
    }
}
