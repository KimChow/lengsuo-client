//! UDP 传输层的错误类型：**两级**（单包级 / 连接级）明确区分。
//!
//! 任务书要求把两件事分开，本文件就是那个分界：
//!
//! | 级别 | 含义 | 上层动作 |
//! |---|---|---|
//! | **单包级**（`ErrorSeverity::Packet`） | 这**一个**数据报解不开 | **只丢这一包**，链路继续 |
//! | **连接级**（`ErrorSeverity::Connection`） | socket 层出错（对端不可达、socket 坏了） | **上报**并结束收发循环 |
//!
//! 另外还有一级**本地调用级**（`ErrorSeverity::Local`）：调用方用法不对
//! （没设对端、缓冲太小、载荷超上限），与链路健康无关，既不丢包也不结束循环。
//!
//! ⛔ 错误文本**不含载荷字节**：只出现长度、序号、来源地址这类元数据。

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use lengsuo_link_core::frame::FrameError;

/// 错误的严重级别。**机器可判定**（上层可以按它决定「丢包」还是「断链」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSeverity {
    /// **单包级**：只影响这一个数据报。丢掉它，链路继续。
    Packet,
    /// **连接级**：socket 层出错。必须上报，并结束收发循环。
    Connection,
    /// **本地调用级**：调用方用法错误，与链路健康无关。
    Local,
}

/// 可克隆的 socket 错误。
///
/// [`std::io::Error`] **不可克隆**，而本 crate 需要把同一个 socket 错误
/// 同时交给「事件通道」与「循环结果」两处 ⇒ 用 `Arc` 包一层。
#[derive(Debug, Clone)]
pub struct SocketError(Arc<io::Error>);

impl SocketError {
    /// 包一个 IO 错误。
    #[must_use]
    pub fn new(source: io::Error) -> Self {
        Self(Arc::new(source))
    }

    /// 底层 IO 错误的种类（例如 [`io::ErrorKind::ConnectionRefused`]）。
    #[must_use]
    pub fn kind(&self) -> io::ErrorKind {
        self.0.kind()
    }

    /// 底层错误的引用（拿到底层 `io::Error` 的 `&`）。
    #[must_use]
    pub fn inner(&self) -> &io::Error {
        &self.0
    }
}

impl fmt::Display for SocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl std::error::Error for SocketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

impl From<io::Error> for SocketError {
    fn from(source: io::Error) -> Self {
        Self::new(source)
    }
}

impl PartialEq for SocketError {
    /// 同一个 `io::Error` 不可克隆、也不可比较 ⇒ 按「种类 + 文本」比较。
    ///
    /// 这样上层的 `LoopOutcome` / `KeepaliveOutcome` 也能整体比较
    /// （用例里要断言「循环以哪种方式结束」）。
    fn eq(&self, other: &Self) -> bool {
        self.kind() == other.kind() && self.0.to_string() == other.0.to_string()
    }
}

impl Eq for SocketError {}

/// UDP 传输层错误。
///
/// 分层纪律：本 crate **不**把 `lengsuo_wireguard` 的错误透传给上层——
/// 帧层错误以 `lengsuo_link_core` 自己的 [`FrameError`] 形态出现，
/// socket 错误以 [`std::io::Error`] 形态出现，两者都被收敛到本枚举。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UdpError {
    /// 帧编码失败（载荷超上限等）：**不发出**，不截断。
    #[error("帧编码失败（不发出、不截断）：{0}")]
    Encode(#[source] FrameError),

    /// 尚未设置对端地址，无从发送。
    #[error("尚未设置对端地址，无法发送")]
    NoPeer,

    /// **socket 级错误**（连接级）：对端不可达（ICMP 拒绝）、socket 坏了等。
    #[error("socket 错误（连接级）：{source}")]
    Socket {
        /// 底层 IO 错误。
        #[source]
        source: SocketError,
    },

    /// **数据报解码失败**（单包级）：这一包不是合法帧，只丢这一包。
    ///
    /// ⚠️ 字段叫 `origin` 而不是 `source`：后者会被错误框架当成
    /// 「底层错误来源」，而这里它只是**元数据**（数据报从哪儿来）。
    #[error("数据报解码失败（单包级，来源 {origin}）：{reason}")]
    BadDatagram {
        /// 数据报来源地址（元数据，不是错误来源）。
        origin: SocketAddr,
        /// 帧层给出的失败原因。
        reason: FrameError,
    },

    /// 接收缓冲太小：连一帧都装不下。
    #[error("接收缓冲过小：至少需要 {needed} 字节，实际 {available} 字节")]
    BufferTooSmall {
        /// 需要的最小字节数。
        needed: usize,
        /// 调用方给的字节数。
        available: usize,
    },
}

impl UdpError {
    /// 错误的严重级别：上层据此决定「只丢这一包」还是「上报并断链」。
    #[must_use]
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            // 单包级：坏包只丢这一包，收发循环**继续**。
            Self::BadDatagram { .. } => ErrorSeverity::Packet,
            // 连接级：socket 坏了，**上报**并结束收发循环。
            Self::Socket { .. } => ErrorSeverity::Connection,
            // 本地调用级：调用方用法错误，与链路无关。
            Self::Encode(_) | Self::NoPeer | Self::BufferTooSmall { .. } => ErrorSeverity::Local,
        }
    }
}
