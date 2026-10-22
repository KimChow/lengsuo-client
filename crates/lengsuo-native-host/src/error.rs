//! 类型化错误。
//!
//! 纪律（照本仓既有风格）：
//! - 变体之间**语义可区分**，不合并成笼统的 `Invalid(String)`。
//! - 每个变体都带**足够的定位信息**（声明长度 / 实际长度 / 越界字符），
//!   便于排查跨端字节不一致。
//! - 错误文本**不含载荷字节**（载荷是 JSON 业务消息，可能承载凭据数据）。
//! - ⛔ 不用字符串匹配做控制流：调用方一律 `match` 具名变体。

/// 管道帧编解码失败。
///
/// 全部 fail-closed：任何分支都不返回部分数据、不猜测长度、
/// 不把截断内容当完整帧交付、不按实际长度「凑」出一帧。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// 缓冲不足**一整帧**：等更多数据，**不返回部分数据**。
    ///
    /// `needed` 说明缺的是什么：
    /// - `needed == 4`（[`FRAME_HEADER_LEN`](crate::frame::FRAME_HEADER_LEN)）
    ///   ⇒ 帧头本身没收全；
    /// - `needed > 4` ⇒ 帧头收全了，但载荷还没收够 `needed - 4` 字节。
    #[error("帧不完整：需要 {needed} 字节，实际 {available} 字节")]
    Incomplete {
        /// 凑齐这一帧还需要的总字节数（帧头 + 载荷）。
        needed: usize,
        /// 当前缓冲里已有的字节数。
        available: usize,
    },

    /// 帧头声明的载荷长度超过上限：**不截断、不巨量分配**。
    ///
    /// 解码侧自设的上限（见 [`MAX_FRAME_PAYLOAD_LEN`](crate::frame::MAX_FRAME_PAYLOAD_LEN)）：
    /// 一个坏的长度头不该让宿主进程申请巨量内存。
    #[error("帧头声明长度 {declared} 字节超过上限 {limit} 字节：拒绝，不截断")]
    FrameTooLong {
        /// 帧头声明的载荷字节数。
        declared: u64,
        /// 允许的上限。
        limit: usize,
    },

    /// 载荷超过上限（编码侧）：**不截断、不分帧**。
    #[error("载荷长度 {declared} 字节超过上限 {limit} 字节：拒绝，不截断")]
    PayloadTooLong {
        /// 待编码的载荷字节数。
        declared: usize,
        /// 允许的上限。
        limit: usize,
    },
}

/// 来源解析失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OriginError {
    /// origin 不是 `chrome-extension://<扩展ID>` 形状。
    ///
    /// Chromium 自己传的 origin **永远是**这个形状；出现别的形状说明
    /// 宿主进程不是被 Chromium 正常拉起来的 ⇒ **显式失败，不放行**。
    #[error("origin 形状不对：{0:?}（期望 chrome-extension://<扩展ID>）")]
    NotExtensionOrigin(String),

    /// 扩展 ID 不符合 Chromium 的 ID 格式。
    #[error("扩展 ID 格式不对：{id:?}：{reason}")]
    InvalidExtensionId {
        /// 出问题的扩展 ID 原文。
        id: String,
        /// 具体哪里不对。
        reason: IdFormatError,
    },
}

/// 扩展 ID 格式不合法的具体原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdFormatError {
    /// 长度不是 32 字节。
    #[error("长度应为 32，实际 {actual}")]
    Length {
        /// 实际长度（字节）。
        actual: usize,
    },

    /// 含有字母表 `a`–`p` 之外的字符。
    #[error("含有字母表 a-p 之外的字符 {char:?}")]
    Char {
        /// 第一个越界字符。
        char: char,
    },
}
