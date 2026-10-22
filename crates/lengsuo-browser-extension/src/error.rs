//! 协议层的类型化错误。
//!
//! 纪律（照本仓既有风格）：
//! - 变体之间**语义可区分**，不合并成一个笼统的 `Invalid(String)`。
//! - 每个变体都带**足够的定位信息**（实际值 / 声明长度 / 实际长度），
//!   便于排查跨仓字节不一致。
//! - 错误文本**不含载荷字节**（载荷可能承载凭据数据）。
//!
//! 五类解码失败对应契约 §5.2 的约束表，另加两条本 crate 补齐的：
//! 载荷被截断（声明长度大于实际字节数）与 `decode_exact` 的多余字节。

/// 消息帧编解码失败。
///
/// 全部 fail-closed：任何分支都不返回部分数据、不猜测长度、
/// 不把截断内容当完整帧交付、不按实际长度「凑」出一帧。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// `len` 超过上限：**立刻失败**（不等数据、不截断）。
    #[error("载荷长度 {declared} 字节超过上限 {limit} 字节：拒绝，不截断")]
    PayloadTooLong {
        /// 帧头声明的载荷长度。
        declared: u64,
        /// 允许的上限。
        limit: usize,
    },

    /// `reserved` 三个字节不全为 0。
    #[error("保留位非零：{got:?}")]
    ReservedNotZero {
        /// 三个保留字节的实际值（顺序即线上顺序）。
        got: [u8; 3],
    },

    /// 消息类型不在已知集合内：**绝不当已知类型解析**。
    #[error("未知消息类型 {got}：拒绝解析")]
    UnknownMessageType {
        /// 帧头里的类型字节。
        got: u8,
    },

    /// 帧头被截断（缓冲不足一个完整帧头）。
    #[error("帧头不足 {needed} 字节：实际 {available} 字节")]
    TruncatedHeader {
        /// 一个完整帧头需要的字节数。
        needed: usize,
        /// 实际给出的字节数。
        available: usize,
    },

    /// 载荷比帧头声明的长度短：**不截断、不按实际长度凑**。
    #[error("载荷被截断：声明 {declared} 字节，实际 {available} 字节")]
    TruncatedPayload {
        /// 帧头声明的载荷长度。
        declared: usize,
        /// 实际可用的载荷字节数。
        available: usize,
    },

    /// 缓冲里有多余字节（`decode_exact` 要求恰好一帧）。
    #[error("缓冲长度不符：期望 {expected} 字节，实际 {actual} 字节")]
    TrailingBytes {
        /// 期望的整帧长度。
        expected: usize,
        /// 实际给出的缓冲长度。
        actual: usize,
    },
}
