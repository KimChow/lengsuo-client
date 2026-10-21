//! 帧层的错误类型。
//!
//! 设计约束（任务书三·5）：
//! - **不把 `lengsuo_wireguard::transport::Error` 透传给上层**——那会让调用方
//!   （含移动端 FFI 侧）依赖 wireguard 内部结构。本文件把传输层错误**逐项映射**
//!   到本 crate 自己的变体上，`KeyLength` / `TooLong` / `Poisoned` / `AuthFailed`
//!   等语义**保持可区分**，绝不合并成一个 `Crypto`。
//! - **错误文本不含密钥字节，也不含载荷/明文**（照抄 `TransportKey` 的纪律）。
//!   错误里只出现长度、计数器、类型值这类元数据。

use lengsuo_wireguard::transport::Error as TransportError;

/// 帧层错误。全部 fail-closed：任何分支都不会返回部分数据、不猜测长度、
/// 不会把截断内容当完整帧交付、不会回退到明文。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    // ---- 帧头解析（本 crate 自己的边界检查） ----
    /// 输入不足以切出一个完整帧头（或完整帧）：**不返回部分数据**。
    #[error("帧缓冲不足：需要 {needed} 字节，实际 {available} 字节")]
    Incomplete { needed: usize, available: usize },

    /// 帧头魔数不匹配：不是本协议的帧。
    #[error("帧头魔数不匹配：期望 {expected:#06x}，实际 {got:#06x}")]
    BadMagic { expected: u16, got: u16 },

    /// 协议版本不受支持：不做「按老版本尽力解析」。
    #[error("协议版本不受支持：期望 {expected}，实际 {got}")]
    UnsupportedVersion { expected: u8, got: u8 },

    /// 未知帧类型：**绝不当数据帧解析**。
    #[error("未知帧类型 {got:#04x}：拒绝解析，不按数据帧处理")]
    UnknownFrameType { got: u8 },

    /// 保留标志位非零：当前版本未定义的位必须为 0。
    #[error("保留标志位非零：{got:#06x}")]
    ReservedFlags { got: u16 },

    /// 帧头声明的载荷长度超过上限：**不截断后当完整帧交付**。
    #[error("载荷长度 {declared} 字节超过上限 {limit} 字节：拒绝，不截断")]
    PayloadTooLong { declared: usize, limit: usize },

    /// 帧头校验和不符：帧头被损坏（改位、截断拼接错位）。
    #[error("帧头校验和不符：期望 {expected:#010x}，实际 {got:#010x}")]
    HeaderCrcMismatch { expected: u32, got: u32 },

    /// 实际缓冲长度与帧头声明的帧长不一致：**不按实际长度猜**。
    #[error("帧长不符：声明 {declared} 字节，实际 {actual} 字节")]
    LengthMismatch { declared: usize, actual: usize },

    /// 帧边界错位：切完一帧后剩余字节不是下一个帧的魔数。
    #[error("帧边界错位：偏移 {offset} 处不是帧头魔数")]
    Desync { offset: usize },

    // ---- 传输层错误（由 `lengsuo-wireguard` 的语义逐项映射而来） ----
    /// 会话密钥长度不对。
    #[error("会话密钥长度 {actual} 字节，要求 {expected} 字节")]
    KeyLength { actual: usize, expected: usize },

    /// 整包长度超过传输层上限。
    #[error("整包长度 {actual} 字节超过上限 {limit} 字节")]
    TooLong { actual: usize, limit: usize },

    /// 发送侧计数器已用尽。
    #[error("计数器 {counter} 已用尽：不回绕复用")]
    CounterExhausted { counter: u64 },

    /// 传输上下文已因认证/封装失败永久 poison。
    #[error("传输上下文已永久 poison：拒绝继续封装或解封")]
    Poisoned,

    /// AEAD 认证解密失败：**不回退明文**，且传输上下文已永久 poison。
    #[error("AEAD 认证失败：永久 poison，不回退明文")]
    AuthFailed,

    /// AEAD 封装失败（理论不可达）。
    #[error("AEAD 封装失败：永久 poison")]
    SealFailed,

    /// 载荷不是传输层运输报文（类型字段不是 4）。
    #[error("载荷不是运输报文：{0}")]
    NotTransport(&'static str),

    /// 接收者标识不匹配。
    #[error("接收者标识不匹配：期望 {expected:#010x}，实际 {actual:#010x}")]
    ReceiverMismatch { expected: u32, actual: u32 },

    /// 重放窗口拒绝（重复、过旧、超出注入上限）：丢包，不改变窗口状态。
    #[error("重放窗口拒绝：丢包")]
    ReplayRejected,
}

impl From<TransportError> for FrameError {
    /// 把传输层错误**逐项**映射到本 crate 的变体，保持语义可区分。
    ///
    /// 这里手写 `From` 而不是用 `#[from]` 属性：`#[from]` 每个源类型只能用一次，
    /// 而本 crate 需要把 `KeyLength` / `TooLong` / `Poisoned` / `AuthFailed`
    /// 各自提升为**一等变体**（否则上层就得认识 wireguard 的错误枚举，
    /// 等于把内部结构透传给调用方）。匹配是穷尽的——传输层新增变体会在
    /// 编译期暴露，不会被静默吞掉。
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
            // 重放窗口的三种拒绝（重复/过旧/超上限）在帧层语义一致：丢包。
            // 刻意不把底层重放错误类型透传给上层。
            TransportError::Replay(_) => Self::ReplayRejected,
            // 头部结构检查失败：载荷不是合法的运输报文。
            TransportError::Wire(_) => Self::NotTransport("运输报文头非法"),
        }
    }
}
