//! 装配层事件：处理一个入站报文后的**可判定结果**。
//!
//! 这不是错误：它把「这包是什么、对端有没有换地址、协商走到哪一步」讲清楚，
//! 让上层不必去匹配错误变体。

use lengsuo_link_core::frame::FrameType;

use crate::negotiate::NegotiationStep;

/// 装配层处理一个入站报文后的**可判定结果**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssemblyEvent {
    /// 收到并**成功解密**一个数据报文（明文已交还上层）。
    Delivered {
        /// 帧类型。
        frame_type: FrameType,
        /// 帧序号。
        seq: u64,
        /// 明文长度（**不含**明文字节本身）。
        plaintext_len: usize,
        /// 对端是否**发生了漫游**（源地址变了 ⇒ endpoint 已更新）。
        roamed: bool,
    },
    /// 收到一个 keepalive 帧（零长载荷）：**不做**认证解密，⛔ 不更新 endpoint。
    Keepalive,
    /// 收到一个**控制帧**并推进**了一步 L4 协商**。
    ///
    /// ⛔ 控制帧**绝不**当数据交给上层（见 [`crate::assembly::control`]）。
    Negotiated(NegotiationStep),
    /// 收到一个**未通过认证**的报文（认证失败 / keypair 过期）：
    /// 已丢弃，⛔ **不更新** endpoint。
    Dropped {
        /// 丢弃原因（固定短语）。
        reason: &'static str,
    },
}

impl AssemblyEvent {
    /// 本次处理是否**发生了漫游**（对端源地址变了）。
    #[must_use]
    pub fn roamed(&self) -> bool {
        matches!(self, Self::Delivered { roamed: true, .. })
    }
}
