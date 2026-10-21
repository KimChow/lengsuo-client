//! L4 协商的**角色 / 状态 / 结果**类型。
//!
//! 这三个类型是本卡对外的「协商语义」入口：
//! - [`NegotiatorRole`]：本端在这次协商里是发起方还是响应方；
//! - [`NegotiateState`]：协商状态机的五个状态；
//! - [`NegotiationResult`]：协商成功后**唯一**的产出
//!   （通道模式 + 能力集 + 世代号）。
//!
//! 状态机的**编排**在 [`crate::negotiate::negotiator`]。

use crate::session::Generation;

use super::capabilities::CapabilitySet;
use super::channel::ChannelMode;

/// 协商角色（一次协商内固定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NegotiatorRole {
    /// 发起方：产出提案、消费应答。
    Initiator,
    /// 响应方：消费提案、产出应答。
    Responder,
}

impl NegotiatorRole {
    /// 稳定英文名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
        }
    }

    /// 对侧角色。
    #[must_use]
    pub const fn peer(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

/// 协商状态机的状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NegotiateState {
    /// 空闲：还没开始协商。
    Idle,
    /// 等待对端应答（发起方已产出提案）。
    Proposing,
    /// 已应答（响应方已产出应答）。
    Answered,
    /// 已完成：协商结果已确定。
    Completed,
    /// 失败：协商没成（**不产生任何结果**）。
    Failed,
}

impl NegotiateState {
    /// 稳定英文名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Proposing => "proposing",
            Self::Answered => "answered",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    /// 协商是否已经**成功**终结（结果可用）。
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Completed | Self::Answered)
    }

    /// 协商是否已经**失败**终结。
    #[must_use]
    pub const fn is_failed(self) -> bool {
        matches!(self, Self::Failed)
    }
}

/// 协商结果：通道模式 + 能力集 + 世代号。
///
/// - `capabilities()`：**有效**能力集（交集 ∩ 已知位）——对外的「能用什么」；
/// - `raw_capabilities()`：**原始**交集掩码（含未知位）——供跨版本比对与诊断。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiationResult {
    channel_mode: ChannelMode,
    capabilities: CapabilitySet,
    raw_capabilities: CapabilitySet,
    generation: Generation,
}

impl NegotiationResult {
    /// 构造一个协商结果（**只由本 crate 的状态机调用**）。
    pub(crate) const fn new(
        channel_mode: ChannelMode,
        capabilities: CapabilitySet,
        raw_capabilities: CapabilitySet,
        generation: Generation,
    ) -> Self {
        Self {
            channel_mode,
            capabilities,
            raw_capabilities,
            generation,
        }
    }

    /// 选中的通道模式。
    #[must_use]
    pub const fn channel_mode(self) -> ChannelMode {
        self.channel_mode
    }

    /// 生效能力集（**交集** ∩ 已知位）。
    #[must_use]
    pub const fn capabilities(self) -> CapabilitySet {
        self.capabilities
    }

    /// 原始能力集（**交集**，含未知位）。
    #[must_use]
    pub const fn raw_capabilities(self) -> CapabilitySet {
        self.raw_capabilities
    }

    /// 确认过的世代号。
    #[must_use]
    pub const fn generation(self) -> Generation {
        self.generation
    }

    /// 世代号的数值形式。
    #[must_use]
    pub const fn generation_value(self) -> u64 {
        self.generation.value()
    }
}
