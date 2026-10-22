//! L4 协商的装配层配置：角色、本端能力/模式、发起方请求的模式。

use lengsuo_link_core::negotiate::{CapabilitySet, ChannelMode, ModeSet, NegotiatorRole};

/// L4 协商的装配层配置。
///
/// ⛔ **不写死**任何能力位或模式集：由调用方按部署给。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiateConfig {
    /// 本端在**这次协商**里的角色。
    ///
    /// ⚠️ 与「L2 握手角色」是**两件事**：L4 的角色由**部署**决定
    /// （移动端固定发起、PC 端固定应答），⛔ 不由握手角色推导。
    pub role: NegotiatorRole,
    /// 本端支持的**可选特性**位集（能力集）。
    pub local_caps: CapabilitySet,
    /// 本端支持的**通道模式**集。
    pub local_modes: ModeSet,
    /// 发起方**显式请求**的通道模式（响应方为 `None`）。
    ///
    /// ⛔ 发起方**必须**显式给一个模式：协商里**没有**「默认直连」。
    pub requested_mode: Option<ChannelMode>,
}

impl NegotiateConfig {
    /// 构造一份协商配置。
    #[must_use]
    pub const fn new(
        role: NegotiatorRole,
        local_caps: CapabilitySet,
        local_modes: ModeSet,
        requested_mode: Option<ChannelMode>,
    ) -> Self {
        Self {
            role,
            local_caps,
            local_modes,
            requested_mode,
        }
    }

    /// 校验配置的**自洽性**（fail-closed）。
    ///
    /// # Errors
    /// 角色与请求模式不匹配，或请求的模式本端不支持 ⇒ 固定短语原因。
    pub fn validate(&self) -> Result<(), &'static str> {
        match (self.role, self.requested_mode) {
            (NegotiatorRole::Initiator, None) => Err("发起方必须显式请求一个通道模式"),
            (NegotiatorRole::Responder, Some(_)) => Err("响应方不得指定请求模式"),
            (NegotiatorRole::Initiator, Some(mode)) => {
                if self.local_modes.contains(mode) {
                    Ok(())
                } else {
                    Err("本端不支持请求的通道模式")
                }
            }
            (NegotiatorRole::Responder, None) => Ok(()),
        }
    }
}
