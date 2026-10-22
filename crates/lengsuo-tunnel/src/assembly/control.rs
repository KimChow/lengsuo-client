//! L4 协商的**装配接线**：控制帧 ⇄ 协商驱动器。
//!
//! # 帧类型纪律（fail-closed）
//!
//! 控制帧**只**走协商驱动器，⛔ **绝不**当数据交给上层；
//! 反过来，数据帧也**绝不**被当成协商载荷解析。
//!
//! # 世代号
//!
//! 世代号由 **L2** 拥有（首次握手成功仍是初始值、每次重新握手成功 +1）。
//! 本模块**只携带与核对**它，⛔ 不自己生成。

use std::time::Instant;

use lengsuo_link_core::frame::FrameType;
use lengsuo_link_core::session::Generation;

use crate::assembly::error::AssemblyError;
use crate::assembly::event::AssemblyEvent;
use crate::assembly::session::Assembly;
use crate::negotiate::NegotiateDriver;

impl Assembly {
    /// 本轮连接的**世代号**（由 L2 拥有，本层只携带）。
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// 协商驱动器（只读）。`None` ⇒ 本端**没配** L4 协商。
    #[must_use]
    pub fn negotiator(&self) -> Option<&NegotiateDriver> {
        self.negotiator.as_ref()
    }

    /// 协商驱动器（可变）。供上层发起协商 / 查结果。
    pub fn negotiator_mut(&mut self) -> Option<&mut NegotiateDriver> {
        self.negotiator.as_mut()
    }

    /// 重建协商驱动器（**新的一轮**协商 ⇒ 新状态机 + 当前世代号）。
    ///
    /// 调用时机：每次握手成功落地密钥后（见 [`Assembly::install_keys`]）。
    /// ⚠️ `Negotiator` 的 `Failed` 是**吸收态** ⇒ 换世代号必须换状态机，
    /// 复用旧状态机会把「上一代的失败」带进这一代。
    pub(super) fn refresh_negotiator(&mut self) {
        let Some(config) = self.config().negotiate else {
            self.negotiator = None;
            return;
        };
        self.negotiator = Some(NegotiateDriver::new(
            config.role,
            config.requested_mode,
            config.local_caps,
            config.local_modes,
            self.generation,
        ));
    }

    /// 把一个**控制帧**的明文路由到协商驱动器。
    ///
    /// ⛔ 控制帧**绝不**作为数据交付给上层。
    pub(super) fn route_control(
        &mut self,
        plaintext: &[u8],
    ) -> Result<AssemblyEvent, AssemblyError> {
        let Some(driver) = self.negotiator.as_mut() else {
            return Err(AssemblyError::NegotiateConfig(
                "本端未配置 L4 协商：控制帧无处可去",
            ));
        };
        let step = driver
            .consume_frame(FrameType::Control, plaintext, Instant::now())
            .map_err(AssemblyError::Negotiate)?;
        Ok(AssemblyEvent::Negotiated(step))
    }
}
