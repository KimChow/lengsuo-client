//! keepalive 驱动装配：把 `spawn_keepalive` 接到**会话状态机**上。
//!
//! # 语义（本卡的核心）
//!
//! | 会话状态 | keepalive 行为 |
//! |---|---|
//! | **未就绪**（握手未完成） | **不发**——一个字节都不发（任务**尚未启动**） |
//! | **已就绪**（握手成功、密钥已落地） | 按 `KeepaliveConfig::interval` 周期发 |
//!
//! ⛔ **未就绪时绝不发**：没有会话密钥时发出去的帧对端解不开，
//! 只会白白消耗对端的重放窗口与认证尝试。
//!
//! # 接线方式（为什么是「**会话就绪时才启动任务**」）
//!
//! L1 的 [`spawn_keepalive`] 只提供**发包能力**，它不知道会话是否就绪
//! （那是 L2 的事）。⇒ 装配层的接法是：**先建驱动，等会话就绪再启动任务**
//! （[`Assembly::start_keepalive`] 是那个「就绪才启动」的落点）。
//! 这样「未就绪 ⇒ 不发」是**结构性保证**（任务根本不存在），
//! 而不是靠运行时的条件判断。
//!
//! # keepalive 载荷
//!
//! keepalive 必须是**合法的零长载荷帧**（[`FrameType::Keepalive`] + 空载荷），
//! ⛔ **不能是裸字节**：裸字节在 L3 层解不开帧，对端只会当成坏包丢掉。
//! （L1 的 `spawn_keepalive` 本来就发这种帧，本层沿用同一语义。）
//!
//! ⚠️ keepalive 帧**不携带**被认证的身份信息 ⇒ 接收侧**不**据此更新
//! endpoint（见 [`crate::assembly::session::Assembly::receive_frame`]）。

use std::time::Duration;

use lengsuo_link_core::frame::{Frame, FrameType};

use crate::assembly::error::AssemblyError;
use crate::udp::{spawn_keepalive, Cancel, KeepaliveConfig, KeepaliveHandle, UdpEndpoint};

/// keepalive 载荷帧：合法的**零长载荷**帧。
///
/// ⛔ **不是裸字节**——它必须能被 L3 帧层解码，否则对端只会当成坏包丢掉。
#[must_use]
pub fn keepalive_frame() -> Frame {
    Frame::new(FrameType::Keepalive, 0, Vec::new())
}

/// 装配层的 keepalive 驱动。
///
/// 生命周期：`new`（**未启动**，不发任何包）→ `activate`（会话就绪，启动任务）
/// → `stop`（停掉任务）。
///
/// ⚠️ 配置直接复用 L1 的 [`KeepaliveConfig`]——本层**不**另造一份配置类型
/// （避免两套「间隔可选」的语义漂移）。
pub struct KeepaliveDriver {
    /// keepalive 间隔（`None` = 关闭 ⇒ 永不启动）。
    interval: Option<Duration>,
    /// keepalive 任务句柄（`None` = **尚未启动** ⇒ 一个字节都没发）。
    handle: Option<KeepaliveHandle>,
    /// 取消令牌。
    cancel: Cancel,
}

impl KeepaliveDriver {
    /// 造一个**尚未启动**的 keepalive 驱动。
    ///
    /// ⚠️ 此时**不会**有任何 keepalive 发出——任务还没启动。
    ///
    /// `interval` 为 `None` ⇒ 关闭 keepalive（后续 `activate` 也不会启动）。
    /// `interval` 为**零** ⇒ **拒绝**（零间隔 = busy loop，绝不允许）。
    ///
    /// # Errors
    /// 间隔为零 ⇒ [`AssemblyError::KeepaliveDisabled`]。
    pub fn new(config: KeepaliveConfig) -> Result<Self, AssemblyError> {
        if config.interval.is_some_and(|interval| interval.is_zero()) {
            return Err(AssemblyError::KeepaliveDisabled(
                "间隔为零（busy loop），拒绝启动",
            ));
        }
        Ok(Self {
            interval: config.interval,
            handle: None,
            cancel: Cancel::new(),
        })
    }

    /// 会话**就绪**后启动 keepalive 任务。
    ///
    /// ⛔ **只有会话就绪才该调它**——这正是「未就绪不发 keepalive」的落点。
    /// 正常路径请走 [`Assembly::start_keepalive`]（它自带就绪判定）。
    ///
    /// # Errors
    /// - keepalive 已关闭（无间隔）⇒ [`AssemblyError::KeepaliveDisabled`]；
    /// - 任务已在运行 ⇒ [`AssemblyError::KeepaliveAlreadyRunning`]。
    pub fn activate(&mut self, endpoint: UdpEndpoint) -> Result<(), AssemblyError> {
        let Some(interval) = self.interval else {
            return Err(AssemblyError::KeepaliveDisabled("未配置间隔"));
        };
        if self.handle.is_some() {
            return Err(AssemblyError::KeepaliveAlreadyRunning);
        }
        let handle = spawn_keepalive(
            endpoint,
            KeepaliveConfig {
                interval: Some(interval),
            },
            self.cancel.clone(),
        )
        .ok_or(AssemblyError::KeepaliveDisabled("间隔非法"))?;
        self.handle = Some(handle);
        Ok(())
    }

    /// keepalive 任务是否已启动。
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.handle.is_some()
    }

    /// 停掉 keepalive 任务并等它退出。
    ///
    /// ⚠️ 调用方必须自己加超时（与 `udp::LoopHandle::stop` 同理）。
    pub async fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(handle) = self.handle.take() {
            let _ = handle.stop().await;
        }
    }
}

impl core::fmt::Debug for KeepaliveDriver {
    /// **只输出间隔与运行状态**，不输出任何载荷内容。
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KeepaliveDriver")
            .field("interval", &self.interval)
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}
