//! 协商驱动器：把 `lengsuo-link-core` 的协商器接进装配层。

use std::time::{Duration, Instant};

use lengsuo_link_core::frame::FrameType;
use lengsuo_link_core::negotiate::{
    decode_control, CapabilitySet, ChannelMode, MessageKind, ModeSet, NegotiateError,
    NegotiateState, NegotiationResult, Negotiator, NegotiatorRole,
};
use lengsuo_link_core::session::Generation;

/// 协商推进的一步。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationStep {
    /// 响应方产出了**应答**载荷（调用方封进控制帧发出）。
    Response(Vec<u8>),
    /// 发起方拿到了**协商结果**（通道模式 + 能力集 + 世代号）。
    Completed(NegotiationResult),
}

/// 协商驱动器：装配层的 L4 接线。
#[derive(Debug, Clone)]
pub struct NegotiateDriver {
    /// 协议真相（L4 语义全在这里）。
    inner: Negotiator,
    /// 发起方请求的通道模式（响应方为 `None`）。
    requested_mode: Option<ChannelMode>,
    /// 本轮连接的世代号。
    generation: Generation,
}

impl NegotiateDriver {
    /// 造一个驱动器。
    #[must_use]
    pub const fn new(
        role: NegotiatorRole,
        requested_mode: Option<ChannelMode>,
        local_caps: CapabilitySet,
        local_modes: ModeSet,
        generation: Generation,
    ) -> Self {
        Self {
            inner: Negotiator::new(role, local_caps, local_modes, generation),
            requested_mode,
            generation,
        }
    }

    /// 本轮连接的世代号。
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// 本端的通道模式集。
    #[must_use]
    pub fn local_modes(&self) -> ModeSet {
        self.inner.local_modes()
    }

    /// 发起方：产出**提案**载荷（调用方封进控制帧发出）。
    ///
    /// # Errors
    /// - 本端不是发起方 ⇒ [`NegotiateError::RoleMismatch`]；
    /// - 发起方没配请求模式 ⇒ [`NegotiateError::Internal`]；
    /// - 重复发起 ⇒ [`NegotiateError::InvalidState`]；
    /// - 请求模式本端不支持 ⇒ [`NegotiateError::ChannelModeNotSupported`]。
    pub fn propose(&mut self, now: Instant) -> Result<Vec<u8>, NegotiateError> {
        // 角色先判：本端不是发起方 ⇒ 直接拒绝（⛔ 不拿「随便一个模式」凑数）。
        if self.inner.role() != NegotiatorRole::Initiator {
            return Err(NegotiateError::RoleMismatch {
                actual: self.inner.role().as_str(),
                expected: NegotiatorRole::Initiator.as_str(),
            });
        }
        let Some(requested) = self.requested_mode else {
            return Err(NegotiateError::Internal("发起方未配置请求的通道模式"));
        };
        self.inner.propose(requested, now)
    }

    /// 响应方：消费**提案**并产出**应答**载荷。
    ///
    /// # Errors
    /// - 本端不是响应方 ⇒ [`NegotiateError::RoleMismatch`]；
    /// - 提案不合法 / 世代号不匹配 / 无共同模式 ⇒ 对应的 [`NegotiateError`]。
    pub fn accept_proposal(
        &mut self,
        proposal: &[u8],
        now: Instant,
    ) -> Result<Vec<u8>, NegotiateError> {
        self.inner.accept_proposal(proposal, now)
    }

    /// 发起方：消费**应答**并确定协商结果。
    ///
    /// # Errors
    /// - 本端不是发起方 / 状态不对 ⇒ [`NegotiateError::RoleMismatch`] /
    ///   [`NegotiateError::InvalidState`]；
    /// - 应答不合法 / 世代号不匹配 / 对端选中的模式本端不支持 ⇒ 对应的
    ///   [`NegotiateError`]。
    pub fn accept_response(
        &mut self,
        response: &[u8],
        now: Instant,
    ) -> Result<NegotiationResult, NegotiateError> {
        self.inner.accept_response(response, now)
    }

    /// 超时判定：**阈值由调用方给**（⛔ 本 crate 不写死任何节奏常量）。
    #[must_use]
    pub fn is_timed_out(&self, now: Instant, timeout: Duration) -> bool {
        self.inner.is_timed_out(now, timeout)
    }

    /// 协商结果（未完成时为 `None`）。
    #[must_use]
    pub fn result(&self) -> Option<NegotiationResult> {
        self.inner.result()
    }

    /// 当前状态。
    #[must_use]
    pub fn state(&self) -> NegotiateState {
        self.inner.state()
    }

    /// 消费一个**控制帧**里的协商载荷，推进协商一步。
    ///
    /// ⛔ 帧类型纪律：非控制帧 ⇒ [`NegotiateError::WrongFrameType`]，
    /// ⛔ **不解析**载荷。
    pub fn consume_frame(
        &mut self,
        frame_type: FrameType,
        plaintext: &[u8],
        now: Instant,
    ) -> Result<NegotiationStep, NegotiateError> {
        let message = decode_control(frame_type, plaintext)?;
        match message.kind {
            MessageKind::Proposal => Ok(NegotiationStep::Response(
                self.accept_proposal(plaintext, now)?,
            )),
            MessageKind::Response => Ok(NegotiationStep::Completed(
                self.accept_response(plaintext, now)?,
            )),
        }
    }
}
