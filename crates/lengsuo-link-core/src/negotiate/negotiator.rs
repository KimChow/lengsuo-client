//! L4 协商器：协商状态机的**编排**。
//!
//! 本文件把「通道模式」（[`ChannelMode`]）、「能力集」（[`CapabilitySet`]）与
//! 「世代号」（[`Generation`]）按 [`crate::negotiate`] §2 的流程组合成一个
//! **纯状态机**——**无 IO、无时钟驱动、无线程**。
//!
//! 载荷的编解码在 [`crate::negotiate::message`]，
//! 错误码目录在 [`crate::negotiate::error`]，
//! 角色 / 状态 / 结果类型在 [`crate::negotiate::state`]。

use std::time::{Duration, Instant};

use crate::session::Generation;

use super::capabilities::CapabilitySet;
use super::channel::{select_channel_mode, ChannelMode, ModeSet};
use super::error::NegotiateError;
use super::message::{MessageKind, NegotiationMessage};
use super::state::{NegotiateState, NegotiationResult, NegotiatorRole};

/// 协商器：一端的状态机。
///
/// **不持有**任何 IO 资源：只持有角色、本端能力集/模式集、世代号与状态。
#[derive(Debug, Clone)]
pub struct Negotiator {
    role: NegotiatorRole,
    local_caps: CapabilitySet,
    local_modes: ModeSet,
    generation: Generation,
    state: NegotiateState,
    result: Option<NegotiationResult>,
    peer_caps: Option<CapabilitySet>,
    peer_unknown_caps: CapabilitySet,
    requested_mode: Option<ChannelMode>,
    started_at: Option<Instant>,
}

impl Negotiator {
    /// 构造一个协商器。
    ///
    /// - `local_caps`：本端支持的**可选特性**位集；
    /// - `local_modes`：本端支持的**通道模式**集。
    #[must_use]
    pub const fn new(
        role: NegotiatorRole,
        local_caps: CapabilitySet,
        local_modes: ModeSet,
        generation: Generation,
    ) -> Self {
        Self {
            role,
            local_caps,
            local_modes,
            generation,
            state: NegotiateState::Idle,
            result: None,
            peer_caps: None,
            peer_unknown_caps: CapabilitySet::empty(),
            requested_mode: None,
            started_at: None,
        }
    }

    /// 本端角色。
    #[must_use]
    pub const fn role(&self) -> NegotiatorRole {
        self.role
    }

    /// 当前状态。
    #[must_use]
    pub const fn state(&self) -> NegotiateState {
        self.state
    }

    /// 本端能力集。
    #[must_use]
    pub const fn local_capabilities(&self) -> CapabilitySet {
        self.local_caps
    }

    /// 本端模式集。
    #[must_use]
    pub const fn local_modes(&self) -> ModeSet {
        self.local_modes
    }

    /// 对端能力集（已知位部分；未知位被剥离）。
    #[must_use]
    pub const fn peer_capabilities(&self) -> Option<CapabilitySet> {
        self.peer_caps
    }

    /// 对端能力集里**本实现不认识**的位（**被忽略并记录**）。
    #[must_use]
    pub const fn peer_unknown_capabilities(&self) -> CapabilitySet {
        self.peer_unknown_caps
    }

    /// 协商结果（未完成时为 `None`）。
    #[must_use]
    pub const fn result(&self) -> Option<NegotiationResult> {
        self.result
    }

    /// 协商是否已完成（结果可用）。
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.state.is_complete()
    }

    /// 协商是否已失败。
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        self.state.is_failed()
    }

    /// 发起方：产出**提案**（明文载荷，由调用方封进控制帧）。
    ///
    /// # Errors
    /// - 角色不是发起方 ⇒ `NegotiateError::RoleMismatch`。
    /// - 状态不是 `Idle`（重复发起）⇒ `NegotiateError::InvalidState`。
    /// - 本端不支持请求的模式 ⇒ `NegotiateError::ChannelModeNotSupported`。
    /// - 编码后超长 ⇒ `NegotiateError::PayloadTooLarge`。
    pub fn propose(
        &mut self,
        requested: ChannelMode,
        now: Instant,
    ) -> Result<Vec<u8>, NegotiateError> {
        if self.role != NegotiatorRole::Initiator {
            return Err(self.fail(NegotiateError::RoleMismatch {
                actual: self.role.as_str(),
                expected: NegotiatorRole::Initiator.as_str(),
            }));
        }
        if self.state != NegotiateState::Idle {
            return Err(self.fail(NegotiateError::InvalidState {
                state: self.state.as_str(),
                role: self.role.as_str(),
            }));
        }
        if !self.local_modes.contains(requested) {
            return Err(self.fail(NegotiateError::ChannelModeNotSupported {
                mode: requested.as_str(),
            }));
        }
        let message = NegotiationMessage::proposal(
            requested,
            self.generation.value(),
            self.local_caps,
            self.local_modes,
        );
        let bytes = match message.encode() {
            Ok(bytes) => bytes,
            Err(error) => return Err(self.fail(error)),
        };
        self.requested_mode = Some(requested);
        self.started_at = Some(now);
        self.state = NegotiateState::Proposing;
        Ok(bytes)
    }

    /// 响应方：消费**提案**并产出**应答**（明文载荷，由调用方封进控制帧）。
    ///
    /// # Errors
    /// - 角色不是响应方 ⇒ `NegotiateError::RoleMismatch`。
    /// - 状态不是 `Idle` ⇒ `NegotiateError::InvalidState`。
    /// - 提案不合法 ⇒ `NegotiateError::MalformedMessage` / `UnsupportedVersion`。
    /// - 世代号不匹配 ⇒ `NegotiateError::GenerationMismatch`（**不继续用旧连接**）。
    /// - **模式集**交集为空 ⇒ `NegotiateError::NoCommonChannelMode`
    ///   （⛔ **不**回退到 `p2p`）。
    /// - 编码后超长 ⇒ `NegotiateError::PayloadTooLarge`。
    pub fn accept_proposal(
        &mut self,
        proposal: &[u8],
        now: Instant,
    ) -> Result<Vec<u8>, NegotiateError> {
        if self.role != NegotiatorRole::Responder {
            return Err(self.fail(NegotiateError::RoleMismatch {
                actual: self.role.as_str(),
                expected: NegotiatorRole::Responder.as_str(),
            }));
        }
        if self.state != NegotiateState::Idle {
            return Err(self.fail(NegotiateError::InvalidState {
                state: self.state.as_str(),
                role: self.role.as_str(),
            }));
        }
        let message = match NegotiationMessage::decode(proposal) {
            Ok(message) => message,
            Err(error) => return Err(self.fail(error)),
        };
        if message.kind != MessageKind::Proposal {
            return Err(self.fail(NegotiateError::malformed("期望提案，收到应答")));
        }
        if message.generation != self.generation.value() {
            return Err(self.fail(NegotiateError::GenerationMismatch {
                local: self.generation.value(),
                remote: message.generation,
            }));
        }

        // 记录对端能力集；未知位**被记录**但**不参与**交集结果。
        self.peer_caps = Some(message.local_caps.known_only());
        self.peer_unknown_caps = CapabilitySet::from_bits(message.local_caps.unknown_bits());
        self.started_at = Some(now);

        // 模式集交集为空 ⇒ **协商失败**（没有共同可走的通道）。
        let common_modes = self.local_modes.intersection(message.local_modes);
        if common_modes.is_empty() {
            return Err(self.fail(NegotiateError::NoCommonChannelMode {
                requested: message.channel_mode.as_str(),
            }));
        }
        // 能力集交集：可以为空（**没有共同的可选特性**），这**不**是协商失败。
        let common_caps = self.local_caps.intersection(message.local_caps);

        let selected = match select_channel_mode(common_modes, message.channel_mode) {
            Ok(mode) => mode,
            Err(error) => return Err(self.fail(error)),
        };

        let response = NegotiationMessage::response(
            selected,
            self.generation.value(),
            self.local_caps,
            common_caps,
            self.local_modes,
            common_modes,
        );
        let bytes = match response.encode() {
            Ok(bytes) => bytes,
            Err(error) => return Err(self.fail(error)),
        };
        self.result = Some(NegotiationResult::new(
            selected,
            common_caps.known_only(),
            common_caps,
            self.generation,
        ));
        self.state = NegotiateState::Answered;
        Ok(bytes)
    }

    /// 发起方：消费**应答**并确定协商结果。
    ///
    /// # Errors
    /// - 角色不是发起方 ⇒ `NegotiateError::RoleMismatch`。
    /// - 状态不是 `Proposing` ⇒ `NegotiateError::InvalidState`。
    /// - 应答不合法 ⇒ `NegotiateError::MalformedMessage` / `UnsupportedVersion`。
    /// - 世代号不匹配 ⇒ `NegotiateError::GenerationMismatch`。
    /// - 对端选中的模式本端不支持 ⇒ `NegotiateError::ChannelModeNotAccepted`。
    pub fn accept_response(
        &mut self,
        response: &[u8],
        now: Instant,
    ) -> Result<NegotiationResult, NegotiateError> {
        if self.role != NegotiatorRole::Initiator {
            return Err(self.fail(NegotiateError::RoleMismatch {
                actual: self.role.as_str(),
                expected: NegotiatorRole::Initiator.as_str(),
            }));
        }
        if self.state != NegotiateState::Proposing {
            return Err(self.fail(NegotiateError::InvalidState {
                state: self.state.as_str(),
                role: self.role.as_str(),
            }));
        }
        let message = match NegotiationMessage::decode(response) {
            Ok(message) => message,
            Err(error) => return Err(self.fail(error)),
        };
        if message.kind != MessageKind::Response {
            return Err(self.fail(NegotiateError::malformed("期望应答，收到提案")));
        }
        if message.generation != self.generation.value() {
            return Err(self.fail(NegotiateError::GenerationMismatch {
                local: self.generation.value(),
                remote: message.generation,
            }));
        }
        if !self.local_modes.contains(message.channel_mode) {
            return Err(self.fail(NegotiateError::ChannelModeNotAccepted {
                mode: message.channel_mode.as_str(),
            }));
        }
        // 对端声称的「共同模式集」必须**包含**它自己选中的模式，
        // 且**不得**包含本端根本不支持的模式（对端算错 ⇒ 拒绝该结果）。
        let claimed = message.common_modes;
        if !claimed.contains(message.channel_mode)
            || !claimed.iter().all(|mode| self.local_modes.contains(mode))
        {
            return Err(self.fail(NegotiateError::ChannelModeNotAccepted {
                mode: message.channel_mode.as_str(),
            }));
        }

        self.peer_caps = Some(message.local_caps.known_only());
        self.peer_unknown_caps = CapabilitySet::from_bits(message.local_caps.unknown_bits());
        self.started_at = Some(now);

        // 生效能力 = 对端应答里的交集 ∩ 本端能力（防御对端算错）∩ 已知位。
        let common = self.local_caps.intersection(message.effective_caps);
        let result = NegotiationResult::new(
            message.channel_mode,
            common.known_only(),
            common,
            self.generation,
        );
        self.result = Some(result);
        self.state = NegotiateState::Completed;
        Ok(result)
    }

    /// 超时判定：**由调用方传入时间戳**，本 crate 不起计时器。
    ///
    /// - `now`：调用方当前时刻（单调钟）。
    /// - `timeout`：阈值。
    ///
    /// 返回 `true` ⇒ 协商已**超时**（调用方应放弃这次协商并报错）。
    /// 协商已完成或失败时一律返回 `false`（没有再等的必要）。
    #[must_use]
    pub fn is_timed_out(&self, now: Instant, timeout: Duration) -> bool {
        if self.state.is_complete() || self.state.is_failed() {
            return false;
        }
        let Some(started_at) = self.started_at else {
            return false;
        };
        now.checked_duration_since(started_at)
            .is_some_and(|elapsed| elapsed >= timeout)
    }

    /// 本端请求的模式（发起方）。
    #[must_use]
    pub const fn requested_mode(&self) -> Option<ChannelMode> {
        self.requested_mode
    }

    /// 记录一次失败：置 `Failed` 态并**清空结果**。
    ///
    /// ⛔ 失败后**绝不**留下「协商结果」——上层拿不到任何
    /// 「默认通道模式」可以回退。
    fn fail(&mut self, error: NegotiateError) -> NegotiateError {
        self.state = NegotiateState::Failed;
        self.result = None;
        error
    }
}
