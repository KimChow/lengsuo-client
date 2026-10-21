//! L2 会话状态机：握手封装、传输密钥落地、连接世代号。
//!
//! 本模块把「一次 WireGuard 风格的密钥协商」变成「一个可跨端复现的会话对象」：
//! 上层（`lk-negotiate` / `lengsuo-tunnel` / 移动端 FFI 侧）能拿到
//! **确定的传输密钥 + 确定的世代号**，而本 crate 依然**不碰 socket、
//! 不碰线程、不碰时钟驱动**。
//!
//! # 分层位置
//!
//! ```text
//! L1 传输（UDP / 打洞）   crates/lengsuo-tunnel   ← 不在本卡
//! L2 会话（本模块）        crates/lengsuo-link-core/src/session
//! L3 密文帧               crates/lengsuo-link-core/src/frame
//! L4 通道协商             后续 lk-negotiate 卡    ← 不在本卡
//! L5 ACP 语义             lengsuo-agent          ← 一行不改
//! ```
//!
//! # 状态机
//!
//! ```text
//!                    create_initiation / consume_initiation
//!        Unhandshaked ─────────────────────────────────▶ Handshaking
//!             │                                            │
//!             │                            握手成功 ───────┤（consume_response / create_response）
//!             │                                            ▼
//!             │            create_initiation / consume_initiation
//!             │          ┌───────────────────────────── Established
//!             │          │                                   │
//!             ▼          ▼                                   │
//!        Invalidated ◀───────────────────────────────────────┘
//!         （AEAD 认证失败 / 显式 invalidate）
//! ```
//!
//! - **角色固定**：一次会话里要么是 initiator、要么是 responder（[`SessionRole`]）。
//! - **世代号**：每次**重新**握手成功 ⇒ 世代号 +1（见 [`Generation`]）。
//! - **失效即拒收**：AEAD 认证失败 ⇒ 会话转入 `Invalidated`，收发一律被拒，
//!   **绝不回退明文**；重连（再开一轮握手）可恢复。
//!
//! # 密钥纪律
//!
//! - 本卡**不生成**密钥、**不做**密钥分发：静态私钥 / 对端公钥 / PSK
//!   全部由调用方经 [`SessionConfig`] 注入。
//! - 握手报文里的随机数（临时私钥种子）也由调用方传入 ⇒ 本 crate
//!   **不引入随机源**（不调 `getrandom`），保持确定性与可对拍。
//! - 会话对象与配置的 `Debug` **只输出角色 / 状态 / 世代号 / 长度**，
//!   **绝不输出密钥字节**（照抄 `TransportKey` 与 `Frame` 的纪律）。

use std::time::Instant;

use lengsuo_wireguard::transport::{Receiver, Sender};

use crate::frame::{FrameType, OpenedFrame};

pub mod error;
pub mod handshake;
pub mod state;

pub use error::SessionError;
pub use handshake::SessionConfig;
pub use state::{Generation, SessionRole, SessionState};

use handshake::{PendingInitiator, PendingResponder};

/// 一个会话的传输上下文（当前 epoch）。
///
/// 只保留**当前** epoch：不做 WireGuard 的 current/previous/next 三槽轮换
/// （见 `docs/link-session-spec.md` §7 偏离清单）。旧 epoch 的包在新 epoch
/// 落地后解不开——这是本卡的已知边界，L1/L4 后续卡可补。
struct Transport {
    sender: Sender,
    receiver: Receiver,
    local_index: u32,
    remote_index: u32,
}

/// L2 会话对象。
///
/// 持有：注入的密钥材料、状态机状态、当前传输上下文、世代号。
/// **不持有**任何 socket / 线程 / 计时器；时间的推进由调用方显式传入
/// （`Instant`）。
pub struct Session {
    /// 注入的静态密钥材料与策略参数。
    config: SessionConfig,
    /// 当前状态。
    state: SessionState,
    /// 连接世代号。
    generation: Generation,
    /// 已完成的握手轮数（用于「首次握手不推进世代号」的语义）。
    handshake_count: u64,
    /// 当前 epoch 的传输上下文；`None` = 尚未建立。
    transport: Option<Transport>,
    /// 在途的发起方握手。
    pending_initiator: Option<PendingInitiator>,
    /// 在途的响应方握手。
    pending_responder: Option<PendingResponder>,
    /// 最近一次成功剥壳的 TAI64N 时间戳（会话层重放检查用）。
    last_accepted_timestamp: Option<[u8; 12]>,
    /// 最近一次消费 initiation 的时刻（会话层洪水检查用）。
    last_initiation_at: Option<Instant>,
}

impl Session {
    /// 用注入的配置构造一个**未握手**的会话。
    ///
    /// # Errors
    /// 密钥材料非法（全零等）⇒ `SessionError::InvalidKeyMaterial`。
    pub fn new(config: SessionConfig) -> Result<Self, SessionError> {
        config.validate()?;
        Ok(Self {
            state: SessionState::Unhandshaked,
            generation: config.initial_generation,
            handshake_count: 0,
            transport: None,
            pending_initiator: None,
            pending_responder: None,
            last_accepted_timestamp: None,
            last_initiation_at: None,
            config,
        })
    }

    /// 本会话的角色（initiator / responder）。
    #[must_use]
    pub fn role(&self) -> SessionRole {
        self.config.role
    }

    /// 当前状态。
    #[must_use]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// 当前世代号（调用方据此区分「旧连接的迟到包」）。
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// 本端在当前 epoch 的 index（传输报文头里的「接收者标识」）。
    #[must_use]
    pub fn local_index(&self) -> Option<u32> {
        self.transport.as_ref().map(|t| t.local_index)
    }

    /// 对端在当前 epoch 的 index。
    #[must_use]
    pub fn remote_index(&self) -> Option<u32> {
        self.transport.as_ref().map(|t| t.remote_index)
    }

    /// 会话是否已建立（可收发）。
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state.is_established()
    }

    /// 会话是否已失效。
    #[must_use]
    pub fn is_invalidated(&self) -> bool {
        self.state.is_invalidated()
    }

    /// 封一帧明文 → 线上字节（帧头 + AEAD 密文包）。
    ///
    /// # Errors
    /// - 会话已失效 ⇒ `SessionError::Invalidated`。
    /// - 尚无传输上下文 ⇒ `SessionError::InvalidState`。
    /// - 明文超长 ⇒ `SessionError::Frame(..)`（**写入前拒绝**，不消耗计数器）。
    /// - 传输层失败（poisoned / 计数器用尽）⇒ 对应错误（fatal 时会话失效）。
    pub fn seal_frame(
        &mut self,
        frame_type: FrameType,
        seq: u64,
        plain: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        self.ensure_usable()?;
        let Some(transport) = self.transport.as_mut() else {
            return Err(SessionError::invalid_state(self.state, self.role()));
        };
        match crate::frame::seal_frame(&mut transport.sender, frame_type, seq, plain) {
            Ok(bytes) => Ok(bytes),
            Err(error) => Err(self.absorb_frame_error(error)),
        }
    }

    /// 解一帧线上字节 → 明文（帧头解析 + AEAD 认证解封）。
    ///
    /// # Errors
    /// - 会话已失效 ⇒ `SessionError::Invalidated`。
    /// - 尚无传输上下文 ⇒ `SessionError::InvalidState`。
    /// - 帧不合法 ⇒ `SessionError::Frame(..)`（**不返回部分数据**）。
    /// - AEAD 认证失败 ⇒ `SessionError::AuthFailed`，且**会话立即失效**、
    ///   **绝不回退明文**。
    /// - 重放窗口拒绝 ⇒ `SessionError::ReplayRejected`（丢包，会话**仍有效**）。
    pub fn open_frame(&mut self, buf: &[u8]) -> Result<OpenedFrame, SessionError> {
        self.ensure_usable()?;
        let Some(transport) = self.transport.as_mut() else {
            return Err(SessionError::invalid_state(self.state, self.role()));
        };
        match crate::frame::open_frame(&mut transport.receiver, buf) {
            Ok(opened) => Ok(opened),
            Err(error) => Err(self.absorb_frame_error(error)),
        }
    }

    /// 显式作废当前会话（上层主动断链时调用）。
    ///
    /// 作废后：状态转入 `Invalidated`，收发一律被拒。
    pub fn invalidate(&mut self) {
        self.state = SessionState::Invalidated;
        self.pending_initiator = None;
        self.pending_responder = None;
    }

    /// **放弃当前在途的握手**（对端拒绝、超时、链路中断时调用）。
    ///
    /// 丢弃在途的握手状态机，状态回退到「已建立」（若已有传输上下文）
    /// 或「未握手」。**不**作废会话，也不推进世代号。
    ///
    /// ⚠️ 为什么需要它：发起方铸出 initiation 后若对端拒绝（洪水/重放/未知对端），
    /// 在途握手会一直挂着，导致后续 `create_initiation` 全部被拒。
    /// L1 的重试逻辑必须先调本方法（或新建会话对象）才能再试一次。
    ///
    /// 返回 `true` 表示确实丢弃了一轮在途握手。
    pub fn abort_handshake(&mut self) -> bool {
        let had_pending =
            self.pending_initiator.take().is_some() || self.pending_responder.take().is_some();
        if had_pending {
            self.recover_after_handshake_failure();
        }
        had_pending
    }

    // ---- 内部辅助（供 `handshake` 子模块使用） ----

    /// 配置（只读）。
    pub(crate) fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// 角色必须匹配。
    pub(crate) fn require_role(&self, expected: SessionRole) -> Result<(), SessionError> {
        if self.config.role == expected {
            Ok(())
        } else {
            Err(SessionError::role_mismatch(self.config.role, expected))
        }
    }

    /// 不能有在途握手。
    pub(crate) fn require_no_handshake_in_flight(&self) -> Result<(), SessionError> {
        if self.pending_initiator.is_some() || self.pending_responder.is_some() {
            return Err(SessionError::invalid_state(self.state, self.config.role));
        }
        Ok(())
    }

    /// 记下在途的发起方握手。
    pub(crate) fn set_pending_initiator(&mut self, pending: PendingInitiator) {
        self.pending_initiator = Some(pending);
    }

    /// 记下在途的响应方握手。
    pub(crate) fn set_pending_responder(&mut self, pending: PendingResponder) {
        self.pending_responder = Some(pending);
    }

    /// 取走在途的发起方握手（消费语义）。
    pub(crate) fn take_pending_initiator(&mut self) -> Option<PendingInitiator> {
        self.pending_initiator.take()
    }

    /// 取走在途的响应方握手（消费语义）。
    pub(crate) fn take_pending_responder(&mut self) -> Option<PendingResponder> {
        self.pending_responder.take()
    }

    /// 进入「握手中」。
    pub(crate) fn mark_handshaking(&mut self) {
        self.state = SessionState::Handshaking;
    }

    /// 握手失败后的回退：恢复传输上下文可用性（没有传输上下文 ⇒ 未握手）。
    pub(crate) fn recover_after_handshake_failure(&mut self) {
        self.state = match self.transport.as_ref() {
            Some(transport) if !is_poisoned(transport) => SessionState::Established,
            Some(_) => SessionState::Invalidated,
            None => SessionState::Unhandshaked,
        };
    }

    /// 落地传输上下文：换 epoch、推进世代号、进入「已建立」。
    pub(crate) fn install_transport(
        &mut self,
        sender: Sender,
        receiver: Receiver,
        local_index: u32,
        remote_index: u32,
    ) {
        self.transport = Some(Transport {
            sender,
            receiver,
            local_index,
            remote_index,
        });
        self.advance_generation();
        self.state = SessionState::Established;
    }

    /// 最近一次成功剥壳的 TAI64N 时间戳。
    pub(crate) fn last_accepted_timestamp(&self) -> Option<[u8; 12]> {
        self.last_accepted_timestamp
    }

    /// 记录最近一次成功剥壳的 TAI64N 时间戳。
    pub(crate) fn set_last_accepted_timestamp(&mut self, timestamp: [u8; 12]) {
        self.last_accepted_timestamp = Some(timestamp);
    }

    /// 记录最近一次消费 initiation 的时刻。
    pub(crate) fn set_last_initiation_at(&mut self, now: Instant) {
        self.last_initiation_at = Some(now);
    }

    /// 会话层握手洪水检查：两次消费 initiation 的间隔不得短于配置窗口。
    pub(crate) fn check_flood_window(&self, now: Instant) -> Result<(), SessionError> {
        let window = self.config.handshake_flood_window;
        if window.is_zero() {
            return Ok(());
        }
        if let Some(last) = self.last_initiation_at {
            if now
                .checked_duration_since(last)
                .is_some_and(|gap| gap < window)
            {
                return Err(SessionError::HandshakeFlood);
            }
        }
        Ok(())
    }

    /// 世代号推进：**首次**握手成功保持初始值，之后每次重新握手 +1。
    fn advance_generation(&mut self) {
        if self.handshake_count > 0 {
            self.generation = self.generation.next();
        }
        self.handshake_count = self.handshake_count.saturating_add(1);
    }

    /// 收发前的可用性检查。
    fn ensure_usable(&self) -> Result<(), SessionError> {
        if self.state.is_invalidated() {
            return Err(SessionError::Invalidated);
        }
        if self.transport.is_none() {
            return Err(SessionError::invalid_state(self.state, self.config.role));
        }
        Ok(())
    }

    /// 收纳帧层/传输层错误：**fatal 时立刻让会话失效**。
    fn absorb_frame_error(&mut self, error: crate::frame::FrameError) -> SessionError {
        let mapped = SessionError::from(error);
        if mapped.is_fatal() {
            self.state = SessionState::Invalidated;
        }
        mapped
    }
}

/// 传输上下文是否已被毒化（发送侧或接收侧任一永久 poison）。
fn is_poisoned(transport: &Transport) -> bool {
    transport.sender.is_poisoned() || transport.receiver.is_poisoned()
}

impl core::fmt::Debug for Session {
    /// **只输出角色 / 状态 / 世代号 / 索引**，绝不输出密钥字节。
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("role", &self.role())
            .field("state", &self.state())
            .field("generation", &self.generation())
            .field("handshake_count", &self.handshake_count)
            .field("local_index", &self.local_index())
            .field("remote_index", &self.remote_index())
            .field("transport", &self.transport.as_ref().map(|_| "[redacted]"))
            // 故意不输出 config（含静态私钥）、transport（含传输密钥）。
            .finish_non_exhaustive()
    }
}
