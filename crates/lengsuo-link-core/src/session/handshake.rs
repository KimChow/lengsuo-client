//! L2 握手编排：发起方与响应方两条路径。
//!
//! 本模块只做**编排**：调用 `lengsuo_wireguard` 的握手状态机、搬运字节、
//! 维护本卡自己的状态与世代号。**不重写**任何密码学（不自己实现
//! ChaCha20Poly1305、不自己实现 Noise IK）。
//!
//! # 多轮会话（重连）：responder 如何重建
//!
//! `lengsuo_wireguard::handshake::Responder::begin_symmetric_session(self)`
//! **消费 self**——一次握手后响应方状态机就没了。本卡给的答案是：
//! **会话对象持有重建 responder 所需的全部材料**（本端静态私钥 + 对端静态公钥
//! + 可选 PSK），每轮握手**重新构造**一个 `Responder`：
//!
//! ```text
//! 第 1 轮: Responder::new(..) ─consume_initiation─▶ create_response
//!          ─begin_symmetric_session(self)─▶ ResponderKeys（状态机被消费）
//! 第 2 轮: Responder::new(..) ─consume_initiation─▶ create_response
//!          ─begin_symmetric_session(self)─▶ ResponderKeys
//! ```
//!
//! 发起方同理：每轮 `create_initiation` 都**新建**一个 `Handshake`
//! （`Handshake` 同样是单向状态机，`consume_response` 之后不可复用）。
//!
//! 密钥材料由**调用方注入**（本卡不生成密钥、不做密钥分发）。
//!
//! ⚠️ 重建会**重置 responder 内部的重放/洪水记账**（`last_timestamp` 与
//! `last_initiation_consumption` 是实例字段，跨轮不可见）。本卡在**会话层**
//! 把这两项检查补齐（见 [`Session::consume_initiation`]），所以重建不损失防护。
//!
//! ⚠️ 握手报文里的随机数（临时私钥种子）也由**调用方传入**——本卡不引入
//! `getrandom`、不调用任何随机源，保持确定性、可对拍。

use std::time::{Duration, Instant};

use lengsuo_wireguard::handshake::{
    tai64n_after, Handshake, Responder, ResponderError, HANDSHAKE_INITIATION_RATE, INITIATION_LEN,
};
use lengsuo_wireguard::transport::Error as TransportError;

use super::error::SessionError;
use super::state::{Generation, SessionRole};
use super::Session;

/// 会话配置：调用方注入的**静态密钥材料**与策略参数。
///
/// ⚠️ 持有本端静态私钥 ⇒ **绝不派生 `Debug`**（本文件手写 `Debug`，
/// 只输出角色与「有没有密钥」，不输出任何密钥字节）。
#[derive(Clone)]
pub struct SessionConfig {
    /// 本端在本次会话中的角色。
    pub role: SessionRole,
    /// 本端静态私钥（32 字节）。**由调用方注入**，本卡不生成、不分发。
    pub local_static_private: [u8; 32],
    /// 对端静态公钥（32 字节）。**由调用方注入**。
    pub remote_static_public: [u8; 32],
    /// 可选预共享密钥（32 字节）。
    pub preshared_key: Option<[u8; 32]>,
    /// 会话层的**握手洪水窗口**：两次「消费 initiation」之间的最小时间间隔。
    ///
    /// 默认取 `lengsuo_wireguard` 的 `HANDSHAKE_INITIATION_RATE`（20ms）——
    /// 因为重建 responder 会重置它内部的洪水记账（见模块文档），本卡在会话层
    /// 用**调用方传入的时间戳**补上这道检查。设为 `Duration::ZERO` 关闭。
    pub handshake_flood_window: Duration,
    /// 会话的**起始世代号**。
    ///
    /// 默认 [`Generation::INITIAL`]（= 0）：本对象第一次握手成功后仍为初始值，
    /// 之后每次重新握手 +1。
    ///
    /// ⚠️ 如果调用方在**重连时新建**会话对象（而不是复用同一个对象），
    /// 必须用本字段把号段接续下去（传 `上一代 + 1`），否则世代号会退回初始值、
    /// 失去「区分旧连接迟到包」的意义。
    pub initial_generation: Generation,
}

impl SessionConfig {
    /// 用默认洪水窗口（20ms）与初始世代号构造配置。
    #[must_use]
    pub fn new(
        role: SessionRole,
        local_static_private: [u8; 32],
        remote_static_public: [u8; 32],
    ) -> Self {
        Self {
            role,
            local_static_private,
            remote_static_public,
            preshared_key: None,
            handshake_flood_window: HANDSHAKE_INITIATION_RATE,
            initial_generation: Generation::INITIAL,
        }
    }

    /// 附加预共享密钥。
    #[must_use]
    pub fn with_preshared_key(mut self, psk: [u8; 32]) -> Self {
        self.preshared_key = Some(psk);
        self
    }

    /// 覆盖握手洪水窗口（`Duration::ZERO` = 关闭会话层洪水检查）。
    #[must_use]
    pub fn with_handshake_flood_window(mut self, window: Duration) -> Self {
        self.handshake_flood_window = window;
        self
    }

    /// 指定会话的**起始世代号**（重连时新建对象时用它接续号段）。
    #[must_use]
    pub fn with_initial_generation(mut self, generation: Generation) -> Self {
        self.initial_generation = generation;
        self
    }

    /// 校验密钥材料（fail-closed）。
    ///
    /// # Errors
    /// 对端公钥或本端私钥为全零 ⇒ `SessionError::InvalidKeyMaterial`。
    pub fn validate(&self) -> Result<(), SessionError> {
        if self.remote_static_public == [0u8; 32] {
            return Err(SessionError::InvalidKeyMaterial("对端静态公钥为全零"));
        }
        if self.local_static_private == [0u8; 32] {
            return Err(SessionError::InvalidKeyMaterial("本端静态私钥为全零"));
        }
        Ok(())
    }
}

impl core::fmt::Debug for SessionConfig {
    /// **只输出角色与密钥长度**，绝不输出任何密钥字节。
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SessionConfig")
            .field("role", &self.role)
            .field("has_local_static_private", &true)
            .field("has_remote_static_public", &true)
            .field("has_preshared_key", &self.preshared_key.is_some())
            .field("handshake_flood_window", &self.handshake_flood_window)
            // 故意不输出任何密钥字节。
            .finish_non_exhaustive()
    }
}

/// 发起方在途握手：状态机 + 本轮使用的本端 index。
pub(crate) struct PendingInitiator {
    pub(crate) handshake: Handshake,
}

/// 响应方在途握手：状态机。
pub(crate) struct PendingResponder {
    pub(crate) responder: Responder,
}

impl Session {
    /// **发起方**：构造 initiation 报文（148 字节）。
    ///
    /// `seed` 是本轮临时私钥种子（32 字节，**由调用方提供**）；`local_index`
    /// 是本轮的本端 index（每轮必须是**新**的——index 与 key epoch 一一对应，
    /// 复用会让对端把新密钥的包当成旧 epoch 的包）。
    ///
    /// `now` 被接受是为了**接口统一**（响应方路径用它做洪水检查）；发起方
    /// 路径当前不消费时间。
    ///
    /// # Errors
    /// - 角色不是发起方 ⇒ `SessionError::RoleMismatch`。
    /// - 已有握手在途 ⇒ `SessionError::InvalidState`。
    /// - 密钥材料非法 ⇒ `SessionError::InvalidKeyMaterial`。
    pub fn create_initiation(
        &mut self,
        seed: [u8; 32],
        local_index: u32,
        _now: Instant,
    ) -> Result<Vec<u8>, SessionError> {
        self.require_role(SessionRole::Initiator)?;
        self.require_no_handshake_in_flight()?;

        let mut handshake = Handshake::new(
            &self.config().local_static_private,
            &self.config().remote_static_public,
            self.config().preshared_key,
            local_index,
        )
        .map_err(map_handshake_setup_error)?;
        let initiation = handshake
            .create_initiation(seed)
            .map_err(map_initiator_error)?;
        self.set_pending_initiator(PendingInitiator { handshake });
        self.mark_handshaking();
        Ok(initiation.to_vec())
    }

    /// **发起方**：消费响应方返回的 response 报文（92 字节）并落地传输上下文。
    ///
    /// 成功后：会话进入 `Established`，世代号按「重新握手则 +1」的规则推进。
    ///
    /// # Errors
    /// - 没有在途的 initiation ⇒ `SessionError::InvalidState`。
    /// - 响应报文非法/认证失败 ⇒ `SessionError::InitiatorFailed`（**不回退明文**；
    ///   旧的传输上下文仍然有效，状态回退到握手前的样子）。
    pub fn consume_response(&mut self, wire: &[u8], _now: Instant) -> Result<(), SessionError> {
        self.require_role(SessionRole::Initiator)?;
        let Some(mut pending) = self.take_pending_initiator() else {
            return Err(SessionError::invalid_state(self.state(), self.role()));
        };
        let keys = match pending.handshake.consume_response(wire) {
            Ok(keys) => keys,
            Err(error) => {
                self.recover_after_handshake_failure();
                return Err(map_initiator_error(error));
            }
        };
        let (sender, receiver) = build_transport(
            &keys.send,
            &keys.receive,
            keys.remote_index,
            keys.local_index,
        )?;
        self.install_transport(sender, receiver, keys.local_index, keys.remote_index);
        Ok(())
    }

    /// **响应方**：消费对端发来的 initiation 报文（148 字节）。
    ///
    /// 本方法负责三件事：
    /// 1. **MAC1 校验**（参考实现把 MAC 检查放在剥壳之前，本卡同序）；
    /// 2. **会话层洪水检查**（重建 responder 会重置它内部的洪水记账，
    ///    这里用调用方传入的 `now` 补上）；
    /// 3. **会话层重放检查**（同理，用上一次接受的 TAI64N 时间戳比对）。
    ///
    /// # Errors
    /// - 角色不是响应方 ⇒ `SessionError::RoleMismatch`。
    /// - 已有握手在途 ⇒ `SessionError::InvalidState`。
    /// - 报文长度不符 ⇒ `SessionError::HandshakeLength`。
    /// - MAC1 校验失败 ⇒ `SessionError::HandshakeMacFailed`。
    /// - 剥壳失败（类型/认证/未知对端）⇒ 对应的 `SessionError`。
    /// - 命中洪水窗口 ⇒ `SessionError::HandshakeFlood`。
    /// - 时间戳不晚于上一轮 ⇒ `SessionError::HandshakeReplay`。
    pub fn consume_initiation(&mut self, wire: &[u8], now: Instant) -> Result<(), SessionError> {
        self.require_role(SessionRole::Responder)?;
        self.require_no_handshake_in_flight()?;
        self.check_flood_window(now)?;

        // 长度先于 MAC1：`check_mac1` 会按报文尾部长度切片，短报体会越界。
        if wire.len() != INITIATION_LEN {
            return Err(SessionError::HandshakeLength {
                actual: wire.len(),
                expected: INITIATION_LEN,
            });
        }

        // 每轮**重新构造** responder：begin_symmetric_session 会消费它。
        let mut responder = Responder::new(
            &self.config().local_static_private,
            &self.config().remote_static_public,
            self.config().preshared_key,
            0,
        )
        .map_err(map_responder_error)?;

        // MAC1 先于剥壳（对齐参考实现的接收顺序）。
        if !responder.check_mac1(wire) {
            return Err(SessionError::HandshakeMacFailed);
        }
        responder
            .consume_initiation(wire)
            .map_err(map_responder_error)?;

        // 会话层重放检查：时间戳必须严格晚于上一轮接受的。
        if let Some(timestamp) = responder.last_timestamp() {
            if let Some(previous) = self.last_accepted_timestamp() {
                if !tai64n_after(&timestamp, &previous) {
                    return Err(SessionError::HandshakeReplay);
                }
            }
            self.set_last_accepted_timestamp(timestamp);
        }
        self.set_last_initiation_at(now);
        self.set_pending_responder(PendingResponder { responder });
        self.mark_handshaking();
        Ok(())
    }

    /// **响应方**：构造 response 报文（92 字节）并落地传输上下文。
    ///
    /// 成功后：会话进入 `Established`，世代号按「重新握手则 +1」的规则推进。
    ///
    /// `seed` 是本轮临时私钥种子（**由调用方提供**）；`local_index` 是本轮的
    /// 本端 index（每轮必须是**新**的）。
    ///
    /// # Errors
    /// - 角色不是响应方 ⇒ `SessionError::RoleMismatch`。
    /// - 没有在途的 initiation ⇒ `SessionError::InvalidState`。
    /// - 状态机失步 / 密钥非法 ⇒ 对应的 `SessionError`。
    pub fn create_response(
        &mut self,
        seed: [u8; 32],
        local_index: u32,
        _now: Instant,
    ) -> Result<Vec<u8>, SessionError> {
        self.require_role(SessionRole::Responder)?;
        let Some(pending) = self.take_pending_responder() else {
            return Err(SessionError::invalid_state(self.state(), self.role()));
        };
        let mut responder = pending.responder;
        let mut response = responder
            .create_response(seed, local_index)
            .map_err(map_responder_error)?;
        // 参考实现里 MAC 由 peer 的 cookieGenerator 加在 response 上。
        responder.add_macs(&mut response);
        // begin_symmetric_session 消费 responder（这是「一轮一建」的根因）。
        let keys = responder
            .begin_symmetric_session()
            .map_err(map_responder_error)?;
        let (sender, receiver) = build_transport(
            &keys.send,
            &keys.receive,
            keys.remote_index,
            keys.local_index,
        )?;
        self.install_transport(sender, receiver, keys.local_index, keys.remote_index);
        Ok(response.to_vec())
    }
}

/// 用派生的传输密钥组装收发上下文。
fn build_transport(
    send: &[u8; 32],
    receive: &[u8; 32],
    remote_index: u32,
    local_index: u32,
) -> Result<
    (
        lengsuo_wireguard::transport::Sender,
        lengsuo_wireguard::transport::Receiver,
    ),
    SessionError,
> {
    use lengsuo_wireguard::timer_constants::REJECT_AFTER_MESSAGES;
    use lengsuo_wireguard::transport::{Receiver, Sender, TransportKey};

    let send_key = TransportKey::new(send).map_err(SessionError::from)?;
    let receive_key = TransportKey::new(receive).map_err(SessionError::from)?;
    Ok((
        Sender::new(send_key, remote_index, 0),
        Receiver::new(receive_key, local_index, REJECT_AFTER_MESSAGES),
    ))
}

/// 握手上下文构造失败（静态密钥非法等）。
fn map_handshake_setup_error(error: TransportError) -> SessionError {
    match error {
        TransportError::AuthFailed => SessionError::InvalidKeyMaterial("静态密钥派生出的公钥非法"),
        TransportError::KeyLength { actual, expected } => {
            SessionError::KeyLength { actual, expected }
        }
        _ => SessionError::HandshakeSetup("握手上下文构造失败"),
    }
}

/// 发起方握手失败（只保留**可区分**的语义，不透传 wireguard 内部枚举）。
fn map_initiator_error(error: TransportError) -> SessionError {
    match error {
        TransportError::AuthFailed => SessionError::InitiatorFailed("响应报文认证失败"),
        TransportError::TooLong { actual, limit } => SessionError::HandshakeLength {
            actual,
            expected: limit,
        },
        TransportError::ReceiverMismatch { .. } => {
            SessionError::HandshakeState("响应报文接收者标识不匹配")
        }
        TransportError::Poisoned => SessionError::HandshakeState("发起方握手状态机失步"),
        TransportError::CounterExhausted { .. } | TransportError::SealFailed => {
            SessionError::HandshakeSetup("发起方握手内部状态异常")
        }
        TransportError::KeyLength { actual, expected } => {
            SessionError::KeyLength { actual, expected }
        }
        TransportError::NotTransport(_) | TransportError::Wire(_) | TransportError::Replay(_) => {
            SessionError::InitiatorFailed("响应报文不是合法的握手响应")
        }
    }
}

/// 响应方握手失败（逐项映射，见 `SessionError: From<ResponderError>`）。
fn map_responder_error(error: ResponderError) -> SessionError {
    SessionError::from(error)
}
