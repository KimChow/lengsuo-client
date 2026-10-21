//! L4 通道协商往返用例：协商成功 / 能力集交集 / 未知位忽略 / 世代号确认。
//!
//! 覆盖任务书 §七 的 1–4 条：
//! 1. **协商成功**：双方跑一次协商 ⇒ 双方得到**一致的协商结果**（通道模式 + 能力集 + 世代号）。
//! 2. **能力集取交集**：A 支持 {x,y}、B 支持 {y,z} ⇒ 交集 = {y}（**不是**并集 {x,y,z}）。
//! 3. **未知能力位被忽略**：对端带一个本端不认识的位 ⇒ 协商**仍然成功**，
//!    且该位**不出现**在结果里（fail-open 于**单项**、fail-closed 于**整体**）。
//! 4. **世代号匹配通过 / 不匹配报错**。
//!
//! 全部是**测试专用假密钥**（0x11 / 0x22 模式字节），不代表任何真实凭据。
//! 对端公钥用**仓外独立实现**（Python `cryptography` 的 X25519）算出后写死
//! 在本文件里——不依赖本仓的 X25519 代码自证。
//!
//! ⚠️ 本文件**不**证明与任何真实对端互通。

use std::time::{Duration, Instant};

use lengsuo_link_core::frame::FrameType;
use lengsuo_link_core::negotiate::{
    decode_control, Capability, CapabilitySet, ChannelMode, ErrorCode, MessageKind, ModeSet,
    NegotiateError, NegotiateState, NegotiationMessage, NegotiationResult, Negotiator,
    NegotiatorRole,
};
use lengsuo_link_core::session::{Generation, Session, SessionConfig, SessionRole};

// ---------------------------------------------------------------- 假密钥材料

/// 发起方静态私钥（测试专用）。
const INITIATOR_STATIC: [u8; 32] = [0x11; 32];
/// 响应方静态私钥（测试专用）。
const RESPONDER_STATIC: [u8; 32] = [0x22; 32];
/// 发起方静态公钥（仓外 Python `cryptography` 的 X25519 独立算出）。
const INITIATOR_PUBLIC: [u8; 32] = [
    0x7b, 0x4e, 0x90, 0x9b, 0xbe, 0x7f, 0xfe, 0x44, 0xc4, 0x65, 0xa2, 0x20, 0x03, 0x7d, 0x60, 0x8e,
    0xe3, 0x58, 0x97, 0xd3, 0x1e, 0xf9, 0x72, 0xf0, 0x7f, 0x74, 0x89, 0x2c, 0xb0, 0xf7, 0x3f, 0x13,
];
/// 响应方静态公钥（仓外 Python `cryptography` 的 X25519 独立算出）。
const RESPONDER_PUBLIC: [u8; 32] = [
    0x0f, 0xaa, 0x68, 0x4e, 0xd2, 0x88, 0x67, 0xb9, 0x7f, 0x4a, 0x6a, 0x2d, 0xee, 0x5d, 0xf8, 0xce,
    0x97, 0x4e, 0x76, 0xb7, 0x01, 0x8e, 0x3f, 0x22, 0xa1, 0xc4, 0xcf, 0x26, 0x78, 0x57, 0x0f, 0x20,
];

// ---------------------------------------------------------------- 常用能力集 / 模式集

/// 只有 `keepalive` 的能力集。
const CAPS_KEEPALIVE: CapabilitySet = CapabilitySet::from_bits(Capability::Keepalive.bit());
/// `keepalive` + `renegotiate` 的能力集。
const CAPS_KEEPALIVE_RENEG: CapabilitySet =
    CapabilitySet::from_bits(Capability::Keepalive.bit() | Capability::Renegotiate.bit());
/// `renegotiate` + `stream_both_directions` 的能力集。
const CAPS_RENEG_STREAM: CapabilitySet = CapabilitySet::from_bits(
    Capability::Renegotiate.bit() | Capability::StreamBothDirections.bit(),
);
/// 只有 `ciphertext_only_relay` 的能力集。
const CAPS_CT_ONLY: CapabilitySet = CapabilitySet::from_bits(Capability::CiphertextOnlyRelay.bit());

/// 只有 `p2p` 的模式集。
const MODE_P2P: ModeSet = ModeSet::from_bits(ChannelMode::P2p.bit());
/// 只有 `relay` 的模式集。
const MODE_RELAY: ModeSet = ModeSet::from_bits(ChannelMode::Relay.bit());
/// `p2p` + `relay` 的模式集。
const MODES_BOTH: ModeSet = ModeSet::from_bits(ChannelMode::P2p.bit() | ChannelMode::Relay.bit());

/// 一个**本构建不认识**的能力位（位 63）。用于验证「未知位被忽略并记录」。
const UNKNOWN_CAP_BIT: u64 = 1u64 << 63;

// ---------------------------------------------------------------- 夹具

/// 一次协商的**测试夹具**：持有两侧的会话（密文通道）与协商器。
struct Fixture {
    initiator_session: Session,
    responder_session: Session,
    initiator: Negotiator,
    responder: Negotiator,
}

impl Fixture {
    /// 构造夹具：先完成 L2 握手（拿到密文通道与世代号），再建两侧协商器。
    ///
    /// `caps_a` / `modes_a` 是发起方的，`caps_b` / `modes_b` 是响应方的。
    fn new(
        caps_a: CapabilitySet,
        modes_a: ModeSet,
        caps_b: CapabilitySet,
        modes_b: ModeSet,
    ) -> Self {
        let (initiator_session, responder_session) = established_pair();
        let generation = initiator_session.generation();
        let initiator = Negotiator::new(NegotiatorRole::Initiator, caps_a, modes_a, generation);
        let responder = Negotiator::new(NegotiatorRole::Responder, caps_b, modes_b, generation);
        Self {
            initiator_session,
            responder_session,
            initiator,
            responder,
        }
    }

    /// 走**完整的密文控制帧**通道跑一轮协商，返回**应答载荷**（明文）。
    ///
    /// 协商载荷**必须**封进 `FrameType::Control` 帧（走同一条 AEAD 密文通道），
    /// 这里刻意不提供明文旁路。
    fn negotiate_raw(&mut self, requested: ChannelMode) -> Result<Vec<u8>, NegotiateError> {
        let now = Instant::now();
        // 发起方 → 提案（封进控制帧）
        let proposal = self.initiator.propose(requested, now)?;
        let wire = self
            .initiator_session
            .seal_frame(FrameType::Control, 1, &proposal)?;
        let opened = self.responder_session.open_frame(&wire)?;
        assert_eq!(opened.frame_type, FrameType::Control, "协商必须走控制帧");
        // 顺带验一遍「控制帧入口能解出协商消息」。
        decode_control(opened.frame_type, &opened.plaintext).expect("控制帧可解出协商消息");
        // 响应方 → 应答（封进控制帧）
        let response = self.responder.accept_proposal(&opened.plaintext, now)?;
        let wire = self
            .responder_session
            .seal_frame(FrameType::Control, 1, &response)?;
        let opened = self.initiator_session.open_frame(&wire)?;
        assert_eq!(opened.frame_type, FrameType::Control);
        Ok(opened.plaintext)
    }

    /// 跑完一整轮协商，返回发起方侧的**结果**。
    fn negotiate(&mut self, requested: ChannelMode) -> Result<NegotiationResult, NegotiateError> {
        let response = self.negotiate_raw(requested)?;
        self.initiator.accept_response(&response, Instant::now())
    }
}

/// 构造（发起方, 响应方）一对**已建立**的会话（只为了拿到可用的密文通道与世代号）。
fn established_pair() -> (Session, Session) {
    let initiator_cfg =
        SessionConfig::new(SessionRole::Initiator, INITIATOR_STATIC, RESPONDER_PUBLIC);
    let responder_cfg =
        SessionConfig::new(SessionRole::Responder, RESPONDER_STATIC, INITIATOR_PUBLIC);
    let mut initiator = Session::new(initiator_cfg).expect("发起方会话可构造");
    let mut responder = Session::new(responder_cfg).expect("响应方会话可构造");
    let now = Instant::now();
    let initiation = initiator
        .create_initiation([0xA1; 32], 100, now)
        .expect("initiation 可生成");
    responder
        .consume_initiation(&initiation, now)
        .expect("initiation 可剥壳");
    let response = responder
        .create_response([0xA2; 32], 101, now)
        .expect("response 可生成");
    initiator
        .consume_response(&response, now)
        .expect("response 可消费");
    (initiator, responder)
}

// ---------------------------------------------------------------- §七 1：协商成功

#[test]
fn negotiation_succeeds_and_both_sides_get_the_same_result() {
    let mut fx = Fixture::new(CAPS_KEEPALIVE, MODES_BOTH, CAPS_KEEPALIVE, MODES_BOTH);
    let result = fx.negotiate(ChannelMode::P2p).expect("协商成功");
    let peer = fx.responder.result().expect("响应方也有结果");

    // 双方结果必须**完全一致**。
    assert_eq!(result.channel_mode(), ChannelMode::P2p);
    assert_eq!(result.channel_mode(), peer.channel_mode());
    assert_eq!(result.capabilities(), peer.capabilities());
    assert_eq!(result.raw_capabilities(), peer.raw_capabilities());
    assert_eq!(result.generation(), peer.generation());
    assert_eq!(result.generation(), fx.initiator_session.generation());
    // 状态机：发起方到「已完成」，响应方到「已应答」（本端侧的成功终态）。
    assert_eq!(fx.initiator.state(), NegotiateState::Completed);
    assert_eq!(fx.responder.state(), NegotiateState::Answered);
    assert!(fx.initiator.is_complete() && fx.responder.is_complete());
}

#[test]
fn relay_mode_negotiation_succeeds_when_both_sides_support_relay() {
    let mut fx = Fixture::new(CAPS_CT_ONLY, MODE_RELAY, CAPS_CT_ONLY, MODE_RELAY);
    let result = fx.negotiate(ChannelMode::Relay).expect("relay 协商成功");

    assert_eq!(result.channel_mode(), ChannelMode::Relay);
    assert!(result
        .capabilities()
        .contains(Capability::CiphertextOnlyRelay));
}

#[test]
fn responder_falls_back_to_the_other_mutually_supported_mode() {
    // 发起方想要 p2p，但只有 relay 是**双方都支持**的模式 ⇒ 显式回退到 relay。
    // ⚠️ 这**不是**「协商不上就默认直连」：回退目标必须落在**交集**里，
    // 且交集为空时必须明确报错（见 negotiate_failclosed.rs）。
    let mut fx = Fixture::new(CAPS_KEEPALIVE, MODES_BOTH, CAPS_KEEPALIVE, MODE_RELAY);
    let result = fx
        .negotiate(ChannelMode::P2p)
        .expect("回退到 relay 的协商成功");

    assert_eq!(result.channel_mode(), ChannelMode::Relay);
}

// ---------------------------------------------------------------- §七 2：能力集取交集

#[test]
fn negotiated_capabilities_are_the_intersection_not_the_union() {
    // A 支持 {keepalive, renegotiate}，B 支持 {renegotiate, stream_both_directions}。
    let mut fx = Fixture::new(CAPS_KEEPALIVE_RENEG, MODE_P2P, CAPS_RENEG_STREAM, MODE_P2P);
    let result = fx.negotiate(ChannelMode::P2p).expect("协商成功");

    // 交集 = {renegotiate}：**不是**并集 {keepalive, renegotiate, stream_both_directions}。
    let caps = result.capabilities();
    assert_eq!(
        caps.bits(),
        Capability::Renegotiate.bit(),
        "生效能力集必须是交集"
    );
    assert!(caps.contains(Capability::Renegotiate));
    assert!(!caps.contains(Capability::Keepalive));
    assert!(!caps.contains(Capability::StreamBothDirections));

    // 并集对照证据（证明结果确实不是并集）。
    let union = CAPS_KEEPALIVE_RENEG.union(CAPS_RENEG_STREAM);
    assert_eq!(
        union.bits(),
        CAPS_KEEPALIVE_RENEG.bits() | CAPS_RENEG_STREAM.bits()
    );
    assert_ne!(result.capabilities().bits(), union.bits());
    assert_eq!(
        result.capabilities().bits(),
        CAPS_KEEPALIVE_RENEG.intersection(CAPS_RENEG_STREAM).bits()
    );
}

// ---------------------------------------------------------------- §七 3：未知能力位

#[test]
fn unknown_capability_bit_is_ignored_and_recorded() {
    // 发起方带一个**本构建不认识**的位（位 63）⇒ 响应方必须**忽略**它、
    // **记录**它，但协商**仍然成功**。
    let caps_a = CapabilitySet::from_bits(CAPS_KEEPALIVE.bits() | UNKNOWN_CAP_BIT);
    let mut fx = Fixture::new(caps_a, MODE_P2P, CAPS_KEEPALIVE, MODE_P2P);
    let result = fx
        .negotiate(ChannelMode::P2p)
        .expect("未知位不应让整个协商失败");

    // 未知位**不出现**在结果里。
    assert_eq!(
        result.capabilities().bits() & UNKNOWN_CAP_BIT,
        0,
        "未知能力位不得出现在协商结果里"
    );
    assert_eq!(result.raw_capabilities().bits() & UNKNOWN_CAP_BIT, 0);
    assert!(result.capabilities().contains(Capability::Keepalive));

    // 未知位**被记录**（可观测，但不参与协商结果）。
    let recorded = fx.responder.peer_unknown_capabilities().bits();
    assert_eq!(recorded, UNKNOWN_CAP_BIT, "对端的未知能力位必须被记录下来");
    assert_eq!(fx.initiator.peer_unknown_capabilities().bits(), 0);
}

#[test]
fn unknown_bits_are_masked_out_of_the_negotiated_result() {
    // 双方都带未知位时：**原始交集**含未知位，但**对外的结果**必须掩掉它。
    let caps_a = CapabilitySet::from_bits(CAPS_KEEPALIVE.bits() | UNKNOWN_CAP_BIT);
    let caps_b = CapabilitySet::from_bits(CAPS_KEEPALIVE.bits() | UNKNOWN_CAP_BIT);
    let mut fx = Fixture::new(caps_a, MODE_P2P, caps_b, MODE_P2P);
    let result = fx.negotiate(ChannelMode::P2p).expect("协商成功");

    assert_eq!(
        result.raw_capabilities().bits() & UNKNOWN_CAP_BIT,
        UNKNOWN_CAP_BIT,
        "原始交集保留未知位（供跨版本比对）"
    );
    assert_eq!(
        result.capabilities().bits() & UNKNOWN_CAP_BIT,
        0,
        "对外的结果必须掩掉未知位"
    );
    assert_eq!(result.capabilities().bits(), Capability::Keepalive.bit());
}

// ---------------------------------------------------------------- §七 4：世代号

#[test]
fn matching_generation_passes_and_is_carried_in_the_message() {
    let mut fx = Fixture::new(CAPS_KEEPALIVE, MODE_P2P, CAPS_KEEPALIVE, MODE_P2P);
    let generation = fx.initiator_session.generation();
    let result = fx
        .negotiate(ChannelMode::P2p)
        .expect("世代号一致 ⇒ 协商成功");

    assert_eq!(result.generation(), generation);
    assert_eq!(result.generation_value(), generation.value());
}

#[test]
fn generation_mismatch_is_rejected_with_a_stable_error_code() {
    // 对端世代号**落后**（对端重连过、本端没察觉）⇒ 明确错误，不许继续用旧连接。
    let (initiator_session, responder_session) = established_pair();
    let responder_generation = responder_session.generation().next();
    let mut initiator = Negotiator::new(
        NegotiatorRole::Initiator,
        CAPS_KEEPALIVE,
        MODE_P2P,
        initiator_session.generation(),
    );
    let mut responder = Negotiator::new(
        NegotiatorRole::Responder,
        CAPS_KEEPALIVE,
        MODE_P2P,
        responder_generation,
    );

    let now = Instant::now();
    let proposal = initiator
        .propose(ChannelMode::P2p, now)
        .expect("提案可产出");
    let error = responder
        .accept_proposal(&proposal, now)
        .expect_err("世代号不匹配必须报错");

    assert_eq!(error.error_code(), ErrorCode::GenerationMismatch);
    assert_eq!(error.code(), 0x0005);
    assert_eq!(
        error,
        NegotiateError::GenerationMismatch {
            local: responder_generation.value(),
            remote: initiator_session.generation().value(),
        }
    );
    assert!(responder.result().is_none(), "失败不得留下结果");
    assert_eq!(responder.state(), NegotiateState::Failed);
}

#[test]
fn initiator_rejects_a_response_whose_generation_differs() {
    let mut fx = Fixture::new(CAPS_KEEPALIVE, MODE_P2P, CAPS_KEEPALIVE, MODE_P2P);
    let response = fx.negotiate_raw(ChannelMode::P2p).expect("应答可产出");

    // 伪造一个世代号不同的应答（对端声称自己是另一代）。
    let mut message = NegotiationMessage::decode(&response).expect("应答可解");
    message.generation = message.generation.wrapping_add(1);
    let tampered = message.encode().expect("可编码");

    let error = fx
        .initiator
        .accept_response(&tampered, Instant::now())
        .expect_err("世代号不匹配必须报错");
    assert_eq!(error.error_code(), ErrorCode::GenerationMismatch);
    assert_eq!(error.code(), 0x0005);
    assert!(fx.initiator.result().is_none());
}

// ---------------------------------------------------------------- 消息层自洽

#[test]
fn negotiation_message_roundtrips_byte_exact() {
    let message = NegotiationMessage {
        kind: MessageKind::Proposal,
        channel_mode: ChannelMode::Relay,
        generation: 7,
        local_caps: CAPS_KEEPALIVE_RENEG,
        effective_caps: CapabilitySet::empty(),
        local_modes: MODES_BOTH,
        common_modes: ModeSet::empty(),
        extensions: Vec::new(),
    };
    let bytes = message.encode().expect("可编码");
    let decoded = NegotiationMessage::decode(&bytes).expect("可解码");
    assert_eq!(decoded.kind, MessageKind::Proposal);
    assert_eq!(decoded.channel_mode, ChannelMode::Relay);
    assert_eq!(decoded.generation, 7);
    assert_eq!(decoded.local_caps, message.local_caps);
    assert_eq!(decoded.effective_caps, message.effective_caps);
    assert_eq!(decoded.local_modes, message.local_modes);
    assert_eq!(decoded.common_modes, message.common_modes);
    assert_eq!(decoded.extensions, message.extensions);
    assert_eq!(decoded.encode().expect("可重编码"), bytes);
}

#[test]
fn timeout_is_decided_by_the_caller_supplied_timestamp() {
    let mut initiator = Negotiator::new(
        NegotiatorRole::Initiator,
        CAPS_KEEPALIVE,
        MODE_P2P,
        Generation::INITIAL,
    );
    let start = Instant::now();
    initiator
        .propose(ChannelMode::P2p, start)
        .expect("提案可产出");
    assert!(
        !initiator.is_timed_out(start, Duration::from_secs(5)),
        "刚发起不算超时"
    );
    assert!(
        initiator.is_timed_out(start + Duration::from_secs(6), Duration::from_secs(5)),
        "调用方传入的时间戳超过阈值 ⇒ 判超时"
    );
}
