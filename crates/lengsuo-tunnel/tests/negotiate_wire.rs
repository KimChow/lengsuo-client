//! L4 通道协商：**跨端字节级对拍** + fail-closed + 装配层接线。
//!
//! 对拍两侧：协议真相 `Negotiator`（`lengsuo_link_core::negotiate`）与装配侧
//! `NegotiateDriver`（`lengsuo_tunnel::negotiate`）。断言的是**字节**
//! （`assert_eq!(Vec<u8>, Vec<u8>)`）——⛔ 不用「字段相等」代替。
//!
//! ⚠️ **证据边界**：这是 **Rust 两侧**的字节级一致。移动端仓尚不存在
//! ⇒ 本文件**不**证明「移动端 ↔ PC 端」的互通。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use lengsuo_link_core::frame::FrameType;
use lengsuo_link_core::negotiate::{
    Capability, CapabilitySet, ChannelMode, ErrorCode, ModeSet, NegotiationMessage, Negotiator,
    NegotiatorRole,
};
use lengsuo_link_core::session::Generation;
use lengsuo_tunnel::assembly::{
    Assembly, AssemblyConfig, AssemblyEvent, InitiatorHandshake, ResponderHandshake, Role,
};
use lengsuo_tunnel::negotiate::{NegotiateConfig, NegotiateDriver, NegotiationStep};

// ---------------------------------------------------------------- 测试夹具

/// 本端能力集（测试夹具）。
const CAPS: CapabilitySet = CapabilitySet::empty()
    .with(Capability::Keepalive)
    .with(Capability::CiphertextOnlyRelay);

/// 本端支持的模式集（测试夹具）。
const MODES: ModeSet = ModeSet::empty()
    .with(ChannelMode::P2p)
    .with(ChannelMode::Relay);

/// 只支持 `p2p` 的模式集（测试夹具）。
const P2P_ONLY: ModeSet = ModeSet::empty().with(ChannelMode::P2p);

/// 只支持 `relay` 的模式集（测试夹具）。
const RELAY_ONLY: ModeSet = ModeSet::empty().with(ChannelMode::Relay);

/// 发起方请求的通道模式（测试夹具）。
const REQ_P2P: Option<ChannelMode> = Some(ChannelMode::P2p);

/// 本轮连接的世代号（测试夹具）：取 **1**（而非初始值 0），「忘了带世代号」会立刻暴露。
const GENERATION: Generation = Generation::INITIAL.next();

/// 造一个协议真相侧的协商器。
fn truth(role: NegotiatorRole, modes: ModeSet, generation: Generation) -> Negotiator {
    Negotiator::new(role, CAPS, modes, generation)
}

/// 造一个装配侧的协商驱动器。
fn drv(
    role: NegotiatorRole,
    modes: ModeSet,
    requested: Option<ChannelMode>,
    generation: Generation,
) -> NegotiateDriver {
    NegotiateDriver::new(role, requested, CAPS, modes, generation)
}

// ------------------------------------------- 字节级对拍（协议侧 vs 装配侧）

#[test]
fn driver_proposal_bytes_match_link_core_negotiator() {
    let now = Instant::now();
    let mut t = truth(NegotiatorRole::Initiator, MODES, GENERATION);
    let mut d = drv(NegotiatorRole::Initiator, MODES, REQ_P2P, GENERATION);

    let from_truth = t.propose(ChannelMode::P2p, now).expect("提案");
    let from_driver = d.propose(now).expect("提案");

    assert_eq!(from_truth, from_driver, "提案载荷必须逐字节相同");
}

#[test]
fn driver_response_bytes_match_link_core_negotiator() {
    let now = Instant::now();
    let mut t = truth(NegotiatorRole::Initiator, MODES, GENERATION);
    let proposal = t.propose(ChannelMode::P2p, now).expect("提案");
    let mut tr = truth(NegotiatorRole::Responder, MODES, GENERATION);
    let mut d = drv(NegotiatorRole::Responder, MODES, None, GENERATION);

    let from_truth = tr.accept_proposal(&proposal, now).expect("应答");
    let from_driver = d.accept_proposal(&proposal, now).expect("应答");

    assert_eq!(from_truth, from_driver, "应答载荷必须逐字节相同");
}

#[test]
fn driver_result_matches_link_core_negotiator() {
    let now = Instant::now();
    let mut t = truth(NegotiatorRole::Initiator, MODES, GENERATION);
    let proposal = t.propose(ChannelMode::P2p, now).expect("提案");
    let mut tr = truth(NegotiatorRole::Responder, MODES, GENERATION);
    let response = tr.accept_proposal(&proposal, now).expect("应答");

    let mut d = drv(NegotiatorRole::Initiator, MODES, REQ_P2P, GENERATION);
    d.propose(now).expect("提案");
    let result = d.accept_response(&response, now).expect("接受应答");

    assert_eq!(result, t.accept_response(&response, now).expect("接受应答"));
    assert_eq!(result.channel_mode(), ChannelMode::P2p);
    assert_eq!(result.generation_value(), GENERATION.value());
    assert_eq!(result.capabilities(), CAPS.intersection(CAPS), "交集");
}

#[test]
fn driver_and_link_core_negotiator_interoperate_bytewise() {
    let now = Instant::now();

    // 装配侧的提案 ⇒ 协议侧能解。
    let mut d = drv(NegotiatorRole::Initiator, MODES, REQ_P2P, GENERATION);
    let d_proposal = d.propose(now).expect("提案");
    let mut tr = truth(NegotiatorRole::Responder, MODES, GENERATION);
    let truth_response = tr.accept_proposal(&d_proposal, now).expect("接受提案");

    // 协议侧的提案 ⇒ 装配侧能解。
    let mut t = truth(NegotiatorRole::Initiator, MODES, GENERATION);
    let t_proposal = t.propose(ChannelMode::P2p, now).expect("提案");
    let mut dr = drv(NegotiatorRole::Responder, MODES, None, GENERATION);
    let d_response = dr.accept_proposal(&t_proposal, now).expect("接受提案");

    assert_eq!(truth_response, d_response, "两侧应答载荷必须逐字节相同");
}

#[test]
fn control_frame_payload_round_trips_through_driver() {
    let now = Instant::now();
    let mut initiator = drv(NegotiatorRole::Initiator, MODES, REQ_P2P, GENERATION);
    let mut responder = drv(NegotiatorRole::Responder, MODES, None, GENERATION);

    let proposal = initiator.propose(now).expect("提案");
    let step = responder
        .consume_frame(FrameType::Control, &proposal, now)
        .expect("控制帧提案");
    let NegotiationStep::Response(response) = step else {
        panic!("响应方必须产出应答");
    };

    let step = initiator
        .consume_frame(FrameType::Control, &response, now)
        .expect("控制帧应答");
    let NegotiationStep::Completed(result) = step else {
        panic!("发起方必须拿到结果");
    };
    assert_eq!(result.channel_mode(), ChannelMode::P2p);
}

// ---------------------------------------------------------------- fail-closed

#[test]
fn negotiation_over_data_frame_is_rejected() {
    let now = Instant::now();
    let mut d = drv(NegotiatorRole::Initiator, MODES, REQ_P2P, GENERATION);
    let proposal = d.propose(now).expect("提案");

    let error = d
        .consume_frame(FrameType::Data, &proposal, now)
        .expect_err("数据帧必须被拒绝");

    assert_eq!(error.error_code(), ErrorCode::WrongFrameType);
    assert!(d.result().is_none(), "被拒绝后不得产生协商结果");
}

#[test]
fn no_common_channel_mode_is_rejected_without_p2p_fallback() {
    let now = Instant::now();
    let mut t = truth(NegotiatorRole::Initiator, P2P_ONLY, GENERATION);
    let proposal = t.propose(ChannelMode::P2p, now).expect("提案");

    let mut d = drv(NegotiatorRole::Responder, RELAY_ONLY, None, GENERATION);
    let error = d.accept_proposal(&proposal, now).expect_err("无共同模式");

    assert_eq!(error.error_code(), ErrorCode::NoCommonChannelMode);
    assert!(d.result().is_none(), "失败后不得有结果（⛔ 不回退 p2p）");
}

#[test]
fn generation_mismatch_is_rejected() {
    let now = Instant::now();
    let mut t = truth(NegotiatorRole::Initiator, MODES, GENERATION);
    let proposal = t.propose(ChannelMode::P2p, now).expect("提案");

    // 对端带着**另一代**的连接来协商。
    let mut d = drv(NegotiatorRole::Responder, MODES, None, GENERATION.next());
    let error = d.accept_proposal(&proposal, now).expect_err("世代号不匹配");

    assert_eq!(error.error_code(), ErrorCode::GenerationMismatch);
    assert!(d.result().is_none(), "失败后不得继续用旧连接");
}

#[test]
fn second_propose_is_rejected() {
    let now = Instant::now();
    let mut d = drv(NegotiatorRole::Initiator, MODES, REQ_P2P, GENERATION);
    d.propose(now).expect("提案");

    let error = d.propose(now).expect_err("重复发起");

    assert_eq!(error.error_code(), ErrorCode::InvalidState);
}

#[test]
fn responder_propose_is_rejected() {
    let now = Instant::now();
    let mut d = drv(NegotiatorRole::Responder, MODES, None, GENERATION);

    let error = d.propose(now).expect_err("响应方发起");

    assert_eq!(error.error_code(), ErrorCode::RoleMismatch);
}

#[test]
fn peer_selected_unsupported_mode_is_rejected() {
    let now = Instant::now();
    // 伪造一份应答：选中 `relay`，而本端只支持 `p2p`。
    let forged = NegotiationMessage::response(
        ChannelMode::Relay,
        GENERATION.value(),
        CAPS,
        CapabilitySet::empty(),
        MODES,
        RELAY_ONLY,
    )
    .encode()
    .expect("编码");

    let mut d = drv(NegotiatorRole::Initiator, P2P_ONLY, REQ_P2P, GENERATION);
    // 先进入 `Proposing` 态（否则状态检查会先于模式检查触发）。
    d.propose(now).expect("提案");
    let error = d.accept_response(&forged, now).expect_err("模式不支持");

    assert_eq!(error.error_code(), ErrorCode::ChannelModeNotAccepted);
}

#[test]
fn peer_claimed_common_modes_outside_local_modes_is_rejected() {
    let now = Instant::now();
    // 伪造：选中 `p2p`（本端支持），但声称的共同模式集里含本端**不支持**的 `relay`。
    let forged = NegotiationMessage::response(
        ChannelMode::P2p,
        GENERATION.value(),
        CAPS,
        CapabilitySet::empty(),
        MODES,
        MODES,
    )
    .encode()
    .expect("编码");

    let mut d = drv(NegotiatorRole::Initiator, P2P_ONLY, REQ_P2P, GENERATION);
    d.propose(now).expect("提案");
    let error = d.accept_response(&forged, now).expect_err("共同模式集越界");

    assert_eq!(error.error_code(), ErrorCode::ChannelModeNotAccepted);
}

#[test]
fn is_timed_out_uses_caller_supplied_threshold() {
    let start = Instant::now();
    let mut d = drv(NegotiatorRole::Initiator, MODES, REQ_P2P, GENERATION);
    d.propose(start).expect("提案");

    assert!(!d.is_timed_out(start + Duration::from_secs(1), Duration::from_secs(5)));
    assert!(d.is_timed_out(start + Duration::from_secs(6), Duration::from_secs(5)));
}

// ---------------------------------------------------------------- 装配层接线

#[test]
fn assembly_routes_control_frame_to_negotiator() {
    let now = Instant::now();
    let (mut initiator, mut responder) = handshaked_assemblies();

    // 发起方产出提案 → 封进**控制帧** → 交给响应方。
    let proposal = initiator
        .negotiator_mut()
        .expect("已配置协商")
        .propose(now)
        .expect("提案");
    let frame = initiator
        .seal_frame(FrameType::Control, 0, &proposal)
        .expect("封控制帧");

    let event = responder
        .receive_frame(peer_addr(), frame)
        .expect("收控制帧");
    let AssemblyEvent::Negotiated(NegotiationStep::Response(response)) = event else {
        panic!("控制帧必须路由到协商驱动器（⛔ 不得当数据交付）：{event:?}");
    };

    // 响应方产出应答 → 封进控制帧 → 交给发起方。
    let frame = responder
        .seal_frame(FrameType::Control, 1, &response)
        .expect("封控制帧");
    let event = initiator
        .receive_frame(peer_addr(), frame)
        .expect("收控制帧");
    let AssemblyEvent::Negotiated(NegotiationStep::Completed(result)) = event else {
        panic!("控制帧必须路由到协商驱动器：{event:?}");
    };
    assert_eq!(result.channel_mode(), ChannelMode::P2p);
}

// ---------------------------------------------------------------- 装配层夹具

/// 假凭据（**仅测试用**，不是任何真实密钥）。
const INITIATOR_SECRET: [u8; 32] = [0x11; 32];
/// 假凭据（**仅测试用**）。
const RESPONDER_SECRET: [u8; 32] = [0x22; 32];
/// 发起方静态公钥（由 `INITIATOR_SECRET` 派生）。
const INITIATOR_PUBLIC: [u8; 32] = [
    0x7b, 0x4e, 0x90, 0x9b, 0xbe, 0x7f, 0xfe, 0x44, 0xc4, 0x65, 0xa2, 0x20, 0x03, 0x7d, 0x60, 0x8e,
    0xe3, 0x58, 0x97, 0xd3, 0x1e, 0xf9, 0x72, 0xf0, 0x7f, 0x74, 0x89, 0x2c, 0xb0, 0xf7, 0x3f, 0x13,
];
/// 响应方静态公钥（由 `RESPONDER_SECRET` 派生）。
const RESPONDER_PUBLIC: [u8; 32] = [
    0x0f, 0xaa, 0x68, 0x4e, 0xd2, 0x88, 0x67, 0xb9, 0x7f, 0x4a, 0x6a, 0x2d, 0xee, 0x5d, 0xf8, 0xce,
    0x97, 0x4e, 0x76, 0xb7, 0x01, 0x8e, 0x3f, 0x22, 0xa1, 0xc4, 0xcf, 0x26, 0x78, 0x57, 0x0f, 0x20,
];
/// 本轮临时密钥种子（确定性 ⇒ 可复现）。
const SEED: [u8; 32] = [0xAA; 32];
/// 响应方临时密钥种子。
const RESPONDER_SEED: [u8; 32] = [0xBB; 32];
/// 响应方本轮 index。
const RESPONDER_INDEX: u32 = 0x2026_1234;

/// 对端地址（**假地址**，仅用于漫游判定）。
fn peer_addr() -> SocketAddr {
    "127.0.0.1:9999".parse().expect("回环地址")
}

/// 发起方装配层配置（**带协商**）。
fn initiator_config() -> AssemblyConfig {
    let cfg = AssemblyConfig::new(Role::Initiator, INITIATOR_SECRET, RESPONDER_PUBLIC);
    cfg.with_negotiate(NegotiateConfig::new(
        NegotiatorRole::Initiator,
        CAPS,
        MODES,
        REQ_P2P,
    ))
}

/// 响应方装配层配置（**带协商**）。
fn responder_config() -> AssemblyConfig {
    let cfg = AssemblyConfig::new(Role::Responder, RESPONDER_SECRET, INITIATOR_PUBLIC);
    cfg.with_negotiate(NegotiateConfig::new(
        NegotiatorRole::Responder,
        CAPS,
        MODES,
        None,
    ))
}

/// 跑完一整轮握手（**在内存里**，不走 socket），把两端的会话密钥都落地。
fn handshaked_assemblies() -> (Assembly, Assembly) {
    let mut initiator = Assembly::new(initiator_config()).expect("建发起方");
    let mut responder = Assembly::new(responder_config()).expect("建响应方");

    let mut ih = InitiatorHandshake::new(&initiator, SEED).expect("建握手");
    let initiation = ih.create_initiation(SEED).expect("构造 initiation");

    let mut rh = ResponderHandshake::new(&responder).expect("建握手");
    rh.consume_initiation(&initiation).expect("接受 initiation");
    let (response, rkeys) = rh
        .create_response(RESPONDER_SEED, RESPONDER_INDEX)
        .expect("构造 response");
    responder.install_keys(&rkeys).expect("落地密钥");

    let ikeys = ih.consume_response(&response).expect("通过认证");
    initiator.install_keys(&ikeys).expect("落地密钥");

    (initiator, responder)
}
