// 共享常量与协商器构造助手。
//
// 本文件由 `tests/negotiate_failclosed.rs` 用 `include!` 文本并入同一模块；
// `use` 全部写在入口文件。

// ---------------------------------------------------------------- 常用能力集 / 模式集

/// 只有 `keepalive` 的能力集。
const CAPS_KEEPALIVE: CapabilitySet = CapabilitySet::from_bits(Capability::Keepalive.bit());
/// 只有 `stream_both_directions` 的能力集。
const CAPS_STREAM: CapabilitySet = CapabilitySet::from_bits(Capability::StreamBothDirections.bit());

/// 只有 `p2p` 的模式集。
const MODE_P2P: ModeSet = ModeSet::from_bits(ChannelMode::P2p.bit());
/// 只有 `relay` 的模式集。
const MODE_RELAY: ModeSet = ModeSet::from_bits(ChannelMode::Relay.bit());
/// `p2p` + `relay` 的模式集。
const MODES_BOTH: ModeSet = ModeSet::from_bits(ChannelMode::P2p.bit() | ChannelMode::Relay.bit());

// ---------------------------------------------------------------- 辅助

/// 构造一个发起方协商器。
fn make_initiator(caps: CapabilitySet, modes: ModeSet, generation: Generation) -> Negotiator {
    Negotiator::new(NegotiatorRole::Initiator, caps, modes, generation)
}

/// 构造一个响应方协商器。
fn make_responder(caps: CapabilitySet, modes: ModeSet, generation: Generation) -> Negotiator {
    Negotiator::new(NegotiatorRole::Responder, caps, modes, generation)
}

/// 一条普通的提案消息（用于篡改类用例）。
fn plain_proposal() -> Vec<u8> {
    NegotiationMessage::proposal(ChannelMode::P2p, 1, CAPS_KEEPALIVE, MODE_P2P)
        .encode()
        .expect("可编码")
}
