// 能力集 / 模式集主题：协商不上不许默认直连（任务书 §七 5）。
//
// 本文件由 `tests/negotiate_failclosed.rs` 用 `include!` 文本并入同一模块；
// 共享常量与助手在 `tests/negotiate_failclosed/common.rs`，`use` 全部写在入口文件。

// ---------------------------------------------------------------- §七 5：协商不上不许默认直连

#[test]
fn failed_negotiation_produces_no_default_p2p_result() {
    // 双方**模式集无交集**（一个只有 p2p，一个只有 relay）⇒ 协商失败。
    let mut initiator = make_initiator(CAPS_KEEPALIVE, MODE_P2P, Generation::INITIAL);
    let mut responder = make_responder(CAPS_KEEPALIVE, MODE_RELAY, Generation::INITIAL);

    let now = Instant::now();
    let proposal = initiator
        .propose(ChannelMode::P2p, now)
        .expect("提案可产出（本端支持 p2p）");

    let error = responder
        .accept_proposal(&proposal, now)
        .expect_err("模式集无交集必须失败");

    // 明确错误码。
    assert_eq!(error.error_code(), ErrorCode::NoCommonChannelMode);
    assert_eq!(error.code(), 0x0006);

    // ⛔ **不产生**任何「默认 p2p」结果。
    assert!(responder.result().is_none(), "失败不得留下结果");
    assert_eq!(responder.state(), NegotiateState::Failed);
    assert!(!responder.is_complete());
    assert!(initiator.result().is_none(), "发起方也拿不到结果");
}

#[test]
fn requesting_an_unsupported_mode_is_rejected_locally() {
    // 本端只有 p2p，却请求 relay ⇒ **本地**就拒绝（不发给对端）。
    let mut initiator = make_initiator(CAPS_KEEPALIVE, MODE_P2P, Generation::INITIAL);
    let error = initiator
        .propose(ChannelMode::Relay, Instant::now())
        .expect_err("本端不支持的模式必须被拒");
    assert_eq!(error.error_code(), ErrorCode::ChannelModeNotSupported);
    assert_eq!(error.code(), 0x000C);
    assert!(initiator.result().is_none());
    assert_eq!(initiator.state(), NegotiateState::Failed);
}

#[test]
fn responder_rejects_a_mode_the_initiator_cannot_support() {
    // 构造一个「应答选了 p2p，但发起方不支持 p2p」的场景：
    // 发起方模式集 = {relay}，响应方模式集 = {relay, p2p}。
    // 交集 = {relay} ⇒ 响应方只会选 relay……所以这里直接**伪造**应答，
    // 验证发起方**自己**会拒绝一个自己不支持的选中模式（防御对端算错）。
    let mut initiator = make_initiator(CAPS_KEEPALIVE, MODE_RELAY, Generation::INITIAL);
    let mut responder = make_responder(CAPS_KEEPALIVE, MODES_BOTH, Generation::INITIAL);

    let now = Instant::now();
    let proposal = initiator
        .propose(ChannelMode::Relay, now)
        .expect("提案可产出");
    let response = responder
        .accept_proposal(&proposal, now)
        .expect("应答可产出");

    // 篡改应答里的通道模式 ⇒ 发起方必须拒绝。
    let mut message = NegotiationMessage::decode(&response).expect("应答可解");
    message.channel_mode = ChannelMode::P2p;
    let tampered = message.encode().expect("可编码");

    let error = initiator
        .accept_response(&tampered, now)
        .expect_err("选中模式本端不支持必须被拒");
    assert_eq!(error.error_code(), ErrorCode::ChannelModeNotAccepted);
    assert_eq!(error.code(), 0x0007);
    assert!(initiator.result().is_none());
    assert_eq!(initiator.state(), NegotiateState::Failed);
}

#[test]
fn initiator_rejects_a_response_whose_claimed_common_modes_are_inconsistent() {
    // 对端声称「共同模式 = {p2p, relay}」，但本端只支持 {p2p}
    // ⇒ 对端算错了交集 ⇒ 发起方必须拒绝该结果。
    let mut initiator = make_initiator(CAPS_KEEPALIVE, MODE_P2P, Generation::INITIAL);
    let mut responder = make_responder(CAPS_KEEPALIVE, MODES_BOTH, Generation::INITIAL);

    let now = Instant::now();
    let proposal = initiator
        .propose(ChannelMode::P2p, now)
        .expect("提案可产出");
    let response = responder
        .accept_proposal(&proposal, now)
        .expect("应答可产出");

    let mut message = NegotiationMessage::decode(&response).expect("应答可解");
    message.common_modes = MODES_BOTH;
    let tampered = message.encode().expect("可编码");

    let error = initiator
        .accept_response(&tampered, now)
        .expect_err("声称的共同模式集不自洽必须被拒");
    assert_eq!(error.error_code(), ErrorCode::ChannelModeNotAccepted);
    assert_eq!(error.code(), 0x0007);
    assert!(initiator.result().is_none());
}

#[test]
fn negotiation_never_silently_falls_back_to_p2p_when_p2p_is_unavailable() {
    // 发起方请求 p2p，但只有 relay 是共同可用的 ⇒ 回退到 **relay**（不是 p2p）。
    let mut initiator = make_initiator(CAPS_KEEPALIVE, MODES_BOTH, Generation::INITIAL);
    let mut responder = make_responder(CAPS_KEEPALIVE, MODE_RELAY, Generation::INITIAL);

    let now = Instant::now();
    let proposal = initiator
        .propose(ChannelMode::P2p, now)
        .expect("提案可产出");
    let response = responder
        .accept_proposal(&proposal, now)
        .expect("应答可产出");
    let result = initiator.accept_response(&response, now).expect("协商成功");

    assert_eq!(result.channel_mode(), ChannelMode::Relay);
    assert_ne!(
        result.channel_mode(),
        ChannelMode::P2p,
        "回退目标必须是交集里的模式，绝不是 p2p"
    );
}

#[test]
fn empty_capability_intersection_does_not_fail_the_negotiation() {
    // ⚠️ 能力集（可选特性）交集为空 **不**等于协商失败：
    // 只要**模式**有交集，链路就成立。这条用例锁死「两条轴不混淆」。
    let mut initiator = make_initiator(CAPS_KEEPALIVE, MODE_P2P, Generation::INITIAL);
    let mut responder = make_responder(CAPS_STREAM, MODE_P2P, Generation::INITIAL);

    let now = Instant::now();
    let proposal = initiator
        .propose(ChannelMode::P2p, now)
        .expect("提案可产出");
    let response = responder
        .accept_proposal(&proposal, now)
        .expect("模式有交集 ⇒ 协商成功");
    let result = initiator.accept_response(&response, now).expect("协商成功");

    assert_eq!(result.channel_mode(), ChannelMode::P2p);
    assert!(result.capabilities().is_empty(), "共同特性为空");
    assert!(result.raw_capabilities().is_empty());
}
