// 错误码主题：码值与标签稳定、载荷超限拒绝（任务书 §七 6 / 7）。
//
// 本文件由 `tests/negotiate_failclosed.rs` 用 `include!` 文本并入同一模块；
// 共享常量与助手在 `tests/negotiate_failclosed/common.rs`，`use` 全部写在入口文件。

// ---------------------------------------------------------------- §七 6：错误码稳定

#[test]
fn error_codes_are_stable_across_repeated_failures() {
    // 同一个失败场景跑 5 次 ⇒ 错误码与错误**完全一致**（逐字节相等）。
    let mut codes = Vec::new();
    let mut errors = Vec::new();

    for _ in 0..5 {
        let mut initiator = make_initiator(CAPS_KEEPALIVE, MODE_P2P, Generation::INITIAL);
        let mut responder = make_responder(CAPS_KEEPALIVE, MODE_RELAY, Generation::INITIAL);
        let now = Instant::now();
        let proposal = initiator
            .propose(ChannelMode::P2p, now)
            .expect("提案可产出");
        let error = responder
            .accept_proposal(&proposal, now)
            .expect_err("模式集无交集必须失败");
        codes.push((
            error.code(),
            error.error_code(),
            error.error_code().as_str(),
        ));
        errors.push(error);
    }

    for entry in &codes {
        assert_eq!(entry.0, 0x0006, "数字码必须稳定");
        assert_eq!(entry.1, ErrorCode::NoCommonChannelMode);
        assert_eq!(entry.2, "NO_COMMON_CHANNEL_MODE", "标签必须稳定");
    }
    assert!(
        errors.windows(2).all(|pair| pair[0] == pair[1]),
        "错误必须完全一致"
    );
}

#[test]
fn every_error_code_has_a_unique_stable_number_and_label() {
    // 码目录自检：数字码唯一、标签唯一。
    let all = [
        ErrorCode::Internal,
        ErrorCode::MalformedMessage,
        ErrorCode::UnsupportedVersion,
        ErrorCode::PayloadTooLarge,
        ErrorCode::GenerationMismatch,
        ErrorCode::NoCommonChannelMode,
        ErrorCode::ChannelModeNotAccepted,
        ErrorCode::ChannelModeNotSupported,
        ErrorCode::InvalidState,
        ErrorCode::RoleMismatch,
        ErrorCode::WrongFrameType,
        ErrorCode::TransportError,
    ];

    let mut numbers: Vec<u16> = all.iter().map(|code| code.code()).collect();
    numbers.sort_unstable();
    let mut deduped = numbers.clone();
    deduped.dedup();
    assert_eq!(deduped.len(), numbers.len(), "数字码必须唯一");

    let mut labels: Vec<&str> = all.iter().map(|code| code.as_str()).collect();
    labels.sort_unstable();
    let mut deduped_labels = labels.clone();
    deduped_labels.dedup();
    assert_eq!(deduped_labels.len(), labels.len(), "标签必须唯一");

    // 逐个锁死码值（这是**跨端契约**，改动即破坏兼容）。
    assert_eq!(ErrorCode::Internal.code(), 0x0001);
    assert_eq!(ErrorCode::MalformedMessage.code(), 0x0002);
    assert_eq!(ErrorCode::UnsupportedVersion.code(), 0x0003);
    assert_eq!(ErrorCode::PayloadTooLarge.code(), 0x0004);
    assert_eq!(ErrorCode::GenerationMismatch.code(), 0x0005);
    assert_eq!(ErrorCode::NoCommonChannelMode.code(), 0x0006);
    assert_eq!(ErrorCode::ChannelModeNotAccepted.code(), 0x0007);
    assert_eq!(ErrorCode::InvalidState.code(), 0x0008);
    assert_eq!(ErrorCode::RoleMismatch.code(), 0x0009);
    assert_eq!(ErrorCode::WrongFrameType.code(), 0x000A);
    assert_eq!(ErrorCode::TransportError.code(), 0x000B);
    assert_eq!(ErrorCode::ChannelModeNotSupported.code(), 0x000C);
}

#[test]
fn generation_mismatch_error_code_is_stable() {
    // 世代号不匹配的错误码与错误内容逐字锁定。
    let mut initiator = make_initiator(CAPS_KEEPALIVE, MODE_P2P, Generation::INITIAL);
    let mut responder = make_responder(CAPS_KEEPALIVE, MODE_P2P, Generation::INITIAL.next());

    let now = Instant::now();
    let proposal = initiator
        .propose(ChannelMode::P2p, now)
        .expect("提案可产出");
    let error = responder
        .accept_proposal(&proposal, now)
        .expect_err("世代号不匹配必须失败");

    assert_eq!(error.code(), 0x0005);
    assert_eq!(error.error_code().as_str(), "GENERATION_MISMATCH");
    assert_eq!(
        error,
        NegotiateError::GenerationMismatch {
            local: 1,
            remote: 0
        }
    );
    assert!(responder.result().is_none());
}

#[test]
fn state_machine_rejects_out_of_order_operations() {
    // 响应方去发起 ⇒ 角色不匹配。
    let mut wrong_role = make_responder(CAPS_KEEPALIVE, MODE_P2P, Generation::INITIAL);
    let error = wrong_role
        .propose(ChannelMode::P2p, Instant::now())
        .expect_err("角色不匹配必须失败");
    assert_eq!(error.code(), 0x0009);

    // 重复发起 ⇒ 状态不允许。
    let mut initiator = make_initiator(CAPS_KEEPALIVE, MODE_P2P, Generation::INITIAL);
    let now = Instant::now();
    initiator
        .propose(ChannelMode::P2p, now)
        .expect("首次发起成功");
    let error = initiator
        .propose(ChannelMode::P2p, now)
        .expect_err("重复发起必须失败");
    assert_eq!(error.code(), 0x0008);

    // 乱序应答（还没发起就应答）⇒ 状态不允许。
    let mut fresh = make_initiator(CAPS_KEEPALIVE, MODE_P2P, Generation::INITIAL);
    let error = fresh
        .accept_response(&plain_proposal(), Instant::now())
        .expect_err("乱序应答必须失败");
    assert_eq!(error.code(), 0x0008);
}

// ---------------------------------------------------------------- §七 7：载荷超限拒绝

#[test]
fn oversized_payload_is_rejected_without_truncation() {
    // 构造一个明文超 `MAX_PLAIN_LEN` 的协商载荷 ⇒ 明确错误，**不截断**。
    let oversized = vec![0xA5u8; MAX_PLAIN_LEN + 1];

    let mut responder = make_responder(CAPS_KEEPALIVE, MODE_P2P, Generation::INITIAL);
    let error = responder
        .accept_proposal(&oversized, Instant::now())
        .expect_err("超限载荷必须被拒");
    assert_eq!(error.error_code(), ErrorCode::MalformedMessage);
    assert_eq!(error.code(), 0x0002);
    assert!(responder.result().is_none());

    // 控制帧入口同样拒绝超限载荷。
    let error =
        decode_control(FrameType::Control, &oversized).expect_err("控制帧入口必须拒绝超限载荷");
    assert_eq!(error.error_code(), ErrorCode::PayloadTooLarge);
    assert_eq!(error.code(), 0x0004);
}

#[test]
fn oversized_extension_block_is_rejected_without_truncation() {
    // 扩展项数据超过 255 字节（TLV 长度字段宽度限制）⇒ 明确错误。
    let message = NegotiationMessage {
        kind: MessageKind::Proposal,
        channel_mode: ChannelMode::P2p,
        generation: 1,
        local_caps: CAPS_KEEPALIVE,
        effective_caps: CapabilitySet::empty(),
        local_modes: MODE_P2P,
        common_modes: ModeSet::empty(),
        extensions: vec![NegotiationExtension::new(0x01, vec![0u8; 256])],
    };
    let error = message.encode().expect_err("超长扩展项必须被拒");
    assert_eq!(error.error_code(), ErrorCode::PayloadTooLarge);
    assert_eq!(error.code(), 0x0004);
}

#[test]
fn malformed_negotiation_payloads_are_rejected() {
    // 太短。
    let error = decode_control(FrameType::Control, &[0u8; 4]).expect_err("太短必须被拒");
    assert_eq!(error.error_code(), ErrorCode::MalformedMessage);

    // 魔数不对 / 保留位非零 ⇒ 格式非法。
    for index in [0usize, 5] {
        let mut bytes = plain_proposal();
        bytes[index] ^= 0xFF;
        let error = decode_control(FrameType::Control, &bytes).expect_err("必须被拒");
        assert_eq!(error.error_code(), ErrorCode::MalformedMessage);
    }

    // 版本不对。
    let mut bytes = plain_proposal();
    bytes[2] = 9;
    let error = decode_control(FrameType::Control, &bytes).expect_err("版本不对必须被拒");
    assert_eq!(error.error_code(), ErrorCode::UnsupportedVersion);
    assert_eq!(error.code(), 0x0003);
}

#[test]
fn negotiation_payload_must_travel_in_a_control_frame() {
    let payload = plain_proposal();

    // 走数据帧 ⇒ 明确拒绝（⛔ 没有明文旁路）。
    let error = decode_control(FrameType::Data, &payload).expect_err("数据帧必须被拒");
    assert_eq!(error.error_code(), ErrorCode::WrongFrameType);
    assert_eq!(error.code(), 0x000A);

    let error = decode_control(FrameType::Keepalive, &payload).expect_err("保活帧必须被拒");
    assert_eq!(error.error_code(), ErrorCode::WrongFrameType);
}

#[test]
fn negotiation_header_is_fixed_length() {
    // 定长头 40 字节：跨端对拍的基础（版本变更时这里要同步改）。
    assert_eq!(NEGOTIATE_HEADER_LEN, 40);
    let payload = plain_proposal();
    assert_eq!(payload.len(), NEGOTIATE_HEADER_LEN);
}
