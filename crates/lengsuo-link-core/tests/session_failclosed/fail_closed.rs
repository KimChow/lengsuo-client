// 失败闭锁主题：认证失败 ⇒ 失效、失效后拒绝收发（任务书 §七 6 / 7）。
//
// 本文件由 `tests/session_failclosed.rs` 用 `include!` 文本并入同一模块；
// 共享夹具在 `tests/session_failclosed/common.rs`，`use` 全部写在入口文件。

// ---------------------------------------------------------------- §七 6：认证失败 ⇒ 失效

#[test]
fn auth_failure_marks_session_invalidated_and_never_falls_back_to_plaintext() {
    let (mut initiator, mut responder) = established_pair();

    let plaintext = b"top secret payload".to_vec();
    let wire = seal(&mut initiator, 1, &plaintext);

    // 篡改密文 ⇒ AEAD 认证失败。
    let corrupted = corrupt(&wire);

    let error = responder
        .open_frame(&corrupted)
        .expect_err("篡改帧必须被拒绝");
    assert!(
        matches!(error, SessionError::AuthFailed),
        "期望 AuthFailed，实际 {error:?}"
    );
    assert!(error.is_fatal(), "认证失败必须是 fatal（上层据此丢弃会话）");

    // **不回退明文**：错误里不得含明文内容。
    let rendered = error.to_string();
    assert!(
        !rendered.contains("top secret"),
        "错误文本不得含明文：{rendered}"
    );

    // 会话被标记为**已失效**。
    assert!(responder.is_invalidated(), "认证失败后必须失效");
    assert_eq!(responder.state(), SessionState::Invalidated);
}

#[test]
fn wrong_key_decryption_fails_closed() {
    // 建**两条独立链路**（静态私钥不同 ⇒ 传输密钥不同）。
    let (mut initiator, _responder) = established_pair();
    let wire = seal(&mut initiator, 7, b"payload");

    let mut other_initiator = Session::new(SessionConfig::new(
        SessionRole::Initiator,
        OTHER_INITIATOR_STATIC,
        RESPONDER_PUBLIC,
    ))
    .expect("另一条链路的发起方可构造");
    let mut other_responder = Session::new(SessionConfig::new(
        SessionRole::Responder,
        RESPONDER_STATIC,
        OTHER_INITIATOR_PUBLIC,
    ))
    .expect("另一条链路的响应方可构造");
    let now = Instant::now();
    let initiation = other_initiator
        .create_initiation([0xC3; 32], 20, now)
        .expect("另一条链路的 initiation 可生成");
    other_responder
        .consume_initiation(&initiation, now)
        .expect("另一条链路的 initiation 可剥壳");
    let response = other_responder
        // **用同一个本端 index**（11）：否则接收者标识检查会先于 AEAD 命中，
        // 测的就不是「错密钥」而是「错 index」。两条链路是独立会话，index 可重复。
        .create_response([0xD4; 32], 11, now)
        .expect("另一条链路的 response 可生成");
    other_initiator
        .consume_response(&response, now)
        .expect("另一条链路的 response 可消费");

    // 用**别的链路**的接收方去解 ⇒ 密钥对不上 ⇒ 认证失败。
    let error = other_responder
        .open_frame(&wire)
        .expect_err("错密钥必须解不开");
    assert!(matches!(error, SessionError::AuthFailed), "{error:?}");
    assert!(other_responder.is_invalidated());
}

#[test]
fn truncated_frame_is_rejected_without_partial_data() {
    let (mut initiator, mut responder) = established_pair();
    let wire = seal(&mut initiator, 1, b"0123456789");

    // 截断一字节 ⇒ 帧层拒绝（不返回部分数据）。
    let error = responder
        .open_frame(&wire[..wire.len() - 1])
        .expect_err("截断帧必须被拒绝");
    assert!(matches!(error, SessionError::Frame(_)), "实际 {error:?}");
    // 帧层错误**不是** fatal ⇒ 会话仍有效（这一帧只是没解出来）。
    assert!(!error.is_fatal());
    assert!(!responder.is_invalidated(), "帧层错误不应让会话失效");
}

#[test]
fn tampered_frame_header_is_rejected() {
    let (mut initiator, mut responder) = established_pair();
    let mut wire = seal(&mut initiator, 1, b"payload");

    // 改帧头里的魔数 ⇒ 帧头 CRC/魔数检查失败。
    wire[0] ^= 0xFF;
    let error = responder.open_frame(&wire).expect_err("坏帧头必须被拒绝");
    assert!(
        matches!(error, SessionError::Frame(_)),
        "期望帧层错误，实际 {error:?}"
    );
}

// ---------------------------------------------------------------- §七 7：失效后拒绝收发

#[test]
fn invalidated_session_refuses_to_seal_and_open() {
    let (mut initiator, mut responder) = established_pair();

    // 先把响应方打成失效态。
    let corrupted = corrupt(&seal(&mut initiator, 1, b"payload"));
    assert!(responder.open_frame(&corrupted).is_err());
    assert!(responder.is_invalidated());

    // 失效后再封 ⇒ 明确错误，**不静默成功**。
    let error = responder
        .seal_frame(FrameType::Data, 2, b"more")
        .expect_err("失效会话不得继续封帧");
    assert!(matches!(error, SessionError::Invalidated), "{error:?}");

    // 失效后再解 ⇒ 明确错误。
    let error = responder
        .open_frame(&corrupted)
        .expect_err("失效会话不得继续解帧");
    assert!(matches!(error, SessionError::Invalidated), "{error:?}");
}

#[test]
fn explicitly_invalidated_session_refuses_traffic() {
    let (mut initiator, mut responder) = established_pair();
    responder.invalidate();
    assert!(responder.is_invalidated());
    assert_eq!(responder.state(), SessionState::Invalidated);

    let error = responder
        .seal_frame(FrameType::Data, 1, b"x")
        .expect_err("失效会话不得封帧");
    assert!(matches!(error, SessionError::Invalidated), "{error:?}");

    let wire = initiator
        .seal_frame(FrameType::Data, 1, b"x")
        .expect("封帧成功");
    let error = responder.open_frame(&wire).expect_err("失效会话不得解帧");
    assert!(matches!(error, SessionError::Invalidated));
}

#[test]
fn unsealed_session_has_no_transport_and_refuses_traffic() {
    // 未握手 ⇒ 没有传输上下文 ⇒ 收发都必须被明确拒绝。
    let mut initiator = Session::new(SessionConfig::new(
        SessionRole::Initiator,
        INITIATOR_STATIC,
        RESPONDER_PUBLIC,
    ))
    .expect("发起方会话可构造");
    assert_eq!(initiator.state(), SessionState::Unhandshaked);

    let error = initiator
        .seal_frame(FrameType::Data, 1, b"x")
        .expect_err("未握手不得封帧");
    assert!(
        matches!(error, SessionError::InvalidState { .. }),
        "{error:?}"
    );

    let error = initiator
        .open_frame(&[0u8; 20])
        .expect_err("未握手不得解帧");
    assert!(
        matches!(error, SessionError::InvalidState { .. }),
        "{error:?}"
    );
}

#[test]
fn oversized_plaintext_is_rejected_before_any_counter_advance() {
    // 明文超长 ⇒ 写入前拒绝，**不消耗发送侧计数器**（后续合法帧仍用计数器 0）。
    let (mut initiator, mut responder) = established_pair();
    let too_long = vec![0x41u8; lengsuo_link_core::frame::MAX_PLAIN_LEN + 1];
    let error = initiator
        .seal_frame(FrameType::Data, 1, &too_long)
        .expect_err("超长明文必须被拒绝");
    assert!(matches!(error, SessionError::Frame(_)), "实际 {error:?}");

    // 计数器没被消耗：下一帧仍是计数器 0，能被对端正常解开。
    // 传输包的计数器在**帧载荷**里的偏移 8..16 ⇒ 整帧偏移 = 帧头 20 + 8。
    let wire = seal(&mut initiator, 2, b"ok");
    let counter_at = FRAME_HEADER_LEN + 8;
    assert_eq!(
        &wire[counter_at..counter_at + 8],
        &0u64.to_le_bytes(),
        "计数器必须是 0"
    );
    let opened = responder.open_frame(&wire).expect("解帧成功");
    assert_eq!(opened.plaintext, b"ok");
}

#[test]
fn replayed_frame_is_dropped_but_session_stays_usable() {
    // 重放窗口拒绝 ⇒ **丢包**，会话**仍有效**（不是密钥失同步）。
    let (mut initiator, mut responder) = established_pair();
    let wire = seal(&mut initiator, 1, b"once");
    responder.open_frame(&wire).expect("首次解帧成功");

    let error = responder.open_frame(&wire).expect_err("重放必须被拒绝");
    assert!(matches!(error, SessionError::ReplayRejected), "{error:?}");
    assert!(!error.is_fatal(), "重放不是 fatal");
    assert!(!responder.is_invalidated(), "重放不应让会话失效");

    // 会话仍可继续收发。
    let opened = responder
        .open_frame(&seal(&mut initiator, 2, b"twice"))
        .expect("解帧成功");
    assert_eq!(opened.plaintext, b"twice");
}
