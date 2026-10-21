// 世代号主题：首次建立不推进、重连 +1、重建对象接续号段、重连重建 responder
// 及其边界行为（任务书 §七 3 / 4）。
//
// 本文件由 `tests/session_roundtrip.rs` 用 `include!` 文本并入同一模块；
// 共享夹具在 `tests/session_roundtrip/common.rs`，`use` 全部写在入口文件。

// ---------------------------------------------------------------- §七 3：世代号递增

#[test]
fn generation_stays_initial_on_first_handshake_and_increments_on_reconnect() {
    let (mut initiator, mut responder) = session_pair();

    // 首次握手前：世代号 = 初始值（0），且**没有**任何传输上下文。
    assert_eq!(initiator.generation(), Generation::INITIAL);
    assert_eq!(initiator.generation().value(), 0);
    assert_eq!(initiator.state(), SessionState::Unhandshaked);

    let start = Instant::now();
    handshake_round(&mut initiator, &mut responder, 400, 0xA5, start);

    // 第一次握手成功后：状态已建立，世代号仍为初始值（本卡语义：
    // 「首次建立」不推进号段，「重新握手」才 +1）。
    assert_eq!(initiator.state(), SessionState::Established);
    assert_eq!(
        initiator.generation(),
        Generation::INITIAL,
        "首次建立不推进世代号"
    );
    assert_eq!(responder.generation(), Generation::INITIAL);

    // **重连**：同一对会话对象再握一次手 ⇒ 双方世代号 +1。
    let now = advance_round(start);
    handshake_round(&mut initiator, &mut responder, 410, 0xA6, now);
    assert_eq!(
        initiator.generation(),
        Generation::INITIAL.next(),
        "重连后世代号必须 +1"
    );
    assert_eq!(
        responder.generation(),
        Generation::INITIAL.next(),
        "重连后世代号必须 +1"
    );
    assert_eq!(initiator.generation().value(), 1);
    assert_eq!(responder.generation().value(), 1);
}

#[test]
fn generation_increments_across_three_rounds() {
    let (mut initiator, mut responder) = session_pair();
    let mut now = Instant::now();

    for round in 0..3u32 {
        if round > 0 {
            now = advance_round(now);
        }
        let base = 700 + round * 10;
        handshake_round(
            &mut initiator,
            &mut responder,
            base,
            0xB0 + round as u8,
            now,
        );
        assert_eq!(
            initiator.generation().value(),
            u64::from(round),
            "第 {round} 轮后世代号应为 {round}"
        );
        assert_eq!(responder.generation().value(), u64::from(round));
    }
}

#[test]
fn generation_continues_when_session_object_is_recreated() {
    // 调用方在重连时**新建**会话对象 ⇒ 必须用 `with_initial_generation` 接续号段。
    let (mut first_initiator, mut first_responder) = session_pair();
    let start = Instant::now();
    handshake_round(&mut first_initiator, &mut first_responder, 800, 0xC0, start);
    assert_eq!(first_initiator.generation().value(), 0);

    // 重建对象，号段接续到 1。
    let now = advance_round(start);
    let mut second = Session::new(
        SessionConfig::new(SessionRole::Initiator, INITIATOR_STATIC, RESPONDER_PUBLIC)
            .with_initial_generation(Generation::INITIAL.next()),
    )
    .expect("重建后的会话可构造");
    let mut peer = Session::new(SessionConfig::new(
        SessionRole::Responder,
        RESPONDER_STATIC,
        INITIATOR_PUBLIC,
    ))
    .expect("重建后的响应方可构造");
    handshake_round(&mut second, &mut peer, 810, 0xC1, now);
    assert_eq!(
        second.generation().value(),
        1,
        "重建对象后号段必须接续，不退回初始值"
    );
}

// ---------------------------------------------------------------- §七 4：重连重建 responder

#[test]
fn reconnect_rebuilds_responder_from_scratch() {
    // §五第 1 点：`begin_symmetric_session` 消费 responder ⇒ 必须能重建。
    // 同一对密钥**连续握手两次都成功**，且第二次能真正收发。
    let (mut initiator, mut responder) = session_pair();
    let start = Instant::now();

    for round in 0..2u32 {
        let now = if round == 0 {
            start
        } else {
            advance_round(start)
        };
        let base = 600 + round * 10;
        handshake_round(
            &mut initiator,
            &mut responder,
            base,
            0xC0 + round as u8,
            now,
        );
        assert_eq!(initiator.state(), SessionState::Established);
        assert_eq!(responder.state(), SessionState::Established);

        // 每轮都能真正收发（不只是握手不报错）。
        let payload = format!("round-{round}").into_bytes();
        let wire = seal(&mut initiator, u64::from(round), &payload);
        assert_eq!(open(&mut responder, &wire), payload);
    }
}

#[test]
fn reconnect_uses_fresh_index_per_epoch() {
    // 每轮必须用**新** index：index 与 key epoch 一一对应。
    let (mut initiator, mut responder) = session_pair();
    let start = Instant::now();
    handshake_round(&mut initiator, &mut responder, 1000, 0xD0, start);
    assert_eq!(initiator.local_index(), Some(1000));

    let now = advance_round(start);
    handshake_round(&mut initiator, &mut responder, 1010, 0xD1, now);
    assert_eq!(initiator.local_index(), Some(1010));
    assert_eq!(responder.remote_index(), Some(1010));
}

#[test]
fn reconnect_with_preshared_key_succeeds() {
    // PSK 分支也必须能重连（KDF3 参与 ⇒ 每轮重新派生）。
    let mut initiator = Session::new(
        SessionConfig::new(SessionRole::Initiator, INITIATOR_STATIC, RESPONDER_PUBLIC)
            .with_preshared_key([0x44; 32]),
    )
    .expect("发起方会话可构造");
    let mut responder = Session::new(
        SessionConfig::new(SessionRole::Responder, RESPONDER_STATIC, INITIATOR_PUBLIC)
            .with_preshared_key([0x44; 32]),
    )
    .expect("响应方会话可构造");
    let start = Instant::now();

    for round in 0..2u32 {
        let now = if round == 0 {
            start
        } else {
            advance_round(start)
        };
        let base = 900 + round * 10;
        handshake_round(
            &mut initiator,
            &mut responder,
            base,
            0xE0 + round as u8,
            now,
        );
    }
    assert_eq!(initiator.generation().value(), 1);
    assert_eq!(responder.generation().value(), 1);
}

// ---------------------------------------------------------------- 重连的边界行为

#[test]
fn flood_window_rejects_back_to_back_handshakes_without_waiting() {
    // 重建 responder 会重置它内部的洪水记账 ⇒ 会话层必须补上这道检查。
    let (mut initiator, mut responder) = session_pair();
    let start = Instant::now();
    handshake_round(&mut initiator, &mut responder, 1000, 0xF0, start);

    // 紧接着再来一轮（注入的 `Instant` 未推进 ⇒ 落在 20ms 洪水窗口内）⇒ 拒绝。
    let initiation2 = initiator
        .create_initiation([0xF1; 32], 1002, start)
        .expect("第二轮 initiation 可生成");
    let error = responder
        .consume_initiation(&initiation2, start)
        .expect_err("洪水窗口内必须拒绝");
    assert!(matches!(error, SessionError::HandshakeFlood));

    // 发起方放弃这一轮在途握手（对端拒绝后的正常清理路径）。
    assert!(initiator.abort_handshake(), "应当丢弃了一轮在途握手");
    assert_eq!(initiator.state(), SessionState::Established);

    // 等过窗口后放行（重连必须**重新铸造** initiation：旧的那条时间戳不晚于
    // 上一轮，会被重放检查拒绝——这正是参考实现的重放语义）。
    let now = advance_round(start);
    let initiation3 = initiator
        .create_initiation([0xF4; 32], 1004, now)
        .expect("第三轮 initiation 可生成");
    responder
        .consume_initiation(&initiation3, now)
        .expect("窗口外应放行");
}

#[test]
fn replayed_initiation_is_rejected_by_session_layer() {
    // 重建 responder 会重置它内部的重放记账 ⇒ 会话层必须补上这道检查。
    let (mut initiator, mut responder) = session_pair();
    let start = Instant::now();

    let initiation = initiator
        .create_initiation([0xF2; 32], 1100, start)
        .expect("initiation 可生成");
    responder
        .consume_initiation(&initiation, start)
        .expect("initiation 可剥壳");
    responder
        .create_response([0xF3; 32], 1101, start)
        .expect("response 可生成");

    // 原样重放同一条 initiation ⇒ 会话层重放检查必须拒绝。
    let now = advance_round(start);
    let error = responder
        .consume_initiation(&initiation, now)
        .expect_err("重放的 initiation 必须被拒绝");
    assert!(
        matches!(error, SessionError::HandshakeReplay),
        "期望重放错误，实际 {error:?}"
    );
}

#[test]
fn wrong_peer_static_key_is_rejected() {
    // 响应方配了「第三方」公钥 ⇒ 剥壳出的对端静态不匹配 ⇒ 拒绝。
    let mut responder = Session::new(SessionConfig::new(
        SessionRole::Responder,
        RESPONDER_STATIC,
        OTHER_PUBLIC,
    ))
    .expect("响应方会话可构造");
    let (mut initiator, _) = session_pair();
    let now = Instant::now();

    let initiation = initiator
        .create_initiation([0x87; 32], 1100, now)
        .expect("initiation 可生成");
    let error = responder
        .consume_initiation(&initiation, now)
        .expect_err("未知对端必须被拒绝");
    assert!(
        matches!(
            error,
            SessionError::HandshakeUnknownPeer | SessionError::HandshakeMacFailed
        ),
        "期望未知对端/ MAC 失败，实际 {error:?}"
    );
}
