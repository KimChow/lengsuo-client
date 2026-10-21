// 往返主题：握手成功、封解帧逐字节一致、角色固定（任务书 §七 1 / 2 / 5）。
//
// 本文件由 `tests/session_roundtrip.rs` 用 `include!` 文本并入同一模块；
// 共享夹具在 `tests/session_roundtrip/common.rs`，`use` 全部写在入口文件。

// ---------------------------------------------------------------- §七 1：握手成功

#[test]
fn handshake_succeeds_and_both_sides_reach_established() {
    let (mut initiator, mut responder) = session_pair();
    handshake_round(&mut initiator, &mut responder, 100, 0xA1, Instant::now());

    assert_eq!(initiator.state(), SessionState::Established);
    assert_eq!(responder.state(), SessionState::Established);
    assert!(initiator.is_established() && responder.is_established());
    assert!(!initiator.is_invalidated() && !responder.is_invalidated());

    // 双方看到的对端 index 必须一致（跨端一致性的最小断言）。
    assert_eq!(initiator.local_index(), Some(100));
    assert_eq!(initiator.remote_index(), Some(101));
    assert_eq!(responder.local_index(), Some(101));
    assert_eq!(responder.remote_index(), Some(100));
}

// ---------------------------------------------------------------- §七 2：收发往返

#[test]
fn sealed_frame_roundtrips_byte_exact() {
    let (mut initiator, mut responder) = session_pair();
    handshake_round(&mut initiator, &mut responder, 200, 0xA2, Instant::now());

    let plaintext = b"\x00\x01\x02ACP frame payload\xff\xfe".to_vec();
    let opened = responder
        .open_frame(&seal(&mut initiator, 42, &plaintext))
        .expect("解帧成功");
    assert_eq!(opened.plaintext, plaintext, "明文必须逐字节相同");
    assert_eq!(opened.frame_type, FrameType::Data);
    assert_eq!(opened.seq, 42);

    // 反向也通：角色不对称不代表方向不对称。
    let reply = b"pong".to_vec();
    let opened = initiator
        .open_frame(&seal(&mut responder, 43, &reply))
        .expect("解帧成功");
    assert_eq!(opened.plaintext, reply);
    assert_eq!(opened.seq, 43);
}

#[test]
fn multiple_frames_flow_in_both_directions() {
    let (mut initiator, mut responder) = session_pair();
    handshake_round(&mut initiator, &mut responder, 300, 0xA3, Instant::now());

    for round in 0..8u64 {
        let payload = vec![round as u8; (round as usize) * 17 + 1];
        let wire = seal(&mut initiator, round, &payload);
        let opened = responder.open_frame(&wire).expect("解帧成功");
        assert_eq!(opened.plaintext, payload, "第 {round} 轮明文必须逐字节相同");
        assert_eq!(opened.seq, round);
    }
}

#[test]
fn empty_payload_keepalive_roundtrips() {
    let (mut initiator, mut responder) = session_pair();
    handshake_round(&mut initiator, &mut responder, 350, 0xA4, Instant::now());

    let wire = initiator
        .seal_frame(FrameType::Keepalive, 0, &[])
        .expect("零长载荷封帧成功");
    let opened = responder.open_frame(&wire).expect("解帧成功");
    assert!(opened.plaintext.is_empty());
    assert_eq!(opened.frame_type, FrameType::Keepalive);
}

// ---------------------------------------------------------------- §七 5：角色固定

#[test]
fn role_is_explicitly_visible_on_the_session() {
    let (mut initiator, mut responder) = session_pair();

    assert_eq!(initiator.role(), SessionRole::Initiator);
    assert!(initiator.role().is_initiator() && !initiator.role().is_responder());
    assert_eq!(responder.role(), SessionRole::Responder);
    assert!(responder.role().is_responder() && !responder.role().is_initiator());

    // 角色固定：发起方会话不能走响应方路径，反之亦然。
    let error = initiator
        .consume_initiation(&[0u8; 148], Instant::now())
        .expect_err("发起方不能消费 initiation");
    assert!(matches!(error, SessionError::RoleMismatch { .. }));

    let error = responder
        .create_initiation([0x01; 32], 1, Instant::now())
        .expect_err("响应方不能产出 initiation");
    assert!(matches!(error, SessionError::RoleMismatch { .. }));
}
