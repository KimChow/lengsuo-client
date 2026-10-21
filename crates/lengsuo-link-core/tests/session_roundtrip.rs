//! L2 会话往返用例：握手 → 收发 → 世代号递增 → 重连重建 responder。
//!
//! 覆盖任务书 §七 的 1–5 条：
//! 1. 握手成功：双方在同一进程内完成一次握手，得到一致的会话状态。
//! 2. 收发往返：封一帧明文 ⇒ 对方解回**逐字节相同**的明文。
//! 3. 世代号递增：第一次握手 ⇒ 世代号 = 初始值；重连（第二次握手）⇒ 世代号 +1。
//! 4. 重连可重建 responder：同一对密钥**连续握手两次都成功**。
//! 5. 角色固定：发起方与响应方的角色在会话对象上显式可见。
//!
//! 全部是**测试专用假密钥**（0x11 / 0x22 模式字节），不代表任何真实凭据。
//! 对端公钥用**仓外独立实现**（Python `cryptography` 的 X25519）算出后写死
//! 在本文件里——不依赖本仓的 X25519 代码自证。
//!
//! ⚠️ 本文件**不**证明与任何真实 WireGuard 端互通：只证明本卡会话状态机的
//! 握手编排、密钥落地、世代号与重连语义自洽。

use std::time::{Duration, Instant};

use lengsuo_link_core::frame::FrameType;
use lengsuo_link_core::session::{
    Generation, Session, SessionConfig, SessionError, SessionRole, SessionState,
};

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
/// 第三方静态公钥（仓外 Python `cryptography` 的 X25519 独立算出）。
const OTHER_PUBLIC: [u8; 32] = [
    0x7b, 0x0d, 0x47, 0xd9, 0x34, 0x27, 0xf8, 0x31, 0x11, 0x60, 0x78, 0x1c, 0x7c, 0x73, 0x3f, 0xd8,
    0x9f, 0x88, 0x97, 0x0a, 0xef, 0x49, 0x0d, 0x8a, 0xa0, 0xee, 0x19, 0xa4, 0xcb, 0x8a, 0x1b, 0x14,
];

/// 两轮握手之间的最小时间间隔（须大于会话层的洪水窗口 20ms）。
const ROUND_GAP: Duration = Duration::from_millis(50);

/// 推进到「下一轮」可用的时刻。
///
/// ⚠️ 为什么必须等：`lengsuo-wireguard` 的握手时间戳来自 `tai64n_now()`
/// （**系统时钟**），纳秒部分被掩到 ~16.78ms 粒度（`subsec_nanos & !0x00ff_ffff`）。
/// 参考实现的重放检查要求「时间戳严格晚于上一次」，所以**两轮握手必须跨过一个
/// TAI64N 刻度**，否则第二轮会被判重放（与参考实现行为一致，不是本卡的缺陷）。
/// 同时还要跨过会话层的**洪水窗口**（20ms，注入的是单调 `Instant`）——两个窗口
/// 是**独立的时钟源**（墙钟 vs 单调钟），必须**都**满足。
fn advance_round(previous: Instant) -> Instant {
    let before = lengsuo_wireguard::handshake::tai64n_now();
    loop {
        std::thread::sleep(Duration::from_millis(2));
        let now = Instant::now();
        let tai_advanced = lengsuo_wireguard::handshake::tai64n_now() != before;
        let monotonic = now
            .checked_duration_since(previous)
            .is_some_and(|gap| gap >= ROUND_GAP);
        if tai_advanced && monotonic {
            return now;
        }
    }
}

/// 构造（发起方, 响应方）一对**未握手**的会话。
fn session_pair() -> (Session, Session) {
    let initiator = Session::new(SessionConfig::new(
        SessionRole::Initiator,
        INITIATOR_STATIC,
        RESPONDER_PUBLIC,
    ))
    .expect("发起方会话可构造");
    let responder = Session::new(SessionConfig::new(
        SessionRole::Responder,
        RESPONDER_STATIC,
        INITIATOR_PUBLIC,
    ))
    .expect("响应方会话可构造");
    (initiator, responder)
}

/// 在**同一对会话对象**上跑完一轮握手。
///
/// `index_base` 是本轮双方 index 的基址：每轮用**不同**的 index（index 与 key
/// epoch 一一对应，复用会让对端把新密钥的包当成旧 epoch 的包）。
fn handshake_round(
    initiator: &mut Session,
    responder: &mut Session,
    index_base: u32,
    seed_base: u8,
    now: Instant,
) {
    let initiation = initiator
        .create_initiation([seed_base; 32], index_base, now)
        .expect("initiation 可生成");
    assert_eq!(initiation.len(), 148, "initiation 固定 148 字节");
    responder
        .consume_initiation(&initiation, now)
        .expect("initiation 可剥壳");
    let response = responder
        .create_response([seed_base.wrapping_add(1); 32], index_base + 1, now)
        .expect("response 可生成");
    assert_eq!(response.len(), 92, "response 固定 92 字节");
    initiator
        .consume_response(&response, now)
        .expect("response 可消费");
}

/// 封一帧数据并取回线上字节。
fn seal(session: &mut Session, seq: u64, plain: &[u8]) -> Vec<u8> {
    session
        .seal_frame(FrameType::Data, seq, plain)
        .expect("封帧成功")
}

/// 解一帧并取回明文。
fn open(session: &mut Session, wire: &[u8]) -> Vec<u8> {
    session.open_frame(wire).expect("解帧成功").plaintext
}

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
