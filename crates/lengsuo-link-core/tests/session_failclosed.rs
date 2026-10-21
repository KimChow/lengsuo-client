//! L2 会话 fail-closed 与失效用例。
//!
//! 覆盖任务书 §七 的 6–8 条：
//! 6. **认证失败 ⇒ 失效**：用错误密钥解封 ⇒ 错误可区分（`AuthFailed` 类），
//!    **不回退明文**，且会话被标记为**已失效**。
//! 7. **失效后拒绝收发**：会话失效后再调封/解 ⇒ 明确错误，**不静默成功**。
//! 8. **错误密钥字节不外泄**：会话对象的 `Debug` / 错误文本**不含**密钥字节。
//!
//! 全部是**测试专用假密钥**（0x11 / 0x22 / 0x5A / 0x99 模式字节），不代表任何
//! 真实凭据。对端公钥由仓外独立实现（Python `cryptography` 的 X25519）算出后
//! 写死 ⇒ 不依赖本仓的 X25519 代码自证。
//!
//! ⚠️ 本文件**不**证明与任何真实 WireGuard 端互通。

use std::time::Instant;

use lengsuo_link_core::frame::{FrameType, FRAME_HEADER_LEN};
use lengsuo_link_core::session::{Session, SessionConfig, SessionError, SessionRole, SessionState};

/// 发起方静态私钥（测试专用）。
const INITIATOR_STATIC: [u8; 32] = [0x11; 32];
/// 响应方静态私钥（测试专用）。
const RESPONDER_STATIC: [u8; 32] = [0x22; 32];
/// 「另一条链路」发起方的静态私钥（测试专用）。
const OTHER_INITIATOR_STATIC: [u8; 32] = [0x99; 32];
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
/// 「另一条链路」发起方的静态公钥（私钥 = 0x99 × 32；仓外独立算出）。
const OTHER_INITIATOR_PUBLIC: [u8; 32] = [
    0xba, 0x19, 0x38, 0x36, 0xcf, 0xf1, 0xf4, 0xe8, 0x66, 0xc1, 0x39, 0x71, 0x5d, 0x30, 0x64, 0x08,
    0xd2, 0x6a, 0x76, 0xf7, 0x6d, 0x63, 0x8a, 0x39, 0xaf, 0xc1, 0x00, 0x10, 0x84, 0xd2, 0x54, 0x11,
];
/// 明显可辨的「错误密钥」字节模式——用于断言它**不出现在**任何输出里。
const POISON_KEY: [u8; 32] = [0x5A; 32];

/// 构造（发起方, 响应方）一对**已建立**的会话。
fn established_pair() -> (Session, Session) {
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
    let (mut initiator, mut responder) = (initiator, responder);
    let now = Instant::now();
    let initiation = initiator
        .create_initiation([0xA1; 32], 10, now)
        .expect("initiation 可生成");
    responder
        .consume_initiation(&initiation, now)
        .expect("initiation 可剥壳");
    let response = responder
        .create_response([0xB2; 32], 11, now)
        .expect("response 可生成");
    initiator
        .consume_response(&response, now)
        .expect("response 可消费");
    (initiator, responder)
}

/// 封一帧数据并取回线上字节。
fn seal(session: &mut Session, seq: u64, plain: &[u8]) -> Vec<u8> {
    session
        .seal_frame(FrameType::Data, seq, plain)
        .expect("封帧成功")
}

/// 篡改密文末字节（制造 AEAD 认证失败）。
fn corrupt(wire: &[u8]) -> Vec<u8> {
    let mut out = wire.to_vec();
    let last = out.len() - 1;
    out[last] ^= 0x01;
    out
}

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

// ---------------------------------------------------------------- §七 8：密钥不外泄

#[test]
fn session_debug_output_contains_no_key_bytes() {
    let (initiator, responder) = established_pair();
    for session in [&initiator, &responder] {
        assert_no_key_bytes(&format!("{session:?}"), "Session Debug");
    }
}

#[test]
fn session_config_debug_output_contains_no_key_bytes() {
    let config = SessionConfig::new(SessionRole::Initiator, INITIATOR_STATIC, RESPONDER_PUBLIC)
        .with_preshared_key(POISON_KEY);
    let rendered = format!("{config:?}");
    assert_no_key_bytes(&rendered, "SessionConfig Debug");
    assert!(
        !rendered.contains("5a5a5a5a") && !rendered.contains("0x5a"),
        "配置 Debug 不得含 PSK 字节：{rendered}"
    );
}

#[test]
fn error_messages_contain_no_key_bytes() {
    let (mut initiator, mut responder) = established_pair();

    // 触发各类错误，检查错误文本里没有密钥字节。
    let corrupted = corrupt(&seal(&mut initiator, 1, b"payload"));

    let errors = vec![
        responder.open_frame(&corrupted).expect_err("必须失败"),
        responder
            .seal_frame(FrameType::Data, 2, b"x")
            .expect_err("必须失败"),
        responder.open_frame(&[0u8; 3]).expect_err("必须失败"),
        initiator
            .seal_frame(FrameType::Data, 3, &vec![0u8; 5000])
            .expect_err("必须失败"),
        initiator
            .consume_response(&[0u8; 92], Instant::now())
            .expect_err("必须失败"),
        initiator
            .consume_initiation(&[0u8; 148], Instant::now())
            .expect_err("必须失败"),
    ];
    for error in &errors {
        assert_no_key_bytes(&error.to_string(), "错误文本");
    }

    // 构造期错误里也不含密钥：全零公钥/私钥被拒。
    let error = Session::new(SessionConfig::new(
        SessionRole::Initiator,
        POISON_KEY,
        [0u8; 32],
    ))
    .expect_err("全零远端公钥应被拒");
    assert_no_key_bytes(&error.to_string(), "构造错误文本");

    let error = Session::new(SessionConfig::new(
        SessionRole::Initiator,
        [0u8; 32],
        RESPONDER_PUBLIC,
    ))
    .expect_err("全零本端私钥应被拒");
    assert_no_key_bytes(&error.to_string(), "构造错误文本");
}

/// 断言文本里**不含**任何密钥字节的常见泄漏形态。
///
/// 覆盖四种形态：数组 Debug（`[17, 17, ...]`）、hex 小写、hex 大写、重复字节。
fn assert_no_key_bytes(text: &str, what: &str) {
    for key in [
        INITIATOR_STATIC,
        RESPONDER_STATIC,
        OTHER_INITIATOR_STATIC,
        POISON_KEY,
    ] {
        // 形态 1：Rust 数组 Debug 形态（逗号分隔的十进制）。
        let decimal = format!("{key:?}");
        assert!(
            !text.contains(&decimal),
            "{what} 泄漏了密钥的数组 Debug 形态：{text}"
        );
        // 形态 2/3：hex 小写 / 大写。
        let hex_lower: String = key.iter().map(|b| format!("{b:02x}")).collect();
        let hex_upper: String = key.iter().map(|b| format!("{b:02X}")).collect();
        assert!(
            !text.contains(&hex_lower) && !text.contains(&hex_upper),
            "{what} 泄漏了密钥的 hex 形态：{text}"
        );
        // 形态 4：单字节连续重复（如 0x5A 全同密钥 ⇒ "5a5a5a5a"）。
        if key.iter().all(|b| *b == key[0]) {
            let repeated = format!("{:02x}", key[0]).repeat(8);
            assert!(
                !text.contains(&repeated),
                "{what} 泄漏了密钥的重复字节形态：{text}"
            );
        }
    }
}
