// 密钥不外泄主题：会话对象 / 配置 / 错误文本里不得出现密钥字节（任务书 §七 8）。
//
// 本文件由 `tests/session_failclosed.rs` 用 `include!` 文本并入同一模块；
// 共享夹具在 `tests/session_failclosed/common.rs`，`use` 全部写在入口文件。

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
