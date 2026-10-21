//! 帧编解码的往返与 fail-closed 用例。
//!
//! 覆盖任务书五·1–8：
//! 1. 往返等价；2. 长度不足；3. 长度字段与实际不符；4. 未知帧类型；
//! 5. 载荷超上限；6. 空载荷（keepalive）；7. 多帧粘包；8. 密文认证失败。
//!
//! 另加若干 fail-closed 分支：同步标记 / 版本 / 保留标志位 / 帧头校验和 /
//! 错误类型可区分性 / `Debug` 不泄漏密钥与载荷。

use lengsuo_link_core::frame::{
    decode, decode_exact, header_crc32, open_frame, seal_frame, split_frames, Frame, FrameError,
    FrameType, FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD_LEN, MAX_PLAIN_LEN,
};
use lengsuo_wireguard::transport::{Receiver, Sender, TransportKey};

/// 测试专用会话密钥（全 0x5A）。**仅用于本测试**，不得用于任何真实会话。
fn test_key() -> TransportKey {
    TransportKey::new(&[0x5Au8; 32]).expect("测试密钥长度固定为 32 字节")
}

/// 发送侧上下文：接收者标识与测试向量保持一致。
fn test_sender() -> Sender {
    Sender::new(test_key(), 0x1122_3344, 0)
}

/// 接收侧上下文。
fn test_receiver() -> Receiver {
    Receiver::new(test_key(), 0x1122_3344, u64::MAX)
}

/// 改过帧头的字节后重算帧头校验和（校验和覆盖帧头前 16 字节）。
fn refresh_crc(buf: &mut [u8]) {
    let crc = header_crc32(&buf[..16]);
    buf[16..20].copy_from_slice(&crc.to_be_bytes());
}

// ---------------------------------------------------------------- 1. 往返等价

#[test]
fn roundtrip_preserves_type_seq_and_plaintext() {
    let mut sender = test_sender();
    let plain = b"\x00\x01ACP-frame-payload".to_vec();
    let bytes = seal_frame(&mut sender, FrameType::Data, 42, &plain).expect("封装应当成功");

    let (frame, consumed) = decode(&bytes).expect("解码应当成功");
    assert_eq!(consumed, bytes.len(), "单帧缓冲应当被恰好消费完");
    assert_eq!(frame.frame_type, FrameType::Data);
    assert_eq!(frame.seq, 42);
    assert_ne!(frame.payload, plain, "帧载荷是密文，不是明文");

    let mut receiver = test_receiver();
    let opened = open_frame(&mut receiver, &bytes).expect("解封应当成功");
    assert_eq!(opened.plaintext, plain, "明文必须逐字节还原");
    assert_eq!(opened.seq, 42);
    assert_eq!(opened.frame_type, FrameType::Data);
}

// ------------------------------------------------------------ 2. 长度不足

#[test]
fn truncated_buffer_reports_incomplete_and_returns_no_partial_data() {
    let mut sender = test_sender();
    let bytes = seal_frame(&mut sender, FrameType::Data, 7, b"0123456789").expect("封装应当成功");
    assert!(bytes.len() > FRAME_HEADER_LEN);

    // 任何长度都切不出完整帧 ⇒ 一律 Incomplete，绝不返回部分数据。
    for cut in 0..bytes.len() {
        match decode(&bytes[..cut]) {
            Err(FrameError::Incomplete { .. }) => {}
            other => panic!("截断到 {cut} 字节时期望 Incomplete，实际 {other:?}"),
        }
        match decode_exact(&bytes[..cut]) {
            Err(FrameError::Incomplete { .. }) => {}
            other => panic!("截断到 {cut} 字节时期望 Incomplete，实际 {other:?}"),
        }
    }
}

// ------------------------------------------------- 3. 长度字段与实际不符

#[test]
fn length_field_mismatch_is_rejected_not_guessed() {
    let mut sender = test_sender();
    let bytes = seal_frame(&mut sender, FrameType::Data, 8, b"abcd").expect("封装应当成功");

    // (a) 实际比声明多：明确报错，不按实际长度猜。
    let mut extra = bytes.clone();
    extra.extend_from_slice(b"xyz");
    match decode_exact(&extra) {
        Err(FrameError::LengthMismatch { declared, actual }) => {
            assert_eq!(declared, bytes.len());
            assert_eq!(actual, bytes.len() + 3);
        }
        other => panic!("期望 LengthMismatch，实际 {other:?}"),
    }

    // (b) 实际比声明少：明确报错，不截断后当完整帧交付。
    let mut short = bytes.clone();
    short.truncate(short.len() - 2);
    match decode(&short) {
        Err(FrameError::Incomplete { .. }) => {}
        other => panic!("期望 Incomplete，实际 {other:?}"),
    }

    // (c) 长度字段被篡改（校验和同步修正）：超上限 ⇒ 明确报错。
    let mut tampered = bytes.clone();
    tampered[12..14].copy_from_slice(&u16::MAX.to_be_bytes());
    refresh_crc(&mut tampered);
    match decode(&tampered) {
        Err(FrameError::PayloadTooLong { .. }) => {}
        other => panic!("期望 PayloadTooLong，实际 {other:?}"),
    }
}

// --------------------------------------------------------- 4. 未知帧类型

#[test]
fn unknown_frame_type_is_rejected_and_never_parsed_as_data() {
    let mut sender = test_sender();
    let bytes = seal_frame(&mut sender, FrameType::Data, 9, b"payload").expect("封装应当成功");

    let mut tampered = bytes.clone();
    tampered[3] = 0x7F;
    refresh_crc(&mut tampered);

    match decode(&tampered) {
        Err(FrameError::UnknownFrameType { got: 0x7F }) => {}
        other => panic!("期望 UnknownFrameType，实际 {other:?}"),
    }

    // 绝不能被当成数据帧解出明文。
    let mut receiver = test_receiver();
    assert!(open_frame(&mut receiver, &tampered).is_err());
}

// --------------------------------------------------------- 5. 载荷超上限

#[test]
fn oversized_payload_is_rejected_without_truncation() {
    let over = vec![0u8; MAX_PLAIN_LEN + 1];
    let mut sender = test_sender();
    let counter_before = sender.next_counter();
    match seal_frame(&mut sender, FrameType::Data, 1, &over) {
        Err(FrameError::PayloadTooLong { .. }) => {}
        other => panic!("期望 PayloadTooLong，实际 {other:?}"),
    }
    assert_eq!(
        sender.next_counter(),
        counter_before,
        "超限必须在写入前拒绝，不消耗发送侧计数器"
    );

    // 编码器同样不接受超限载荷，且不截断。
    let frame = Frame::new(FrameType::Data, 1, vec![0u8; MAX_FRAME_PAYLOAD_LEN + 1]);
    match frame.encode() {
        Err(FrameError::PayloadTooLong { .. }) => {}
        other => panic!("期望 PayloadTooLong，实际 {other:?}"),
    }
}

// --------------------------------------------- 6. 空载荷（keepalive 语义）

#[test]
fn empty_payload_keepalive_roundtrips() {
    let mut sender = test_sender();
    let bytes = seal_frame(&mut sender, FrameType::Keepalive, 0, &[]).expect("封装应当成功");

    let (frame, consumed) = decode(&bytes).expect("解码应当成功");
    assert_eq!(consumed, bytes.len());
    assert_eq!(frame.frame_type, FrameType::Keepalive);
    // 载荷是**密封后**的空明文包（传输头 + 认证标签，非零长）；
    // 零长指的是明文侧。
    assert_eq!(frame.payload.len(), 32, "空明文密封后是 32 字节的传输包");

    let mut receiver = test_receiver();
    let opened = open_frame(&mut receiver, &bytes).expect("解封应当成功");
    assert!(opened.plaintext.is_empty(), "keepalive 的明文必须零长");
    assert_eq!(opened.frame_type, FrameType::Keepalive);
}

// ------------------------------------------------------------ 7. 多帧粘包

#[test]
fn three_sticky_frames_split_correctly() {
    let mut sender = test_sender();
    let mut buffer = Vec::new();
    let mut expected = Vec::new();
    for i in 0..3u64 {
        let plain = format!("frame-{i}-payload").into_bytes();
        buffer.extend_from_slice(
            &seal_frame(&mut sender, FrameType::Data, i * 10, &plain).expect("封装应当成功"),
        );
        expected.push(plain);
    }

    let mut rest: &[u8] = &buffer;
    for (i, want) in expected.iter().enumerate() {
        let (frame, consumed) = decode(rest).expect("应当能切出下一帧");
        assert!(consumed > 0, "切分必须推进");
        assert_eq!(frame.seq, i as u64 * 10, "第 {i} 帧序号不对");
        let mut receiver = test_receiver();
        let opened = open_frame(&mut receiver, &rest[..consumed]).expect("解封应当成功");
        assert_eq!(&opened.plaintext, want, "第 {i} 帧内容不对");
        rest = &rest[consumed..];
    }
    assert!(rest.is_empty(), "三帧应当被恰好切完");
}

#[test]
fn split_frames_splits_all_and_reports_desync() {
    let mut sender = test_sender();
    let mut buffer = Vec::new();
    for i in 0..3u64 {
        buffer.extend_from_slice(
            &seal_frame(&mut sender, FrameType::Data, i, format!("p{i}").as_bytes())
                .expect("封装应当成功"),
        );
    }
    let frames = split_frames(&buffer).expect("应当切出 3 帧");
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0].seq, 0);
    assert_eq!(frames[2].seq, 2);

    // 尾部塞垃圾 ⇒ 帧边界错位，明确报错（不把垃圾当载荷）。
    let mut broken = buffer.clone();
    broken.extend_from_slice(b"garbage");
    match split_frames(&broken) {
        Err(FrameError::Desync { offset }) => assert_eq!(offset, buffer.len()),
        other => panic!("期望 Desync，实际 {other:?}"),
    }
}

// ------------------------------------------------------ 8. 密文认证失败

#[test]
fn wrong_key_open_reports_auth_failure_and_never_returns_plaintext() {
    let mut sender = test_sender();
    let bytes =
        seal_frame(&mut sender, FrameType::Data, 3, b"top-secret-plaintext").expect("封装应当成功");

    let other_key = TransportKey::new(&[0xC3u8; 32]).expect("长度合法");
    let mut receiver = Receiver::new(other_key, 0x1122_3344, u64::MAX);
    match open_frame(&mut receiver, &bytes) {
        Err(FrameError::AuthFailed) => {}
        other => panic!("期望 AuthFailed，实际 {other:?}"),
    }
    assert!(receiver.is_poisoned(), "认证失败后接收侧永久 poison");
    match open_frame(&mut receiver, &bytes) {
        Err(FrameError::Poisoned) => {}
        other => panic!("期望 Poisoned，实际 {other:?}"),
    }
}

// ------------------------------------------------- 其余 fail-closed 分支

#[test]
fn bad_magic_is_rejected() {
    let mut sender = test_sender();
    let mut bytes = seal_frame(&mut sender, FrameType::Data, 1, b"x").expect("封装应当成功");
    bytes[0] = 0x00;
    refresh_crc(&mut bytes);
    match decode(&bytes) {
        Err(FrameError::BadMagic { .. }) => {}
        other => panic!("期望 BadMagic，实际 {other:?}"),
    }
}

#[test]
fn unsupported_version_is_rejected() {
    let mut sender = test_sender();
    let mut bytes = seal_frame(&mut sender, FrameType::Data, 1, b"x").expect("封装应当成功");
    bytes[2] = 0x02;
    refresh_crc(&mut bytes);
    match decode(&bytes) {
        Err(FrameError::UnsupportedVersion { got: 0x02, .. }) => {}
        other => panic!("期望 UnsupportedVersion，实际 {other:?}"),
    }
}

#[test]
fn reserved_flags_must_be_zero() {
    let mut sender = test_sender();
    let mut bytes = seal_frame(&mut sender, FrameType::Data, 1, b"x").expect("封装应当成功");
    bytes[14..16].copy_from_slice(&1u16.to_be_bytes());
    refresh_crc(&mut bytes);
    match decode(&bytes) {
        Err(FrameError::ReservedFlags { got: 1 }) => {}
        other => panic!("期望 ReservedFlags，实际 {other:?}"),
    }
}

#[test]
fn header_crc_mismatch_is_rejected() {
    let mut sender = test_sender();
    let mut bytes = seal_frame(&mut sender, FrameType::Data, 1, b"x").expect("封装应当成功");
    bytes[16] ^= 0xFF; // 只破坏校验和，载荷仍完整
    match decode(&bytes) {
        Err(FrameError::HeaderCrcMismatch { .. }) => {}
        other => panic!("期望 HeaderCrcMismatch，实际 {other:?}"),
    }
}

#[test]
fn transport_error_semantics_stay_distinguishable() {
    // KeyLength：密钥长度不对。
    let bad_key = TransportKey::new(&[0u8; 31]).expect_err("31 字节密钥必须被拒");
    assert!(matches!(
        bad_key,
        lengsuo_wireguard::transport::Error::KeyLength { .. }
    ));

    // TooLong：载荷超上限（帧层自己的上限检查先命中）。
    let mut sender = test_sender();
    let err = seal_frame(
        &mut sender,
        FrameType::Data,
        1,
        &vec![0u8; MAX_PLAIN_LEN + 1],
    )
    .expect_err("超限必须报错");
    assert!(matches!(err, FrameError::PayloadTooLong { .. }));

    // Poisoned：发送侧显式 poison。
    let mut poisoned = test_sender();
    poisoned.poison();
    match seal_frame(&mut poisoned, FrameType::Data, 1, b"x") {
        Err(FrameError::Poisoned) => {}
        other => panic!("期望 Poisoned，实际 {other:?}"),
    }

    // AuthFailed：错误密钥。
    let mut sender = test_sender();
    let bytes = seal_frame(&mut sender, FrameType::Data, 1, b"x").expect("封装应当成功");
    let mut receiver = Receiver::new(
        TransportKey::new(&[0x11u8; 32]).unwrap(),
        0x1122_3344,
        u64::MAX,
    );
    match open_frame(&mut receiver, &bytes) {
        Err(FrameError::AuthFailed) => {}
        other => panic!("期望 AuthFailed，实际 {other:?}"),
    }
}

#[test]
fn debug_and_error_text_never_leak_key_bytes_or_plaintext() {
    let secret = [0x9Eu8; 32];
    let key = TransportKey::new(&secret).expect("长度合法");
    let mut sender = Sender::new(key, 0x1122_3344, 0);
    let plain = b"PLAINTEXT-MUST-NOT-APPEAR".to_vec();
    let bytes = seal_frame(&mut sender, FrameType::Data, 1, &plain).expect("封装应当成功");

    let mut receiver = Receiver::new(
        TransportKey::new(&[0x01u8; 32]).unwrap(),
        0x1122_3344,
        u64::MAX,
    );
    let err = open_frame(&mut receiver, &bytes).expect_err("错误密钥必须失败");
    let text = format!("{err} {err:?}");
    for byte in secret {
        let hex = format!("{byte:02x}");
        assert!(
            !text.contains(&hex) && !text.contains(&format!("{byte:02X}")),
            "错误文本泄漏了密钥字节 {hex}"
        );
    }
    assert!(
        !text.contains("PLAINTEXT-MUST-NOT-APPEAR"),
        "错误文本泄漏了明文"
    );

    // 帧的 Debug 只出类型/序号/长度，不出载荷。
    let (frame, _) = decode(&bytes).expect("解码应当成功");
    let debug = format!("{frame:?}");
    assert!(!debug.contains("PLAINTEXT-MUST-NOT-APPEAR"));
    assert!(debug.contains("payload_len"), "Debug 应当只出长度：{debug}");
}
