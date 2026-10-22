// ② 分块边界 + 错误输入 fail-closed（显式报错，不静默产出垃圾）。
/// 等价性：分块上限与参考一致——超长明文被切成 8192 字节的记录。
///
/// 参考 `common.go:53` `CommonConn.Write`：`if len(b) > 8192 { b = b[:8192] }`。
#[test]
fn long_payload_is_chunked_at_reference_8192_boundary() {
    let (mut sender, mut receiver) = pair(XelCipher::Aes256Gcm, false);
    let payload = vec![0x5A; MAX_PLAINTEXT_PER_RECORD * 2 + 17];
    let wire = sender.seal(&payload).expect("封包成功");
    // 三条记录：8192 + 8192 + 17 字节明文，每条加 16 字节 tag。
    let expected = 3 * (5 + 16) + payload.len();
    assert_eq!(wire.len(), expected, "记录条数必须与参考分块一致");
    assert_eq!(receiver.open(&wire).unwrap(), payload, "载荷必须逐字节还原");
    receiver.finish().unwrap();
}

/// 非法参数：IV 长度不对 ⇒ 显式报错，不静默降级。
#[test]
fn invalid_iv_length_is_rejected_explicitly() {
    for iv in [
        &[0u8; XOR_IV_LEN - 1][..],
        &[0u8; XOR_IV_LEN + 1][..],
        &[][..],
    ] {
        let outcome = XorLayer::new(uplink_key(), iv, downlink_key(), &IV_DOWN);
        assert!(
            matches!(
                outcome,
                Err(WireError::Record(XelError::InvalidIvLength { got, want }))
                    if got == iv.len() && want == XOR_IV_LEN
            ),
            "IV 长度 {} 必须被显式拒绝，实际 {:?}",
            iv.len(),
            outcome.err()
        );
    }
    // 下行 IV 同样受检。
    assert!(matches!(
        XorLayer::new(uplink_key(), &IV_UP, downlink_key(), &[0u8; 3]),
        Err(WireError::Record(XelError::InvalidIvLength { .. }))
    ));
}

/// 非法参数：AEAD 密钥长度不对 ⇒ 在构造 `XelKey` 时即被拒绝。
#[test]
fn invalid_key_length_is_rejected_explicitly() {
    for bytes in [&[0u8; 31][..], &[0u8; 33][..], &[][..]] {
        assert!(
            matches!(
                XelKey::new(bytes),
                Err(XelError::InvalidKeyLength { got, want })
                    if got == bytes.len() && want == 32
            ),
            "密钥长度 {} 必须被显式拒绝",
            bytes.len()
        );
    }
}

/// 错误密钥 ⇒ 显式认证失败，且方向被 poison（后续调用返回 `Poisoned`）。
#[test]
fn wrong_key_fails_closed_and_poisons() {
    let (mut sender, _) = pair(XelCipher::Aes256Gcm, false);
    let wire = sender.seal(b"secret xel wire payload").unwrap();
    // 用错钥构造接收端。
    let config = XelWireConfig {
        cipher: XelCipher::Aes256Gcm,
        uplink_key: wrong_key(),
        downlink_key: wrong_key(),
        xor: None,
    };
    let (_, mut receiver) = config.split().unwrap();
    assert!(
        matches!(
            receiver.open(&wire),
            Err(WireError::Record(XelError::AuthFailed))
        ),
        "错钥必须显式认证失败"
    );
    assert!(receiver.is_poisoned(), "认证失败后方向必须 poison");
    // 后续调用一律 `Poisoned`，绝不产出明文。
    assert!(matches!(
        receiver.open(&wire),
        Err(WireError::Record(XelError::Poisoned))
    ));
    // 帧器本身未被污染（污染的是 AEAD 方向），但方向已 poison ⇒ `finish`
    // 之后的任何读取都必须被拒绝。
    assert!(matches!(
        receiver.finish(),
        Ok(()) | Err(WireError::Record(XelError::Poisoned))
    ));
    assert!(matches!(
        receiver.open(&wire),
        Err(WireError::Record(XelError::Poisoned))
    ));
}

/// 截断输入：残字节 ⇒ 显式 `Truncated`，不静默丢弃。
#[test]
fn truncated_stream_is_reported_not_swallowed() {
    let (mut sender, mut receiver) = pair(XelCipher::Aes256Gcm, false);
    let wire = sender
        .seal(b"a xel wire payload long enough to truncate")
        .unwrap();
    receiver
        .open(&wire[..wire.len() - 3])
        .expect("不足一帧属于正常等待");
    assert!(
        matches!(
            receiver.finish(),
            Err(WireError::Record(XelError::Truncated { .. }))
        ),
        "残字节必须显式报截断"
    );
    assert!(receiver.is_poisoned(), "截断后方向必须 poison");
}

/// 非法头部：魔数被改 ⇒ 显式 `InvalidHeader`，不静默产出垃圾。
#[test]
fn invalid_magic_is_rejected_explicitly() {
    let (mut sender, mut receiver) = pair(XelCipher::Aes256Gcm, false);
    let mut wire = sender.seal(b"payload bytes here").unwrap();
    wire[0] ^= 0x01; // 破坏魔数
    assert!(
        matches!(
            receiver.open(&wire),
            Err(WireError::Record(XelError::InvalidHeader))
        ),
        "魔数不符必须显式报错"
    );
    assert!(receiver.is_poisoned(), "头部非法后方向必须 poison");
}

/// 长度越界：长度前缀不可信 ⇒ 显式 `InvalidRecordLength`，不静默攒字节。
#[test]
fn unsane_length_prefix_is_rejected_explicitly() {
    let (_, mut receiver) = pair(XelCipher::Aes256Gcm, false);
    // 魔数合法但 BE16 = 65535 > 16640（参考 `common.go:216` 的上界）。
    let outcome = receiver.open(&[23, 3, 3, 0xFF, 0xFF]);
    assert!(
        matches!(
            outcome,
            Err(WireError::Record(XelError::InvalidRecordLength { .. }))
        ),
        "长度前缀越界必须显式报错"
    );
    assert!(receiver.is_poisoned());
}

/// XOR 模式下头部被篡改 ⇒ 显式报错（掩蔽层 poison），不静默产出垃圾。
#[test]
fn xor_tampered_header_fails_closed() {
    let (mut sender, mut receiver) = pair(XelCipher::Aes256Gcm, true);
    let mut wire = sender.seal(b"payload for xor tamper check").unwrap();
    wire[0] ^= 0x01; // 掩蔽后的头部被篡改
    let outcome = receiver.open(&wire);
    assert!(
        matches!(
            outcome,
            Err(WireError::Record(
                XelError::InvalidHeader | XelError::InvalidRecordLength { .. }
            ))
        ),
        "XOR 头部被篡改必须显式报错，实际 {:?}",
        outcome.err()
    );
    assert!(receiver.is_poisoned());
}
