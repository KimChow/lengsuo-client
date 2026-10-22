// ① 正常往返 + 与既有原语的逐字节等价（新 API 只是编排，没有复制第二份实现）。
/// 正常往返：既有原语封出的线上字节 → 新 API 还原 ⇒ 载荷逐字节一致。
#[test]
fn roundtrip_via_new_api_restores_payload_byte_for_byte() {
    for cipher in [XelCipher::Aes256Gcm, XelCipher::ChaCha20Poly1305] {
        for xor in [false, true] {
            let (mut sender, mut receiver) = pair(cipher, xor);
            for payload in payloads() {
                let wire = sender.seal(&payload).expect("封包成功");
                let plain = receiver.open(&wire).expect("解包成功");
                assert_eq!(plain, payload, "{cipher:?} xor={xor}：载荷必须逐字节还原");
            }
            receiver.finish().expect("流必须恰好结束");
        }
    }
}

/// 正常往返（流式）：线上字节任意切分喂入 ⇒ 载荷逐字节一致、顺序不变。
#[test]
fn roundtrip_survives_arbitrary_wire_chunking() {
    for step in [1usize, 2, 3, 5, 7, 22, 64, 512] {
        // 分块与一次性各用独立实例：接收方向有状态（序号锁定步）。
        let (mut sender, mut receiver) = pair(XelCipher::Aes256Gcm, true);
        let mut wire = Vec::new();
        for payload in payloads() {
            wire.extend_from_slice(&sender.seal(&payload).unwrap());
        }
        let mut got: Vec<u8> = Vec::new();
        for chunk in wire.chunks(step) {
            got.extend_from_slice(&receiver.open(chunk).expect("解包成功"));
        }
        receiver.finish().expect("流必须恰好结束");
        let want: Vec<u8> = payloads().concat();
        assert_eq!(got, want, "分块步长 {step}：载荷必须逐字节一致");
    }
}

/// 空载荷不产出线上字节（参考 `common.go:49` 的 `if len(b) == 0 { return 0, nil }`）。
#[test]
fn empty_payload_produces_no_wire_bytes() {
    let (mut sender, mut receiver) = pair(XelCipher::Aes256Gcm, false);
    assert!(sender.seal(b"").unwrap().is_empty());
    assert!(receiver.open(b"").unwrap().is_empty());
    receiver.finish().expect("空流必须恰好结束");
}

/// 等价性：AEAD 模式下，新 API 的线上字节与既有 `RecordWriter` 逐字节相同。
#[test]
fn new_api_matches_existing_record_writer_byte_for_byte() {
    for cipher in [XelCipher::Aes256Gcm, XelCipher::ChaCha20Poly1305] {
        let (mut sender, _) = pair(cipher, false);
        // 既有原语：同一把密钥、同一套件，逐条封。
        let mut legacy = RecordWriter::new(cipher, uplink_key());
        for payload in payloads() {
            let ours = sender.seal(&payload).expect("封包成功");
            let theirs = legacy.seal(&payload).expect("既有原语封包成功");
            assert_eq!(
                ours, theirs,
                "{cipher:?}：新 API 的线上字节必须与既有原语逐字节相同"
            );
        }
    }
}

/// 等价性：AEAD 模式下，新 API 解出的明文与既有 `RecordReader` 逐字节相同。
#[test]
fn new_api_matches_existing_record_reader_byte_for_byte() {
    for cipher in [XelCipher::Aes256Gcm, XelCipher::ChaCha20Poly1305] {
        // 用既有原语封流。
        let mut legacy = RecordWriter::new(cipher, uplink_key());
        let mut wire = Vec::new();
        for payload in payloads() {
            wire.extend_from_slice(&legacy.seal(&payload).unwrap());
        }
        // 新 API 还原。
        let (_, mut receiver) = pair(cipher, false);
        assert_eq!(
            receiver.open(&wire).expect("解包成功"),
            payloads().concat(),
            "{cipher:?}：新 API 必须逐字节还原既有原语产出的流"
        );
        // 既有原语还原同一流 ⇒ 与新 API 结果逐字节相同。
        let mut legacy_reader = RecordReader::new(cipher, uplink_key());
        legacy_reader.push(&wire).unwrap();
        let mut legacy_plain = Vec::new();
        while let Some(chunk) = legacy_reader.next_plaintext().unwrap() {
            legacy_plain.extend_from_slice(&chunk);
        }
        legacy_reader.finish().unwrap();
        let (_, mut receiver2) = pair(cipher, false);
        assert_eq!(
            receiver2.open(&wire).unwrap(),
            legacy_plain,
            "{cipher:?}：新 API 与既有原语的还原结果必须逐字节相同"
        );
    }
}

/// 等价性：XOR 模式下，新 API 的线上字节与既有 `XorMask` + `RecordWriter` 逐字节相同。
#[test]
fn new_api_matches_existing_xor_mask_byte_for_byte() {
    let (mut sender, _) = pair(XelCipher::Aes256Gcm, true);
    // 既有原语：先 AEAD 封记录，再掩蔽 5 字节头（参考的层序）。
    let mut legacy_writer = RecordWriter::new(XelCipher::Aes256Gcm, uplink_key());
    let mut legacy_mask = XorMask::new(&uplink_key(), &IV_UP, &uplink_key(), &IV_UP).unwrap();
    for payload in payloads() {
        let mut theirs = legacy_writer.seal(&payload).unwrap();
        legacy_mask.mask_outgoing(&mut theirs).unwrap();
        let ours = sender.seal(&payload).expect("封包成功");
        assert_eq!(
            ours, theirs,
            "XOR 模式：新 API 的线上字节必须与既有原语逐字节相同"
        );
    }
}

/// 等价性：XOR 模式下，新 API 还原的明文与既有 `XorMask` + `RecordReader` 逐字节相同。
#[test]
fn new_api_matches_existing_xor_reader_byte_for_byte() {
    let mut legacy_writer = RecordWriter::new(XelCipher::Aes256Gcm, uplink_key());
    let mut legacy_mask = XorMask::new(&uplink_key(), &IV_UP, &uplink_key(), &IV_UP).unwrap();
    let mut wire = Vec::new();
    for payload in payloads() {
        let mut record = legacy_writer.seal(&payload).unwrap();
        legacy_mask.mask_outgoing(&mut record).unwrap();
        wire.extend_from_slice(&record);
    }
    // 既有原语还原。
    let mut legacy_reader = RecordReader::new(XelCipher::Aes256Gcm, uplink_key());
    let mut legacy_plain = Vec::new();
    for chunk in wire.chunks(7) {
        let mut unmasked = chunk.to_vec();
        legacy_mask.unmask_incoming(&mut unmasked).unwrap();
        legacy_reader.push(&unmasked).unwrap();
        while let Some(plain) = legacy_reader.next_plaintext().unwrap() {
            legacy_plain.extend_from_slice(&plain);
        }
    }
    legacy_reader.finish().unwrap();
    // 新 API 还原同一流。
    let (_, mut receiver) = pair(XelCipher::Aes256Gcm, true);
    assert_eq!(
        receiver.open(&wire).expect("解包成功"),
        legacy_plain,
        "XOR 模式：新 API 与既有原语的还原结果必须逐字节相同"
    );
}
