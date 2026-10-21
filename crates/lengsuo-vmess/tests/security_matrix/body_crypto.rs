// 数据段密码学语义：篡改检出 / none 档明文 / 长度段形态 / 掩码流推进。
//
// 本文件由 `tests/security_matrix.rs` 用 `include!` 文本并入同一模块；
// 共享常量与助手在 `security_matrix/common.rs`，`use` 写在入口文件。

/// 篡改：数据段密文/tag 逐档必须 fail-closed。
#[test]
fn body_tampering_is_rejected_for_every_tier() {
    for (security, _) in TIERS {
        let suite = suite_of(security);
        let mut seal = BodyCipher::from_suite(suite, &BODY_KEY, &BODY_IV);
        let ct = seal.seal_payload(b"secret-payload").expect("可封");
        if suite == BodySuite::None {
            // none 档没有 AEAD：明文篡改不可检出，这是参考的既定语义
            // （`SecurityType_NONE` 不带认证）。断言「不 panic、长度不变」。
            let mut open = BodyCipher::from_suite(suite, &BODY_KEY, &BODY_IV);
            let plain = open.open_payload(&ct).expect("none 档可解");
            assert_eq!(plain.len(), ct.len());
            continue;
        }
        for index in [0usize, ct.len() / 2, ct.len() - 1] {
            let mut broken = ct.clone();
            broken[index] ^= 0x01;
            let mut open = BodyCipher::from_suite(suite, &BODY_KEY, &BODY_IV);
            let result = open.open_payload(&broken);
            assert!(
                matches!(result, Err(lengsuo_vmess::Error::AuthFailed)),
                "security={security:?} index={index} 必须 AuthFailed，实际 {result:?}"
            );
        }
    }
}

/// 数据段的 `none` 档不产生 AEAD（参考 `SecurityType_NONE` 的既定语义），
/// 但**不得**被误当成「解析失败」而静默变 AES。
#[test]
fn none_tier_produces_plaintext_body_not_aes() {
    let mut seal = BodyCipher::from_suite(BodySuite::None, &BODY_KEY, &BODY_IV);
    let ct = seal.seal_payload(b"plain-body").expect("可封");
    assert_eq!(ct, b"plain-body", "none 档载荷必须是明文");
    let mut open = BodyCipher::from_suite(BodySuite::None, &BODY_KEY, &BODY_IV);
    let plain = open.open_payload(&ct).expect("可解");
    assert_eq!(plain, b"plain-body");
}

/// `SizeMode` 的判定：认证长度段优先于掩码（对齐参考的选项组合）。
#[test]
fn size_mode_precedence_matches_reference() {
    use lengsuo_vmess::bodyframe::size_mode_for_options;
    // 只有掩码 ⇒ Masked。
    assert_eq!(
        size_mode_for_options(0x04, BodySuite::Aes128Gcm).expect("可判定"),
        SizeMode::Masked
    );
    // 认证长度段 ⇒ Authenticated（替换掉 Shake 解析器）。
    assert_eq!(
        size_mode_for_options(0x10, BodySuite::Aes128Gcm).expect("可判定"),
        SizeMode::Authenticated
    );
    assert_eq!(
        size_mode_for_options(0x1C, BodySuite::Aes128Gcm).expect("可判定"),
        SizeMode::Authenticated
    );
    // 都没有 ⇒ Plain。
    assert_eq!(
        size_mode_for_options(0x00, BodySuite::Aes128Gcm).expect("可判定"),
        SizeMode::Plain
    );
    // none 档：参考的 NONE 分支不看认证长度段。
    assert_eq!(
        size_mode_for_options(0x10, BodySuite::None).expect("可判定"),
        SizeMode::Plain
    );
}

/// 掩码流在每帧推进（跨帧不复用掩码）——逐档验证。
#[test]
fn shake_mask_advances_per_frame_for_every_tier() {
    const PAYLOAD: &[u8] = b"same";
    for (security, _) in TIERS {
        let suite = suite_of(security);
        let mut seal =
            BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, 0x04)
                .expect("可建");
        let mut wire = Vec::new();
        seal.seal(&mut wire, PAYLOAD).expect("可写");
        let first_len = wire[..2].to_vec();
        // 帧长 = 长度段(2) + 载荷密文(明文长 + tag)；none 档无 tag。
        let frame_len = 2 + PAYLOAD.len() + suite.overhead();
        seal.seal(&mut wire, PAYLOAD).expect("可写");
        let second_len = wire[frame_len..frame_len + 2].to_vec();
        assert_ne!(
            first_len, second_len,
            "security={security:?} 掩码流必须逐帧推进"
        );
    }
}

/// 掩码流与 `DataSizeParser` 的行为一致（本仓与参考共用 Shake 语义）。
#[test]
fn mask_matches_data_size_parser_for_every_tier() {
    const PAYLOAD: &[u8] = b"payload";
    for (security, _) in TIERS {
        let suite = suite_of(security);
        let mut parser = DataSizeParser::new(&BODY_IV);
        let mut seal =
            BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, 0x04)
                .expect("可建");
        let mut wire = Vec::new();
        seal.seal(&mut wire, PAYLOAD).expect("可写");
        // 声明长度 = 载荷密文长 = 明文长 + tag（none 档无 tag）。
        let declared = (PAYLOAD.len() + suite.overhead()) as u16;
        assert_eq!(
            wire[..2].to_vec(),
            parser.encode_size(declared).to_vec(),
            "security={security:?} 长度段掩码必须与 ShakeSizeParser 一致"
        );
    }
}
