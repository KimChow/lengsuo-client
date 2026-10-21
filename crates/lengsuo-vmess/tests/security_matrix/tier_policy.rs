// 档位 fail-closed 语义：哨兵档 / 未知字节 / 头部套件解析。
//
// 本文件由 `tests/security_matrix.rs` 用 `include!` 文本并入同一模块；
// 共享常量与助手在 `security_matrix/common.rs`，`use` 写在入口文件。

// ---- 档位 fail-closed 语义 ----

/// `AutoCipher` 哨兵：本层**不解析**，必须 fail-closed，绝不默认 AES。
#[test]
fn autocipher_sentinel_is_never_resolved_to_aes() {
    // 请求头规划器直接拒绝。
    let planner = HeaderPlanner::new(KeySource {
        body_key: BODY_KEY,
        body_iv: BODY_IV,
        response_header: 0x33,
    });
    let header = RequestHeader {
        target: Some(TargetAddr::Domain("example.invalid".into(), 443)),
        command: Command::Tcp,
        security: SecurityOption::AutoCipher,
        option: 0,
        padding_len: 0,
    };
    let result = planner.plan_with(&header, &[]);
    assert!(
        matches!(result, Err(lengsuo_vmess::Error::Unsupported { .. })),
        "AutoCipher 必须被拒，实际 {result:?}"
    );

    // `SecurityOption::resolve()` 对 AutoCipher 返回 None（调用方自己决定）。
    assert_eq!(SecurityOption::AutoCipher.resolve(), None);
    assert!(SecurityOption::Aes128Gcm.resolve().is_some());
    assert!(SecurityOption::ChaCha20Poly1305.resolve().is_some());

    // 数据段套件解析对哨兵字节（2 = AUTO）fail-closed。
    let err = BodyCipher::new(SECURITY_AUTOCIPHER_BYTE, &BODY_KEY, &BODY_IV);
    assert!(err.is_err(), "AUTO 哨兵字节必须被拒");
}

/// `SecurityType_AUTO` 的线上字节（`common/protocol/headers.pb.go`：AUTO=2）。
const SECURITY_AUTOCIPHER_BYTE: u8 = 2;

/// 未知安全档字节（不在 `SecurityType_name` 表里）⇒ 数据段 fail-closed。
#[test]
fn unknown_security_bytes_fail_closed() {
    for byte in [0u8, 1, 6, 7, 0x0F] {
        let result = BodyCipher::new(byte, &BODY_KEY, &BODY_IV);
        assert!(
            matches!(result, Err(lengsuo_vmess::Error::Unsupported { .. })),
            "security byte={byte} 必须 fail-closed"
        );
    }
}

/// 三档的 `HeaderSecurity` 解析必须与参考 `parseSecurityType` 一致。
#[test]
fn header_security_parsing_matches_reference() {
    assert_eq!(
        HeaderSecurity::from_nibble(SECURITY_AES_128_GCM),
        Some(HeaderSecurity::Aes128Gcm)
    );
    assert_eq!(
        HeaderSecurity::from_nibble(SECURITY_CHACHA20_POLY1305),
        Some(HeaderSecurity::ChaCha20Poly1305)
    );
    assert_eq!(
        HeaderSecurity::from_nibble(SECURITY_NONE),
        Some(HeaderSecurity::None)
    );
    // AUTO(2) 与未知值在头阶段就拒（对齐参考「unknown security type」）。
    assert_eq!(HeaderSecurity::from_nibble(2), None);
    assert_eq!(HeaderSecurity::from_nibble(0), None);
    assert_eq!(HeaderSecurity::from_nibble(7), None);
}

/// 头部 AEAD 的 ChaCha 档必须 fail-closed（参考头部恒 AES-128-GCM）。
#[test]
fn header_chacha_suite_fails_closed_for_every_tier() {
    for (security, _) in TIERS {
        let plain = plan_header(security);
        let err =
            aead::seal_vmess_aead_header_with(&CMD_KEY, &plain, HeaderSuite::ChaCha20Poly1305)
                .expect_err("ChaCha 头部必须被拒");
        assert!(
            matches!(err, lengsuo_vmess::Error::Unsupported { .. }),
            "security={security:?} 实际 {err:?}"
        );
    }
}
