// 头部异常矩阵：错密码 / 截断 / 篡改 / 重放（只作用于**请求头**字节）。
//
// 本文件由 `tests/security_matrix.rs` 用 `include!` 文本并入同一模块；
// 共享常量与助手在 `security_matrix/common.rs`，`use` 写在入口文件。

// ---- 1) 错密码 ----

/// 错密码（cmd key 不匹配）⇒ 头部必须被拒，且不得返回任何明文。
#[test]
fn wrong_password_is_rejected_for_every_tier() {
    for (security, _) in TIERS {
        let wire = seal_request(security);
        let wrong_key: [u8; 16] = *b"wrong-password--";
        let mut cursor = &wire[..];
        let mut session = accept_session();
        let result = decode_request_header(&[wrong_key], &mut cursor, NOW, &mut session);
        match result {
            Err(HeaderDecodeError::InvalidUser) => {}
            Err(other) => panic!("security={security:?} 期望 InvalidUser，实际 {other:?}"),
            Ok(_) => panic!("security={security:?} 错密码不得通过"),
        }
    }
}

// ---- 2) 截断 ----

/// 截断：头部 / 长度段 / 载荷段各截一处 ⇒ 必须报错，不得 panic、不得返回明文。
#[test]
fn truncation_is_rejected_for_every_tier() {
    for (security, _) in TIERS {
        let wire = seal_request(security);
        // 头部截断（AuthID 之后不足长度段+nonce）。
        {
            let mut cursor = &wire[..20];
            let mut session = accept_session();
            let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session);
            assert!(result.is_err(), "security={security:?} 头部截断必须失败");
            assert!(
                !result.is_ok(),
                "security={security:?} 头部截断不得返回明文"
            );
        }
        // 长度段截断（AuthID 16B 之后只给 10B）。
        {
            let mut cursor = &wire[..16 + 10];
            let mut session = accept_session();
            let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session);
            assert!(result.is_err(), "security={security:?} 长度段截断必须失败");
        }
        // 载荷段截断（砍掉尾部 8 字节）。
        {
            let mut cursor = &wire[..wire.len() - 8];
            let mut session = accept_session();
            let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session);
            assert!(result.is_err(), "security={security:?} 载荷段截断必须失败");
        }
    }
}

// ---- 3) 篡改 ----

/// 篡改：头部 AAD（AuthID）/ 连接 nonce / 载荷 tag 各改一处 ⇒ 必须 AuthFailed。
#[test]
fn tampering_is_rejected_for_every_tier() {
    for (security, _) in TIERS {
        let wire = seal_request(security);

        // 改 AuthID（AAD）⇒ 长度段 tag 校验失败。
        {
            let mut broken = wire.clone();
            broken[0] ^= 0x01;
            let mut cursor = &broken[..];
            let mut session = accept_session();
            let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session);
            assert!(
                matches!(result, Err(HeaderDecodeError::InvalidUser)),
                "security={security:?} 改 AuthID 必须 invalid user，实际 {:?}",
                result.map(|_| ())
            );
        }
        // 改连接 nonce ⇒ 长度段 tag 校验失败。
        {
            let mut broken = wire.clone();
            broken[16 + 18] ^= 0x01;
            let mut cursor = &broken[..];
            let mut session = accept_session();
            let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session);
            assert!(
                matches!(result, Err(HeaderDecodeError::AeadLengthTag)),
                "security={security:?} 改 nonce 必须 AeadLengthTag，实际 {:?}",
                result.map(|_| ())
            );
        }
        // 改载荷段密文 ⇒ 载荷 tag 校验失败。
        {
            let mut broken = wire.clone();
            let last = broken.len() - 1;
            broken[last] ^= 0x01;
            let mut cursor = &broken[..];
            let mut session = accept_session();
            let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session);
            assert!(
                matches!(result, Err(HeaderDecodeError::AeadPayloadTag)),
                "security={security:?} 改载荷 tag 必须 AeadPayloadTag，实际 {:?}",
                result.map(|_| ())
            );
        }
    }
}

// ---- 4) 重放 ----

/// 重放：同一 AuthID 二次出现 ⇒ 第二次必须 `Replay`。
#[test]
fn replayed_session_is_rejected_for_every_tier() {
    for (security, _) in TIERS {
        let wire = seal_request(security);
        // 会话过滤器：第一次接受，第二次拒绝（模拟 session history）。
        let mut calls = 0usize;
        let mut filter = |_: &[u8; 16], _: &[u8; 16], _: &[u8; 16]| {
            calls += 1;
            calls == 1
        };
        {
            let mut cursor = &wire[..];
            let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut filter);
            assert!(result.is_ok(), "security={security:?} 首次必须通过");
        }
        {
            let mut cursor = &wire[..];
            let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut filter);
            assert!(
                matches!(result, Err(HeaderDecodeError::Replay)),
                "security={security:?} 重放必须 Replay，实际 {:?}",
                result.map(|_| ())
            );
        }
    }
}
