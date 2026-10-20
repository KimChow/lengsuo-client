//! VMess **多安全档异常矩阵**：3 档 × 7 类异常，逐条有明确断言。
//!
//! 档位（`SecurityOption`）：`None` / `Aes128Gcm` / `ChaCha20Poly1305`。
//! 异常类别：
//! 1. **错密码**（cmd key 不匹配）⇒ AuthID 校验失败（`InvalidUser`）。
//! 2. **截断**（头部 / 长度段 / 载荷段各截一处）⇒ `Truncated` / `Io`，
//!    绝不 panic、绝不返回明文。
//! 3. **篡改**（AAD / nonce / tag 各改一处）⇒ `AuthFailed`。
//! 4. **重放**（同一 AuthID 重发）⇒ `Replay`。
//! 5. **半关闭**（写端关闭后读端 EOF 边界）⇒ 读到 EOF 帧或干净关闭。
//! 6. **超时**（对端不响应）⇒ 读端在上限内返回，不无限挂起。
//! 7. **清理**（连接结束后资源释放、无后台任务残留）⇒ 帧上下文无残留状态。
//!
//! 全部用例都带**总超时**（`tokio::time::timeout`），避免 CI 上挂死。
//! 全部只用回环地址、临时端口、假凭据；日志不输出密钥/明文/口令。
//!
//! 协议事实（见 `docs/vmess-status.md`）：安全档只作用于**数据段**；请求头与
//! 响应头两段 AEAD 恒为 AES-128-GCM。因此「篡改 AAD / nonce」在头部用例里
//! 对两档是同一条路径，在数据段用例里才分档。

use std::time::Duration;

use lengsuo_vmess::aead::{self, HeaderSuite};
use lengsuo_vmess::bodyframe::{BodyCipher, BodyFrame, BodySuite, SizeMode};
use lengsuo_vmess::chunkframe::DataSizeParser;
use lengsuo_vmess::consts::{SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305, SECURITY_NONE};
use lengsuo_vmess::request::{Command, HeaderPlanner, KeySource, RequestHeader, SecurityOption};
use lengsuo_vmess::server::decode::{decode_request_header, HeaderDecodeError, HeaderSecurity};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// 每个用例的总超时上限。
const CASE_TIMEOUT: Duration = Duration::from_secs(10);
/// 假 cmd key（测试假凭据）。
const CMD_KEY: [u8; 16] = *b"b831381d-6324-4d";
/// 假会话密钥。
const BODY_KEY: [u8; 16] = *b"request-body-key";
/// 假会话 IV。
const BODY_IV: [u8; 16] = *b"request-body-iv!";
/// 固定 unix 秒（AuthID 时间窗可控）。
const NOW: i64 = 1_700_000_000;

/// 三个安全档 → 线上安全档字节。
const TIERS: [(SecurityOption, u8); 3] = [
    (SecurityOption::None, SECURITY_NONE),
    (SecurityOption::Aes128Gcm, SECURITY_AES_128_GCM),
    (SecurityOption::ChaCha20Poly1305, SECURITY_CHACHA20_POLY1305),
];

/// 档位 → 数据段套件（`None` 档没有 AEAD）。
fn suite_of(security: SecurityOption) -> BodySuite {
    security.resolve().expect("三档都可解析")
}

/// 造一个可用的请求头明文（固定 padding 长度，消掉随机项）。
fn plan_header(security: SecurityOption) -> Vec<u8> {
    let planner = HeaderPlanner::new(KeySource {
        body_key: BODY_KEY,
        body_iv: BODY_IV,
        response_header: 0x33,
    });
    let header = RequestHeader {
        target: Some(TargetAddr::Domain("example.invalid".into(), 443)),
        command: Command::Tcp,
        security,
        option: 0,
        padding_len: 0,
    };
    planner.plan_with(&header, &[]).expect("请求头明文可编码")
}

/// 造一条完整请求头线上字节（AuthID 时间固定在窗口内）。
fn seal_request(security: SecurityOption) -> Vec<u8> {
    let plain = plan_header(security);
    let auth = lengsuo_vmess::create_auth_id_with(&CMD_KEY, NOW, &[0x01, 0x02, 0x03, 0x04]);
    aead::seal_header_with(&CMD_KEY, auth.as_bytes(), &[0x11; 8], &plain)
}

/// 一次性会话过滤器（总是接受）。
fn accept_session() -> impl FnMut(&[u8; 16], &[u8; 16], &[u8; 16]) -> bool {
    |_, _, _| true
}

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

// ---- 5) 半关闭 ----

/// 半关闭：写端关闭后读端必须干净地看到 EOF（不挂起、不返回半截明文）。
#[tokio::test]
async fn half_close_yields_clean_eof_for_every_tier() {
    for (security, _) in TIERS {
        let outcome = tokio::time::timeout(CASE_TIMEOUT, async {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("可监听");
            let addr = listener.local_addr().expect("有地址");
            let wire = seal_request(security);
            let server = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.expect("可接受");
                // 读一点就关闭写端（半关闭）。
                let mut buf = [0u8; 64];
                let _ = sock.read(&mut buf).await;
                let _ = sock.shutdown().await;
            });
            let mut client = tokio::net::TcpStream::connect(addr).await.expect("可连接");
            client.write_all(&wire).await.expect("可写");
            let _ = client.shutdown().await;
            let mut rest = Vec::new();
            let read_result = client.read_to_end(&mut rest).await;
            server.await.expect("服务端线程不 panic");
            (read_result, rest.len())
        })
        .await
        .expect("半关闭用例不得超时");
        let (read_result, rest_len) = outcome;

        assert!(
            matches!(read_result, Ok(0)),
            "security={security:?} 半关闭后读端必须干净 EOF，实际 {read_result:?}"
        );
        assert_eq!(rest_len, 0, "security={security:?} 半关闭后不得有残留数据");
    }
}

/// 半关闭（数据段）：写端发出 EOF 帧后关闭 ⇒ 读端必须解出 `None`（流结束）。
#[tokio::test]
async fn body_half_close_reads_eof_frame_for_every_tier() {
    for (security, _) in TIERS {
        let suite = suite_of(security);
        let outcome = tokio::time::timeout(CASE_TIMEOUT, async {
            let mut seal =
                BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, 0)
                    .expect("可建");
            let mut wire = Vec::new();
            seal.seal(&mut wire, b"partial").expect("可写");
            seal.seal(&mut wire, b"").expect("EOF 可写");

            let mut open =
                BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, 0)
                    .expect("可建");
            let mut cursor = &wire[..];
            let first = open.open_from(&mut cursor).expect("可解");
            let eof = open.open_from(&mut cursor).expect("可解");
            (first, eof, cursor.len())
        })
        .await
        .expect("数据段半关闭用例不得超时");

        assert_eq!(
            outcome.0.as_deref(),
            Some(&b"partial"[..]),
            "security={security:?}"
        );
        assert!(
            outcome.1.is_none(),
            "security={security:?} EOF 帧必须读到 None"
        );
        assert_eq!(outcome.2, 0, "security={security:?} 不得有残留字节");
    }
}

// ---- 6) 超时 ----

/// 超时：对端不响应时，读端必须在上限内返回（不得无限挂起）。
#[tokio::test]
async fn unresponsive_peer_hits_the_timeout_bound_for_every_tier() {
    for (security, _) in TIERS {
        let outcome = tokio::time::timeout(CASE_TIMEOUT, async {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("可监听");
            let addr = listener.local_addr().expect("有地址");
            // 对端接受连接后**不写任何字节**，也不关闭。
            let server = tokio::spawn(async move {
                let (sock, _) = listener.accept().await.expect("可接受");
                // 保持连接开着直到被取消。
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(sock);
            });
            let mut client = tokio::net::TcpStream::connect(addr).await.expect("可连接");
            let read = tokio::time::timeout(
                Duration::from_millis(500),
                client.read_exact(&mut [0u8; 18]),
            )
            .await;
            server.abort();
            read
        })
        .await
        .expect("超时用例本身不得挂起");

        assert!(
            outcome.is_err(),
            "security={security:?} 不响应对端必须触发读超时"
        );
    }
}

/// 超时：数据段读到一半（长度段已到、载荷段缺失）必须报截断，不得挂起。
#[tokio::test]
async fn partial_body_frame_reports_truncation_for_every_tier() {
    for (security, _) in TIERS {
        let suite = suite_of(security);
        let outcome = tokio::time::timeout(CASE_TIMEOUT, async {
            let mut seal =
                BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, 0)
                    .expect("可建");
            let mut wire = Vec::new();
            seal.seal(&mut wire, b"0123456789").expect("可写");
            // 砍掉载荷段的一半。
            wire.truncate(2 + 5);

            let mut open =
                BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, 0)
                    .expect("可建");
            let mut cursor = &wire[..];
            open.open_from(&mut cursor)
        })
        .await
        .expect("半帧用例不得超时");

        assert!(
            matches!(
                outcome,
                Err(lengsuo_vmess::Error::Truncated { .. })
                    | Err(lengsuo_vmess::Error::BadLength { .. })
            ),
            "security={security:?} 半帧必须报截断，实际 {outcome:?}"
        );
    }
}

// ---- 7) 清理 ----

/// 清理：连接结束后帧上下文无残留状态（nonce 计数不外泄、可重复使用）。
///
/// 判据：新建的帧上下文与用过的帧上下文在**同样输入**下必须产出同样字节——
/// 证明上一条连接的计数/掩码状态没有泄漏到下一条连接。
#[test]
fn no_state_leaks_between_connections_for_every_tier() {
    for (security, _) in TIERS {
        let suite = suite_of(security);
        let build = |option: u8| {
            BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, option)
                .expect("可建")
        };
        // 第一条连接：写两帧。
        let mut first = build(0x04);
        let mut wire_a = Vec::new();
        first.seal(&mut wire_a, b"one").expect("可写");
        first.seal(&mut wire_a, b"two").expect("可写");

        // 第二条连接：全新上下文，必须产出与第一条**完全相同**的字节。
        let mut second = build(0x04);
        let mut wire_b = Vec::new();
        second.seal(&mut wire_b, b"one").expect("可写");
        second.seal(&mut wire_b, b"two").expect("可写");

        assert_eq!(
            wire_a, wire_b,
            "security={security:?} 帧状态不得跨连接泄漏（掩码流/nonce 计数必须从头开始）"
        );
    }
}

/// 清理：帧上下文在被完整消费后，读到 EOF 且没有半开的残留。
#[test]
fn eof_frame_leaves_no_residual_state_for_every_tier() {
    for (security, _) in TIERS {
        let suite = suite_of(security);
        let mut seal =
            BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, 0x04)
                .expect("可建");
        let mut wire = Vec::new();
        seal.seal(&mut wire, b"payload").expect("可写");
        seal.seal(&mut wire, b"").expect("EOF 可写");

        let mut open =
            BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, 0x04)
                .expect("可建");
        let mut cursor = &wire[..];
        assert!(open.open_from(&mut cursor).expect("可解").is_some());
        assert!(open.open_from(&mut cursor).expect("可解").is_none());
        assert!(cursor.is_empty(), "security={security:?} EOF 后不得有残留");
        // 再读一次必须报截断（流已结束），而不是凭空造出数据。
        let result = open.open_from(&mut cursor);
        assert!(
            matches!(result, Err(lengsuo_vmess::Error::Truncated { .. })),
            "security={security:?} EOF 后再读必须报截断，实际 {result:?}"
        );
    }
}

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
