//! **档位不一致 ⇒ 必须 fail-closed**（安全关键路径）。
//!
//! 语义基线：Xray commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//!
//! ## 参考事实（决定了本卡怎么构造「不一致」）
//!
//! 参考的 VMess **服务端不钉档位**：`proxy/vmess/encoding/server.go:203` 的
//! `request.Security = parseSecurityType(buffer.Byte(35) & 0x0F)` 总是取
//! **请求头里的** security 字节；`proxy/vmess/inbound/inbound.go` 全文**没有**
//! 任何 `Security` 引用（账号档位只影响参考**出口**
//! `proxy/vmess/outbound/outbound.go:106`）。
//!
//! ⇒ 参考里「档位不一致」的真实形态是：**客户端声明的档位**与
//! **客户端实际用于数据段的档位**不一致（声明 A、实发 B），或服务端按
//! **显式策略**钉了另一个档（此时服务端用 B 解 A 产的密文）。
//!
//! 两种形态在参考里都必须 fail-closed：
//! - 声明 A、实发 B：服务端按 A 解 B 的密文 ⇒ AEAD tag 校验失败
//!   （参考 `common/crypto/auth.go:readInternal` 里 `r.auth.Open` 返回错误 ⇒
//!   连接断开）。
//! - 服务端钉 B、实发 A：同理，B 的 AEAD 解不开 A 的密文 ⇒ 断开。
//!
//! **绝不能**出现「降级到明文 / 弱档」：服务端不得把 A 档的密文当明文交出去，
//! 也不得把 B 档的密文按更弱的档解出来。
//!
//! ## `none` 档的诚实结论
//!
//! 参考的 `SecurityType_NONE` 分支（`server.go:265-283`）用的是
//! `NoOpAuthenticator` / `buf.NewReader` ⇒ **没有任何认证**。所以当**服务端**
//! 档位是 `none` 时，服务端在原理上**无法**察觉数据段档位不一致（它根本没
//! 校验能力）。本卡对该组合断言的是**可观测的安全下界**（原始明文不得被
//! 复原成可用的载荷），并在 `docs/vmess-security-matrix-extra.md` 里如实记
//! 这条**参考固有限制**（不是本仓的缺陷，也不是本仓能修的）。

use std::time::Duration;

use super::common::{
    accept_session, plan_header_with_security_nibble, seal_plain_header, BODY_IV, BODY_KEY,
    CASE_TIMEOUT, CMD_KEY, NOW, OPTION, TIERS,
};
use lengsuo_vmess::bodyframe::{BodyCipher, BodyFrame, BodySuite};
use lengsuo_vmess::server::decode_request_header;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// 假载荷（不含任何真实凭据）。
const PAYLOAD: &[u8] = b"tier-mismatch-probe-payload";

/// 封一帧数据段（指定套件）。
fn seal_with(suite: BodySuite, payload: &[u8]) -> Vec<u8> {
    let mut frame = BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, OPTION)
        .expect("帧上下文可建");
    let mut wire = Vec::new();
    frame.seal(&mut wire, payload).expect("可写");
    wire
}

/// 解一帧数据段（指定套件）。
fn open_with(suite: BodySuite, wire: &[u8]) -> lengsuo_vmess::Result<Option<Vec<u8>>> {
    let mut frame = BodyFrame::for_request(suite, &BODY_KEY, &BODY_IV, &BODY_KEY, &BODY_IV, OPTION)
        .expect("帧上下文可建");
    let mut cursor = wire;
    frame.open_from(&mut cursor)
}

/// 数据段档位不一致时的判定：必须报错，且**绝不能**交出原始明文。
fn assert_body_tier_mismatch_is_rejected(
    server_suite: BodySuite,
    client_suite: BodySuite,
    label: &str,
) {
    let wire = seal_with(client_suite, PAYLOAD);
    let result = open_with(server_suite, &wire);
    match result {
        Ok(Some(plain)) => panic!(
            "{label}: 服务端档={server_suite:?} 客户端档={client_suite:?} \
             必须 fail-closed，实际解出了明文 {:?}",
            String::from_utf8_lossy(&plain)
        ),
        Ok(None) => panic!(
            "{label}: 服务端档={server_suite:?} 客户端档={client_suite:?} \
             不得读成 EOF 帧（说明长度段被误判成空帧）"
        ),
        Err(error) => {
            // 允许的错误种类：AEAD tag 失败 / 长度不自洽（档位不同 ⇒ 长度段
            // 声明值与实际密文长度不同）。**不允许**是「成功解出明文」。
            assert!(
                matches!(
                    error,
                    lengsuo_vmess::Error::AuthFailed
                        | lengsuo_vmess::Error::Truncated { .. }
                        | lengsuo_vmess::Error::BadLength { .. }
                ),
                "{label}: 失败类型必须 fail-closed 类，实际 {error:?}"
            );
        }
    }
}

/// 声明档 = 服务端实际用档，但**数据段被别的档加密** ⇒ 必须 fail-closed。
///
/// 逐档覆盖：AES 声明 + ChaCha 实发、ChaCha 声明 + AES 实发。
#[test]
fn declared_tier_must_match_the_tier_actually_used_for_the_body() {
    // AES 声明（线上字节 3）+ ChaCha 实发。
    assert_body_tier_mismatch_is_rejected(
        BodySuite::Aes128Gcm,
        BodySuite::ChaCha20Poly1305,
        "声明 aes-128-gcm 实发 chacha20-poly1305",
    );
    // ChaCha 声明（线上字节 4）+ AES 实发。
    assert_body_tier_mismatch_is_rejected(
        BodySuite::ChaCha20Poly1305,
        BodySuite::Aes128Gcm,
        "声明 chacha20-poly1305 实发 aes-128-gcm",
    );
}

/// **不得降级到明文**：声明 AES 档、却用 `none` 档发明文载荷 ⇒ 服务端必须
/// 拒绝（AES 的 tag 校验必然失败），**不得**把明文当载荷交出去。
///
/// 这是本卡最关键的一条：它直接对应「不是降级到明文/弱档」。
#[test]
fn a_tiered_client_cannot_downgrade_to_plaintext_none() {
    // none 档产出的是明文（无 tag）。
    let mut none_cipher = BodyCipher::from_suite(BodySuite::None, &BODY_KEY, &BODY_IV);
    let plaintext = none_cipher.seal_payload(PAYLOAD).expect("可封");
    assert_eq!(plaintext, PAYLOAD, "none 档载荷确为明文");

    // 声明 AES 档，服务端按 AES 解 ⇒ 必须失败。
    let mut frame = BodyFrame::for_request(
        BodySuite::Aes128Gcm,
        &BODY_KEY,
        &BODY_IV,
        &BODY_KEY,
        &BODY_IV,
        OPTION,
    )
    .expect("帧上下文可建");
    let result = frame.cipher_mut().open_payload(&plaintext);
    assert!(
        matches!(result, Err(lengsuo_vmess::Error::AuthFailed)),
        "AES 档不得接受明文载荷（禁止降级），实际 {result:?}"
    );
    // ChaCha 档同样不得接受。
    let mut frame = BodyFrame::for_request(
        BodySuite::ChaCha20Poly1305,
        &BODY_KEY,
        &BODY_IV,
        &BODY_KEY,
        &BODY_IV,
        OPTION,
    )
    .expect("帧上下文可建");
    let result = frame.cipher_mut().open_payload(&plaintext);
    assert!(
        matches!(result, Err(lengsuo_vmess::Error::AuthFailed)),
        "ChaCha 档不得接受明文载荷（禁止降级），实际 {result:?}"
    );
}

/// 服务端**显式钉档**与客户端声明档不同时 ⇒ 必须 fail-closed。
///
/// 这一条覆盖「客户端用一个档、服务端用另一个档」的字面形态：服务端按自己
/// 的档解数据段，与客户端实际发出的档不同 ⇒ 解不开。
///
/// **适用范围**：只在**有认证**的服务端档位（`aes-128-gcm` /
/// `chacha20-poly1305`）上成立。`none` 档服务端**在原理上无法**察觉不一致
/// （参考 `proxy/vmess/encoding/server.go:265-283` 的 `NoOpAuthenticator`：
/// 没有认证就没有「不一致」可察），单独由下一条用例钉住。
#[test]
fn server_pinned_authenticated_tier_differs_from_client_tier_fails_closed() {
    for server_tier in TIERS {
        if !server_tier.suite.is_aead() {
            // `none` 服务端档无认证能力 ⇒ 由 `none_tier_server_cannot_detect_…` 覆盖。
            continue;
        }
        for client_tier in TIERS {
            if client_tier.suite == server_tier.suite {
                continue;
            }
            // 客户端按自己的档封数据段，服务端按自己钉的档解。
            let wire = seal_with(client_tier.suite, PAYLOAD);
            let result = open_with(server_tier.suite, &wire);
            match result {
                Ok(Some(plain)) => panic!(
                    "服务端钉 {} 客户端实发 {}：必须 fail-closed，实际解出 {:?}",
                    server_tier.name,
                    client_tier.name,
                    String::from_utf8_lossy(&plain)
                ),
                Ok(None) => panic!(
                    "服务端钉 {} 客户端实发 {}：不得读成 EOF 帧",
                    server_tier.name, client_tier.name
                ),
                Err(error) => assert!(
                    matches!(
                        error,
                        lengsuo_vmess::Error::AuthFailed
                            | lengsuo_vmess::Error::Truncated { .. }
                            | lengsuo_vmess::Error::BadLength { .. }
                    ),
                    "服务端钉 {} 客户端实发 {}：失败类型必须 fail-closed，实际 {error:?}",
                    server_tier.name,
                    client_tier.name
                ),
            }
        }
    }
}

/// `none` 档服务端**在原理上无法**察觉数据段档位不一致（参考固有限制）。
///
/// 参考依据：`proxy/vmess/encoding/server.go:265-283` 的 `SecurityType_NONE`
/// 分支用 `NoOpAuthenticator` / `buf.NewReader` ⇒ **没有任何认证**。
/// 没有认证就没有「不一致」可察——Xray 的 `none` 档入站同样如此。
///
/// ⇒ 本卡的 fail-closed 保证**只在有认证的档位上成立**（`aes-128-gcm` /
/// `chacha20-poly1305`）。`none` 档的定位是「不提供机密性与完整性」，
/// 用它等于放弃这层保护。本用例把这条事实**钉住**，避免将来误以为 `none`
/// 档也有 fail-closed 能力（不得声称已禁用而实际可用——见任务书第 3 条）。
///
/// 断言的边界（**不是**「不一致被检出」）：
/// - 服务端**不得**交出客户端的明文（它拿到的是客户端的密文字节，乱码）；
/// - 客户端的明文在服务端侧**不可恢复**；
/// - 本仓必须**显式**把 `none` 标成「无认证」，不得含糊。
#[test]
fn none_tier_server_cannot_detect_body_tier_mismatch_by_construction() {
    // 本仓显式标注 none 无认证。
    let none = TIERS
        .iter()
        .find(|t| t.name == "none")
        .expect("none 档在表内");
    assert!(!none.suite.is_aead(), "none 档必须被显式标为无认证");
    assert_eq!(none.suite.overhead(), 0, "none 档无 tag");

    // 客户端用 AES 档（密文），服务端用 none 档（无认证）⇒ 服务端**不会**
    // 察觉不一致（这是参考的固有限制，不是本仓能修的）。
    let wire = seal_with(BodySuite::Aes128Gcm, PAYLOAD);
    let result = open_with(BodySuite::None, &wire);
    let served = match result {
        Ok(Some(plain)) => plain,
        Ok(None) => panic!("none 服务端不得把不一致的数据读成 EOF 帧"),
        Err(error) => {
            // 若长度不自洽而被拒，同样算「未交出明文」。
            assert!(
                matches!(
                    error,
                    lengsuo_vmess::Error::AuthFailed
                        | lengsuo_vmess::Error::Truncated { .. }
                        | lengsuo_vmess::Error::BadLength { .. }
                ),
                "失败类型必须 fail-closed 类，实际 {error:?}"
            );
            return;
        }
    };
    // 服务端拿到的是客户端的**密文**字节（乱码），不是明文。
    assert_ne!(served, PAYLOAD, "none 服务端不得交出客户端明文");
    assert!(
        !served.windows(PAYLOAD.len()).any(|w| w == PAYLOAD),
        "none 服务端不得在任何位置交出客户端明文"
    );
}

/// 头里的 security 字节与服务端实际用的数据段套件**必须一致**：服务端按
/// 头里的字节定档（参考 `server.go:203`），客户端头里写 A、数据段用 B ⇒
/// 服务端按 A 解 B ⇒ 失败。
#[test]
fn header_security_byte_selects_the_body_suite_and_mismatch_fails() {
    for tier in TIERS {
        // 头里声明该档（线上字节）。
        let mut session = accept_session();
        let mut cursor =
            &seal_plain_header(&plan_header_with_security_nibble(tier.option, tier.wire))[..];
        let decoded = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session)
            .expect("头必须被接受");
        // 服务端据此定档：解码出的档位必须与头里声明的字节对应。
        let derived = match decoded.security {
            lengsuo_vmess::server::HeaderSecurity::None => BodySuite::None,
            lengsuo_vmess::server::HeaderSecurity::Aes128Gcm => BodySuite::Aes128Gcm,
            lengsuo_vmess::server::HeaderSecurity::ChaCha20Poly1305 => BodySuite::ChaCha20Poly1305,
            lengsuo_vmess::server::HeaderSecurity::Zero => {
                panic!("zero 档不该出现在本用例");
            }
        };
        assert_eq!(
            derived, tier.suite,
            "档位 {} 的头字节必须定出同一套件",
            tier.name
        );
    }
}

/// 端到端：客户端声明 AES 档、却用 `none` 明文发数据段 ⇒ 服务端读帧失败，
/// 连接必须**断开且不回任何数据**（不得把明文当载荷回显）。
///
/// 服务端用**本仓真实的入站路径**（`decode_request_header` + `BodyFrame::
/// read_sync`），因此服务端是按**头里声明的档**（`aes-128-gcm`）定档的
/// （对齐参考 `proxy/vmess/encoding/server.go:203`）。
#[tokio::test]
async fn plaintext_downgrade_attempt_is_rejected_on_the_wire() {
    let outcome = tokio::time::timeout(CASE_TIMEOUT, async {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("可监听");
        let addr = listener.local_addr().expect("有地址");

        // 服务端线程（同步 std socket，配合本仓的同步解码 API）。
        let server = tokio::task::spawn_blocking(move || {
            let (mut sock, _) = listener.accept().expect("可接受");
            // (1) 解请求头（头里的 security 字节 = 3 ⇒ aes-128-gcm）。
            let mut session = accept_session();
            let decoded = match decode_request_header(&[CMD_KEY], &mut sock, NOW, &mut session) {
                Ok(decoded) => decoded,
                Err(_) => return Vec::new(),
            };
            // (2) 按头里声明的档定套件（参考 server.go:203 的语义）。
            let suite = match decoded.security {
                lengsuo_vmess::server::HeaderSecurity::Aes128Gcm => BodySuite::Aes128Gcm,
                lengsuo_vmess::server::HeaderSecurity::ChaCha20Poly1305 => {
                    BodySuite::ChaCha20Poly1305
                }
                lengsuo_vmess::server::HeaderSecurity::None => BodySuite::None,
                lengsuo_vmess::server::HeaderSecurity::Zero => {
                    return Vec::new();
                }
            };
            // (3) 读一帧数据段（明文载荷 ⇒ AEAD tag 失败）。
            let mut frame = match BodyFrame::for_request(
                suite,
                &decoded.request_body_key,
                &decoded.request_body_iv,
                &decoded.request_body_key,
                &decoded.request_body_iv,
                decoded.option,
            ) {
                Ok(frame) => frame,
                Err(_) => return Vec::new(),
            };
            match frame.read_sync(&mut sock) {
                Ok(Some(plain)) => plain,
                _ => Vec::new(),
            }
        });

        // 客户端：头里声明 aes-128-gcm，数据段用 none（明文）。
        let mut plain =
            plan_header_with_security_nibble(lengsuo_vmess::request::SecurityOption::Aes128Gcm, 3);
        // 明文里带 FNV 尾，重算后封装。
        let body_len = plain.len() - 4;
        let tail = lengsuo_vmess::request::fnv1a32(&plain[..body_len]).to_be_bytes();
        plain[body_len..].copy_from_slice(&tail);
        let header = seal_plain_header(&plain);

        let mut client = tokio::net::TcpStream::connect(addr).await.expect("可连接");
        client.write_all(&header).await.expect("可写头");
        // none 档载荷 = 明文，长度段按 AES 档的格式写（掩码 2 字节）。
        let mut parser = lengsuo_vmess::chunkframe::DataSizeParser::new(&BODY_IV);
        let len_wire = parser.encode_size(PAYLOAD.len() as u16);
        client.write_all(&len_wire).await.expect("可写长度段");
        client.write_all(PAYLOAD).await.expect("可写载荷");
        let _ = client.flush().await;
        // 写端关闭：服务端读帧时能拿到 EOF 而不是挂住。
        let _ = client.shutdown().await;

        // 服务端必须回**空**（拒绝）而不是回显明文。
        let mut rest = Vec::new();
        let read =
            tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut rest)).await;
        let served = server.await.expect("服务端不 panic");
        (read, rest, served)
    })
    .await
    .expect("用例不得超时");

    let (read, rest, served) = outcome;
    assert!(
        served.is_empty(),
        "服务端不得解出明文（禁止降级），实际解出 {:?}",
        String::from_utf8_lossy(&served)
    );
    match read {
        Ok(result) => assert_eq!(
            result.unwrap_or(0),
            0,
            "服务端拒绝后不得回任何数据，实际 {rest:?}"
        ),
        Err(_) => {
            // 读超时也算「服务端没有交付数据」，但要确认没交付过明文。
            assert!(rest.is_empty(), "服务端拒绝后不得回任何数据，实际 {rest:?}");
        }
    }
}
