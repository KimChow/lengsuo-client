//! 逐安全档的异常矩阵（每档 × 每场景一条具名用例 + 明确断言）。
//!
//! 与既有 `tests/security_matrix.rs` 的区别：那一份是**循环**里跑同一组场景
//! （一个用例覆盖三档），本文件是**逐档具名**（`tier_none_*` / `tier_aes128gcm_*` /
//! `tier_chacha20poly1305_*`），便于 CI 里按档定位失败。
//!
//! 语义基线：Xray commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//! 参考事实（只读）：
//! - 安全档只作用于**数据段**：`proxy/vmess/encoding/server.go:264` 的
//!   `switch request.Security`；请求头两段 AEAD 恒 AES-128-GCM
//!   （`proxy/vmess/aead/encrypt.go` 写死 `crypto.NewAesGcm`）。
//! - `SecurityType_NONE` 走 `buf.NewReader(reader)`（`server.go:265-283`），
//!   **无 AEAD、无认证** ⇒ 明文篡改不可检出，这是参考的既定语义。
//! - 载荷 AEAD 认证失败 ⇒ 参考 `common/crypto/auth.go:readInternal` 返回错误，
//!   连接被断开（fail-closed）。

/// 宏：为一个档位生成 4 条具名用例（篡改 / 重放 / 截断 / 半关闭）。
///
/// 用宏而不是循环，是为了**用例名带档位**（CI 按名字定位），且每条用例体
/// 独立（一条失败不掩盖其它档）。
macro_rules! tier_cases {
    ($mod_name:ident, $tier:expr) => {
        mod $mod_name {
            use std::time::Duration;

            use super::super::common::*;
            use lengsuo_vmess::bodyframe::BodySuite;
            use lengsuo_vmess::server::{decode_request_header, HeaderDecodeError};
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            use tokio::net::TcpListener;

            /// 本模块的档位。
            const TIER: Tier = $tier;

            /// 被篡改的载荷（常量切片，便于取长度）。
            const PAYLOAD: &[u8] = b"tier-body-payload";

            /// 档位声明必须落在**真正封出去的那条线**上。
            ///
            /// ⛔ 不能只断言 `TIER.option.to_byte()`（那是断言枚举映射函数，
            /// 不是断言发出去的字节）。这里解**已封装的线上字节**，
            /// 读明文第 35 字节的 security 低 4 位，断言它就是本档。
            #[test]
            fn tier_security_byte_is_serialized_on_the_wire() {
                let wire = seal_request(TIER.option);
                assert_eq!(
                    wire_security_nibble(&wire),
                    TIER.wire,
                    "档位 {}：线上请求头解出的 security 字节必须是 {}",
                    TIER.name,
                    TIER.wire
                );
                // 明文层同样自洽（构造路径与线上路径一致）。
                assert_eq!(
                    serialized_security_nibble(&plan_header(TIER.option)),
                    TIER.wire,
                    "档位 {}：请求头明文的 security 字节必须是 {}",
                    TIER.name,
                    TIER.wire
                );
            }

            /// 错密码（cmd key 不匹配）⇒ 头部必须被拒，且不得返回任何明文。
            ///
            /// 对齐参考 `proxy/vmess/encoding/server.go:171-176`：
            /// `GetAEAD` 找不到用户 ⇒ `invalid user`。
            #[test]
            fn tier_wrong_password_is_rejected() {
                let wire = seal_request(TIER.option);
                let wrong_key: [u8; 16] = *b"wrong-password--";
                let mut cursor = &wire[..];
                let mut session = accept_session();
                let result = decode_request_header(&[wrong_key], &mut cursor, NOW, &mut session);
                assert!(
                    matches!(result, Err(HeaderDecodeError::InvalidUser)),
                    "档位 {}：错密码必须 InvalidUser，实际 {:?}",
                    TIER.name,
                    result.map(|_| ())
                );
            }

            /// 篡改：请求头 AuthID（AAD）+ 数据段载荷密文 ⇒ 必须 fail-closed。
            #[test]
            fn tier_tampering_is_rejected() {
                // (1) 改 AuthID（AAD）⇒ 长度段 tag 失败 ⇒ InvalidUser。
                {
                    let mut wire = seal_request(TIER.option);
                    wire[0] ^= 0x01;
                    let mut cursor = &wire[..];
                    let mut session = accept_session();
                    let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session);
                    assert!(
                        matches!(result, Err(HeaderDecodeError::InvalidUser)),
                        "改 AuthID 必须 invalid user，实际 {:?}",
                        result.map(|_| ())
                    );
                }
                // (2) 数据段载荷密文篡改 ⇒ AuthFailed（none 档除外，见下）。
                {
                    let mut wire = seal_body(TIER.suite, PAYLOAD);
                    let last = wire.len() - 1;
                    wire[last] ^= 0x01;
                    let mut frame = TIER.body_frame();
                    let mut cursor = &wire[..];
                    let result = frame.open_from(&mut cursor);
                    if TIER.suite == BodySuite::None {
                        // 参考 NONE 档无 AEAD ⇒ 明文篡改不可检出（既定语义，
                        // `proxy/vmess/encoding/server.go:265-283`）。
                        // 但长度必须仍然自洽（解出的明文长度 = 篡改后长度），
                        // 且不得被误判成 EOF 帧。
                        let plain = result
                            .expect("none 档可解（无认证）")
                            .expect("none 档必须解出载荷帧（不得是 EOF 帧）");
                        assert_eq!(plain.len(), PAYLOAD.len());
                    } else {
                        assert!(
                            matches!(result, Err(lengsuo_vmess::Error::AuthFailed)),
                            "篡改载荷必须 AuthFailed，实际 {result:?}"
                        );
                    }
                }
            }

            /// 重放：同一 AuthID 二次出现 ⇒ 第二次必须 Replay。
            #[test]
            fn tier_replayed_session_is_rejected() {
                let wire = seal_request(TIER.option);
                let mut calls = 0usize;
                let mut filter = |_: &[u8; 16], _: &[u8; 16], _: &[u8; 16]| {
                    calls += 1;
                    calls == 1
                };
                {
                    let mut cursor = &wire[..];
                    let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut filter);
                    assert!(
                        result.is_ok(),
                        "首次必须通过，实际 {:?}",
                        result.map(|_| ())
                    );
                }
                {
                    let mut cursor = &wire[..];
                    let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut filter);
                    assert!(
                        matches!(result, Err(HeaderDecodeError::Replay)),
                        "重放必须 Replay，实际 {:?}",
                        result.map(|_| ())
                    );
                }
            }

            /// 截断：头部 / 长度段 / 载荷段 / 数据段各截一处 ⇒ 必须报错。
            #[test]
            fn tier_truncation_is_rejected() {
                let wire = seal_request(TIER.option);
                // (1) 头部截断（AuthID 之后不足长度段+nonce）。
                {
                    let mut cursor = &wire[..20];
                    let mut session = accept_session();
                    let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session);
                    assert!(result.is_err(), "头部截断必须失败");
                }
                // (2) 长度段截断。
                {
                    let mut cursor = &wire[..16 + 10];
                    let mut session = accept_session();
                    let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session);
                    assert!(result.is_err(), "长度段截断必须失败");
                }
                // (3) 载荷段截断（砍掉尾部 8 字节）。
                {
                    let mut cursor = &wire[..wire.len() - 8];
                    let mut session = accept_session();
                    let result = decode_request_header(&[CMD_KEY], &mut cursor, NOW, &mut session);
                    assert!(result.is_err(), "载荷段截断必须失败");
                }
                // (4) 数据段半帧（长度段已到、载荷段缺失）⇒ 报截断。
                {
                    let mut body = seal_body(TIER.suite, b"0123456789");
                    body.truncate(2 + 5);
                    let mut frame = TIER.body_frame();
                    let mut cursor = &body[..];
                    let result = frame.open_from(&mut cursor);
                    assert!(
                        matches!(
                            result,
                            Err(lengsuo_vmess::Error::Truncated { .. })
                                | Err(lengsuo_vmess::Error::BadLength { .. })
                        ),
                        "半帧必须报截断，实际 {result:?}"
                    );
                }
            }

            /// 半关闭：写端关闭后读端必须干净 EOF（不挂起、无残留）。
            #[tokio::test]
            async fn tier_half_close_yields_clean_eof() {
                let outcome = tokio::time::timeout(CASE_TIMEOUT, async {
                    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("可监听");
                    let addr = listener.local_addr().expect("有地址");
                    let wire = seal_request(TIER.option);
                    let server = tokio::spawn(async move {
                        let (mut sock, _) = listener.accept().await.expect("可接受");
                        let mut buf = [0u8; 64];
                        let _ = sock.read(&mut buf).await;
                        let _ = sock.shutdown().await;
                    });
                    let mut client = tokio::net::TcpStream::connect(addr).await.expect("可连接");
                    client.write_all(&wire).await.expect("可写");
                    let _ = client.shutdown().await;
                    let mut rest = Vec::new();
                    let read_result = client.read_to_end(&mut rest).await;
                    server.await.expect("服务端不 panic");
                    (read_result, rest.len())
                })
                .await
                .expect("半关闭用例不得超时");
                let (read_result, rest_len) = outcome;
                assert!(
                    matches!(read_result, Ok(0)),
                    "半关闭后读端必须干净 EOF，实际 {read_result:?}"
                );
                assert_eq!(rest_len, 0, "半关闭后不得有残留数据");
            }

            /// 超时：对端不响应时，读端必须在上限内返回（不得无限挂起）。
            ///
            /// 对齐参考 `proxy/vmess/encoding/server.go` 的
            /// `DecodeRequestHeader` 走 `buf.ReadFullFrom`（阻塞读，不自设超时）
            /// ⇒ 超时是**连接层**策略；本仓原语层只保证「读不满就报错」，
            /// 断言的是「读端在有界时间内拿到结果，不挂死」。
            #[tokio::test]
            async fn tier_unresponsive_peer_hits_the_timeout_bound() {
                let outcome = tokio::time::timeout(CASE_TIMEOUT, async {
                    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("可监听");
                    let addr = listener.local_addr().expect("有地址");
                    // 对端接受连接后**不写任何字节**，也不关闭。
                    let server = tokio::spawn(async move {
                        let (sock, _) = listener.accept().await.expect("可接受");
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        drop(sock);
                    });
                    let mut client = tokio::net::TcpStream::connect(addr).await.expect("可连接");
                    // 只发 AuthID（16B），后续字节不发 ⇒ 读端必然等不满。
                    let wire = seal_request(TIER.option);
                    client.write_all(&wire[..16]).await.expect("可写 AuthID");
                    let _ = client.flush().await;
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
                    "档位 {}：不响应对端必须触发读超时",
                    TIER.name
                );
            }

            /// 状态不外泄：两条连接的数据段上下文必须产出**完全相同**的字节。
            #[test]
            fn tier_frame_state_does_not_leak_between_connections() {
                let build = || TIER.body_frame();
                let mut first = build();
                let mut wire_a = Vec::new();
                first.seal(&mut wire_a, b"one").expect("可写");
                first.seal(&mut wire_a, b"two").expect("可写");

                let mut second = build();
                let mut wire_b = Vec::new();
                second.seal(&mut wire_b, b"one").expect("可写");
                second.seal(&mut wire_b, b"two").expect("可写");

                assert_eq!(
                    wire_a, wire_b,
                    "帧状态不得跨连接泄漏（nonce 计数 / 掩码流必须从头开始）"
                );
            }
        }
    };
}

tier_cases!(
    tier_none,
    Tier {
        name: "none",
        option: lengsuo_vmess::request::SecurityOption::None,
        suite: BodySuite::None,
        wire: 5,
    }
);
tier_cases!(
    tier_aes128gcm,
    Tier {
        name: "aes128gcm",
        option: lengsuo_vmess::request::SecurityOption::Aes128Gcm,
        suite: BodySuite::Aes128Gcm,
        wire: 3,
    }
);
tier_cases!(
    tier_chacha20poly1305,
    Tier {
        name: "chacha20poly1305",
        option: lengsuo_vmess::request::SecurityOption::ChaCha20Poly1305,
        suite: BodySuite::ChaCha20Poly1305,
        wire: 4,
    }
);

/// 让文件级导入不报未使用（宏内部有自己的 `use`）。
#[allow(dead_code)]
fn _file_level_imports_are_used() {}
