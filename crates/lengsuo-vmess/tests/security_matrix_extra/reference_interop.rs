//! 与**真实 Xray** 的档位互通取证（`#[ignore]`，需 `LENGSUO_XRAY`）。
//!
//! 语义基线：Xray commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//!
//! 运行方式：
//! ```text
//! LENGSUO_XRAY=~/ref/bin/xray cargo test -p lengsuo-vmess \
//!     --test security_matrix_extra --locked -- --ignored --nocapture
//! ```
//!
//! ## 为什么需要它
//!
//! 本卡的「档位不一致 ⇒ fail-closed」在**纯本仓**测试里只能证明本仓自己的
//! 两端自洽。要证明**与参考一致**，必须有参考实跑证据：
//!
//! 1. **逐档互通**：本仓客户端 → Xray 入站，三档各跑一遍，回程载荷逐字节一致
//!    （证明本仓的档位语义与参考的 `switch request.Security` 一致）。
//! 2. **降级不可行**：把本仓客户端的**数据段**换成 `none` 明文，但**头里声明**
//!    `aes-128-gcm`，打给 Xray 入站 ⇒ Xray 必须**拒绝**（不回数据）。
//!    这条直接验证「档位不一致必须握手失败，不是降级到明文」。
//!
//! ## 参考依据
//!
//! - `proxy/vmess/encoding/server.go:203`：服务端按**请求头**的 security 字节
//!   定档（`parseSecurityType`）⇒ 头里声明 AES、数据段发明文 ⇒ 按 AES 解 ⇒
//!   `common/crypto/auth.go:readInternal` 的 `r.auth.Open` 失败 ⇒ 连接断开。
//! - `proxy/vmess/encoding/server.go:242-243`：`UNKNOWN` / `AUTO` ⇒ 头阶段拒。
//! - `proxy/vmess/encoding/server.go:323`：`ZERO` 等其余档 ⇒ 体阶段
//!   `invalid option: Security`。

use std::time::Duration;

use lengsuo_vmess::aead;
use lengsuo_vmess::bodyframe::{BodyFrame, BodySuite, ChunkStreamFrame};
use lengsuo_vmess::chunkframe::DataSizeParser;
use lengsuo_vmess::request::{KeySource, SecurityOption};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use super::refharness::{
    plan_request_header, start_xray_inbound, xray_bin, CONNECT_TIMEOUT, PAYLOAD, RESPONSE_TIMEOUT,
};
use super::refhelpers::{cmd_key_from_uuid, response_key_iv, spawn_echo, uuid_bytes, uuid_string};

/// 本仓客户端 → Xray 入站 → 本地回显后端：回程载荷必须逐字节一致。
///
/// 逐档跑（`none` / `aes-128-gcm` / `chacha20-poly1305`）。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn every_tier_roundtrips_against_real_xray() {
    let Some(bin) = xray_bin() else { return };

    let uuid_bytes = uuid_bytes();
    let uuid = uuid_string(&uuid_bytes);
    let cmd_key = cmd_key_from_uuid(&uuid_bytes);
    let (echo_addr, echo_handle) = spawn_echo().await;

    // 参考的入站**不看**账号档位（`proxy/vmess/inbound/inbound.go` 全文无
    // `Security` 引用）⇒ 一个入站即可服务三档；档位由**请求头**决定
    // （`proxy/vmess/encoding/server.go:203`）。
    let (port, mut child) = match start_xray_inbound(&bin, &uuid) {
        Ok(v) => v,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败");
        }
    };

    for (tier, option) in [
        ("none", 0x01u8 | 0x04),
        ("aes-128-gcm", 0x01 | 0x04 | 0x08),
        ("chacha20-poly1305", 0x01 | 0x04 | 0x08),
    ] {
        let keys = KeySource::generate().expect("生成会话密钥");
        let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());
        let security = match tier {
            "none" => SecurityOption::None,
            "aes-128-gcm" => SecurityOption::Aes128Gcm,
            _ => SecurityOption::ChaCha20Poly1305,
        };
        let plain = plan_request_header(&keys, target, security, option);
        let header = aead::seal_vmess_aead_header(&cmd_key, &plain).expect("请求头可封");

        let mut stream =
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(("127.0.0.1", port)))
                .await
                .expect("连接不超时")
                .expect("可连接");
        let echoed = tokio::time::timeout(RESPONSE_TIMEOUT, async {
            stream.write_all(&header).await.expect("可写头");
            if tier == "none" {
                // 参考 NONE 分支：chunk-stream（明文载荷、无 padding）。
                let mut frame = ChunkStreamFrame::with_iv(option, &keys.body_iv);
                frame
                    .write_to(&mut stream, PAYLOAD)
                    .await
                    .expect("可写载荷");
                frame.write_eof(&mut stream).await.expect("可写 EOF");
            } else {
                let suite = if tier == "aes-128-gcm" {
                    BodySuite::Aes128Gcm
                } else {
                    BodySuite::ChaCha20Poly1305
                };
                let mut frame = BodyFrame::for_request(
                    suite,
                    &keys.body_key,
                    &keys.body_iv,
                    &keys.body_key,
                    &keys.body_iv,
                    option,
                )
                .expect("帧上下文可建");
                frame
                    .write_to(&mut stream, PAYLOAD)
                    .await
                    .expect("可写载荷");
                frame.write_to(&mut stream, b"").await.expect("可写 EOF");
            }
            stream.flush().await.expect("可刷写");
            // 读响应头（38 字节）+ 响应体。
            let mut resp = [0u8; 38];
            stream.read_exact(&mut resp).await.expect("可读响应头");
            let (resp_key, resp_iv) = response_key_iv(&keys.body_key, &keys.body_iv);
            let mut out = Vec::new();
            if tier == "none" {
                let mut frame = ChunkStreamFrame::with_iv(option, &resp_iv);
                loop {
                    match frame.read_from(&mut stream).await {
                        Ok(Some(plain)) => out.extend_from_slice(&plain),
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            } else {
                let suite = if tier == "aes-128-gcm" {
                    BodySuite::Aes128Gcm
                } else {
                    BodySuite::ChaCha20Poly1305
                };
                let mut frame = BodyFrame::for_request(
                    suite,
                    &resp_key,
                    &resp_iv,
                    &keys.body_key,
                    &keys.body_iv,
                    option,
                )
                .expect("响应帧上下文可建");
                loop {
                    match frame.read_from(&mut stream).await {
                        Ok(Some(plain)) => out.extend_from_slice(&plain),
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            }
            out
        })
        .await
        .expect("回程不超时");

        assert_eq!(
            echoed,
            PAYLOAD,
            "档位 {tier} 的回程载荷必须逐字节一致（实际 {} 字节）",
            echoed.len()
        );
        eprintln!(
            "OK 档位={tier} 参考互通：回程 {} 字节逐字节一致",
            echoed.len()
        );
    }

    let _ = child.kill();
    let _ = child.wait();
    drop(echo_handle);
}

/// **档位不一致 ⇒ 参考必须拒绝**（不降级到明文）。
///
/// 头里声明 `aes-128-gcm`，数据段却用 `none` 明文 ⇒ 参考按头里的档位
/// （`server.go:203`）用 AES 解 ⇒ tag 失败 ⇒ 连接被断开、**不回数据**。
///
/// 这条是本卡安全关键路径的**参考实跑证据**。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn real_xray_rejects_tier_mismatch_instead_of_downgrading() {
    let Some(bin) = xray_bin() else { return };

    let uuid_bytes = uuid_bytes();
    let uuid = uuid_string(&uuid_bytes);
    let cmd_key = cmd_key_from_uuid(&uuid_bytes);
    let (echo_addr, echo_handle) = spawn_echo().await;

    let (port, mut child) = match start_xray_inbound(&bin, &uuid) {
        Ok(v) => v,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败");
        }
    };

    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());
    // 头里声明 aes-128-gcm。
    let plain = plan_request_header(&keys, target, SecurityOption::Aes128Gcm, 0x01 | 0x04 | 0x08);
    let header = aead::seal_vmess_aead_header(&cmd_key, &plain).expect("请求头可封");

    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(("127.0.0.1", port)))
        .await
        .expect("连接不超时")
        .expect("可连接");
    stream.write_all(&header).await.expect("可写头");
    // 数据段：用 none 档（明文载荷）——与头里声明的档**不一致**。
    let mut parser = DataSizeParser::new(&keys.body_iv);
    let len_wire = parser.encode_size(PAYLOAD.len() as u16);
    stream.write_all(&len_wire).await.expect("可写长度段");
    stream.write_all(PAYLOAD).await.expect("可写明文载荷");
    let _ = stream.flush().await;

    // 参考必须拒绝 ⇒ 读不到任何响应数据（EOF 或超时），且绝不回显明文。
    let mut rest = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
    match read {
        Ok(result) => assert_eq!(
            result.unwrap_or(0),
            0,
            "参考必须拒绝档位不一致的请求（不得回数据），实际回 {} 字节",
            rest.len()
        ),
        Err(_) => {
            // 超时 = 参考没交付任何数据；再确认没有明文回显。
            assert!(
                !rest.windows(PAYLOAD.len()).any(|w| w == PAYLOAD),
                "参考不得回显明文载荷"
            );
        }
    }
    eprintln!(
        "OK 参考拒绝档位不一致（头声明 aes-128-gcm / 数据段 none 明文）：\
         参考未回显明文（收到 {} 字节）",
        rest.len()
    );

    let _ = child.kill();
    let _ = child.wait();
    drop(echo_handle);
}
