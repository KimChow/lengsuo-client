//! **多安全档**与真实 Xray 的互通（`#[ignore]`，需 `LENGSUO_XRAY`）。
//!
//! 运行方式（缺 `LENGSUO_XRAY` 时每个用例明确打印原因并 return，不静默通过）：
//! ```text
//! LENGSUO_XRAY=~/ref/bin/xray cargo test -p lengsuo-vmess --test xray_multitier --locked -- --ignored --nocapture
//! ```
//!
//! 拓扑（方向 A：本仓客户端 → Xray 入站）：
//! ```text
//! 测试进程 --TCP--> Xray VMess 入站（security=<档位>） --freedom--> 本地回显后端
//! ```
//! 拓扑（方向 B：Xray 客户端 → 本仓入站）：
//! ```text
//! 测试进程 --SOCKS5--> Xray（SOCKS 入站 + VMess 出站，security=<档位>）
//!                --VMess--> 本仓入站夹具 --TCP--> 本地回显后端
//! ```
//!
//! 判据（每个方向、每个档位都单独跑）：
//! - 回程字节与发送载荷**逐字节一致**（不是「没报错」就算过）；
//! - 载荷覆盖 1B / 4KiB / 256KiB（跨越参考的 8192 字节单帧边界）；
//! - 全程有超时上限（连接 10s / 回程 30s），不挂死。
//!
//! **安全档只作用于数据段**（参考固定 commit `d2758a02`）：
//! `proxy/vmess/aead/encrypt.go` 的请求头与响应头两段 AEAD 恒为 AES-128-GCM；
//! 档位分派发生在 `proxy/vmess/encoding/{client,server}.go` 的
//! `switch request.Security`（数据段）。因此本文件里「档位」影响的是**载荷
//! 与长度段**，请求头两段在所有档位下都是 AES-128-GCM。
//!
//! `none` 档的特殊形态（对齐参考）：`SecurityType_NONE` + `ChunkStream` +
//! TCP ⇒ 参考走 `common/crypto/chunk.go` 的 `ChunkStreamReader/Writer`
//! （**明文**载荷、无 padding、长度段可掩码），而不是 `AuthenticationReader`。
//! 见 `lengsuo_vmess::bodyframe::ChunkStreamFrame`。

#[path = "support/mod.rs"]
mod support;

use std::path::PathBuf;
use std::time::Duration;

use lengsuo_vmess::aead;
use lengsuo_vmess::bodyframe::{BodyFrame, BodySuite, ChunkStreamFrame};
use lengsuo_vmess::request::KeySource;
use ss_core::target::TargetAddr;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;

use support::codec;
use support::tiercodec::{self, Tier};

/// 连接超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 回程超时。
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// 惰性获取参考二进制；未设置时打印原因并返回 `None`（调用方 `return` 跳过）。
fn xray_bin() -> Option<PathBuf> {
    match std::env::var_os("LENGSUO_XRAY") {
        Some(path) => Some(PathBuf::from(path)),
        None => {
            eprintln!(
                "SKIP: 环境变量 LENGSUO_XRAY 未设置，跳过多安全档互通用例。\
                 原因：没有参考二进制可拉起，无法证明 Rust↔Xray 的档位互通。"
            );
            None
        }
    }
}

/// 三段载荷：1B / 4KiB / 256KiB（跨越参考 8192 字节单帧边界）。
fn payloads() -> Vec<Vec<u8>> {
    vec![
        vec![0x2Au8],
        (0..4096).map(|i| (i % 251) as u8).collect(),
        (0..(256 * 1024)).map(|i| (i % 251) as u8).collect(),
    ]
}

/// 写一条完整的请求（头 + 数据段）并读回全部回程。
///
/// `none` 档走 chunk-stream 分帧，其余档位走 AEAD 认证分帧
/// （参考 `SecurityType_NONE` 分支的差别，见模块文档）。
async fn roundtrip_tier(
    tier: Tier,
    address: std::net::SocketAddr,
    cmd_key: &[u8; 16],
    keys: &KeySource,
    target: &TargetAddr,
    payloads: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    roundtrip_tier_with_option(
        tier,
        tier.request_option(),
        address,
        cmd_key,
        keys,
        target,
        payloads,
    )
    .await
}

/// 同上，但显式指定 option 字节（用于认证长度段等变体）。
async fn roundtrip_tier_with_option(
    tier: Tier,
    option: u8,
    address: std::net::SocketAddr,
    cmd_key: &[u8; 16],
    keys: &KeySource,
    target: &TargetAddr,
    payloads: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    let plain = tiercodec::build_request_plaintext(keys, target, tier, option)
        .map_err(|e| format!("请求头明文构造失败: {e:?}"))?;
    let header = aead::seal_vmess_aead_header(cmd_key, &plain)
        .map_err(|e| format!("请求头封装失败: {e:?}"))?;

    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| "连接超时".to_string())?
        .map_err(|e| format!("连接失败: {e}"))?;

    let echoed = tokio::time::timeout(RESPONSE_TIMEOUT, async {
        stream
            .write_all(&header)
            .await
            .map_err(|e| format!("写请求头失败: {e:?}"))?;
        write_body(&mut stream, tier, option, keys, payloads).await?;
        stream
            .flush()
            .await
            .map_err(|e| format!("刷写失败: {e:?}"))?;
        read_response_body(&mut stream, tier, option, keys).await
    })
    .await
    .map_err(|_| "回程超时".to_string())??;

    Ok(echoed)
}

/// 按档位写数据段（三段载荷）。
async fn write_body(
    stream: &mut TcpStream,
    tier: Tier,
    option: u8,
    keys: &KeySource,
    payloads: &[Vec<u8>],
) -> Result<(), String> {
    match tier {
        Tier::None => {
            // 参考的 NONE 分支：chunk-stream（明文载荷、可掩码长度段、无 padding）。
            let mut frame = ChunkStreamFrame::with_iv(option, &keys.body_iv);
            for payload in payloads {
                frame
                    .write_to(stream, payload)
                    .await
                    .map_err(|e| format!("写 chunk-stream 失败: {e:?}"))?;
            }
            frame
                .write_eof(stream)
                .await
                .map_err(|e| format!("写 chunk-stream EOF 失败: {e:?}"))?;
        }
        _ => {
            let suite = tier.body_suite();
            let mut frame = tiercodec::request_frame(suite, &keys.body_key, &keys.body_iv, option)
                .map_err(|e| format!("构造数据段帧失败: {e:?}"))?;
            for payload in payloads {
                frame
                    .write_to(stream, payload)
                    .await
                    .map_err(|e| format!("写数据段失败: {e:?}"))?;
            }
            // 终止帧（空载荷帧；参考 `AuthenticationWriter.WriteMultiBuffer` 的
            // 空 MultiBuffer 分支）。
            frame
                .write_to(stream, b"")
                .await
                .map_err(|e| format!("写终止帧失败: {e:?}"))?;
        }
    }
    Ok(())
}

/// 读响应头 + 数据段，返回数据段明文。
async fn read_response_body(
    stream: &mut TcpStream,
    tier: Tier,
    option: u8,
    keys: &KeySource,
) -> Result<Vec<u8>, String> {
    let (resp_key, resp_iv) = codec::response_key_iv(&keys.body_key, &keys.body_iv);
    codec::read_response_header(stream, &keys.body_key, &keys.body_iv)
        .await
        .map_err(|e| format!("读响应头失败: {e:?}"))?;

    let mut out = Vec::new();
    match tier {
        Tier::None => {
            let mut frame = ChunkStreamFrame::with_iv(option, &resp_iv);
            loop {
                match frame.read_from(stream).await {
                    Ok(Some(plain)) => out.extend_from_slice(&plain),
                    Ok(None) => break,
                    Err(e) if codec::is_clean_close(&e) => break,
                    Err(e) => return Err(format!("读数据段失败: {e:?}")),
                }
            }
        }
        _ => {
            let suite = tier.body_suite();
            let mut frame: BodyFrame = tiercodec::response_frame(
                suite,
                &resp_key,
                &resp_iv,
                &keys.body_key,
                &keys.body_iv,
                option,
            )
            .map_err(|e| format!("构造响应帧失败: {e:?}"))?;
            loop {
                match frame.read_from(stream).await {
                    Ok(Some(plain)) => out.extend_from_slice(&plain),
                    Ok(None) => break,
                    Err(e) if codec::is_clean_close(&e) => break,
                    Err(e) => return Err(format!("读数据段失败: {e:?}")),
                }
            }
        }
    }
    Ok(out)
}

/// 方向 A：**本仓客户端 → Xray 入站**，逐档位跑一遍完整回显。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn rust_client_to_xray_server_every_tier() {
    let Some(bin) = xray_bin() else { return };

    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let (echo_addr, echo_handle) = codec::spawn_echo().await;

    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());
    let payloads = payloads();
    let expected: Vec<u8> = payloads.iter().flatten().copied().collect();

    for tier in Tier::ALL {
        // Xray 入站的账号安全档按档位配置（参考的入站**不看**账号档位，
        // 真正决定数据段套件的是请求头里的 security 字节——见参考
        // `proxy/vmess/encoding/server.go` 的 `parseSecurityType`）。
        let fixture = match support::XrayFixture::start_with_security(&bin, &uuid, tier.xray_name())
        {
            Ok(f) => f,
            Err(report) => {
                eprintln!("{report}");
                panic!("启动 Xray 失败（档位 {}，UUID 已打码）", tier.xray_name());
            }
        };

        let echoed = roundtrip_tier(tier, fixture.address(), &cmd_key, &keys, &target, &payloads)
            .await
            .unwrap_or_else(|msg| panic!("档位 {} 互通失败: {msg}", tier.xray_name()));

        assert_eq!(
            echoed.len(),
            expected.len(),
            "档位 {} 回程长度必须相等",
            tier.xray_name()
        );
        assert_eq!(
            echoed,
            expected,
            "档位 {} 回程必须逐字节一致",
            tier.xray_name()
        );
        eprintln!(
            "OK: 方向 A 档位 {} 回程 {} 字节逐字节一致。",
            tier.xray_name(),
            echoed.len()
        );
    }

    echo_handle.abort();
}

/// 方向 A'：**认证长度段**（`RequestOptionAuthenticatedLength`）下的逐档位互通。
///
/// 长度段走 AEAD 认证时：长度段密钥 = `KDF16(requestBodyKey, "auth_len")` 再按
/// 档位派生（AES 直接 16B / ChaCha 走 MD5 链扩 32B），nonce 基值取**请求方向**
/// 的 requestBodyIV，计数器与载荷段**各自独立**。
///
/// 参考的入站在 `proxy/vmess/encoding/server.go` 的 `DecodeRequestBody` 里
/// **无条件**支持该选项（不需要账号开关）；账号开关只影响参考**出口**。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn rust_client_to_xray_server_authenticated_length_every_tier() {
    let Some(bin) = xray_bin() else { return };

    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let (echo_addr, echo_handle) = codec::spawn_echo().await;

    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());
    let payloads = payloads();
    let expected: Vec<u8> = payloads.iter().flatten().copied().collect();

    for tier in Tier::ALL {
        let fixture = match support::XrayFixture::start_with_security(&bin, &uuid, tier.xray_name())
        {
            Ok(f) => f,
            Err(report) => {
                eprintln!("{report}");
                panic!("启动 Xray 失败（档位 {}，UUID 已打码）", tier.xray_name());
            }
        };

        let echoed = roundtrip_tier_with_option(
            tier,
            tier.request_option_auth_len(),
            fixture.address(),
            &cmd_key,
            &keys,
            &target,
            &payloads,
        )
        .await
        .unwrap_or_else(|msg| panic!("档位 {} 认证长度段互通失败: {msg}", tier.xray_name()));

        assert_eq!(
            echoed.len(),
            expected.len(),
            "档位 {} 认证长度段回程长度必须相等",
            tier.xray_name()
        );
        assert_eq!(
            echoed,
            expected,
            "档位 {} 认证长度段回程必须逐字节一致",
            tier.xray_name()
        );
        eprintln!(
            "OK: 方向 A' 档位 {}（认证长度段）回程 {} 字节逐字节一致。",
            tier.xray_name(),
            echoed.len()
        );
    }

    echo_handle.abort();
}

/// 档位 → 套件的显式断言（防止 `Tier::body_suite` 与请求头字节脱节）。
#[test]
fn tier_mapping_is_self_consistent() {
    use lengsuo_vmess::request::SecurityOption;
    assert_eq!(Tier::None.security(), SecurityOption::None);
    assert_eq!(Tier::Aes.security(), SecurityOption::Aes128Gcm);
    assert_eq!(Tier::ChaCha.security(), SecurityOption::ChaCha20Poly1305);
    assert_eq!(Tier::None.body_suite(), BodySuite::None);
    assert_eq!(Tier::Aes.body_suite(), BodySuite::Aes128Gcm);
    assert_eq!(Tier::ChaCha.body_suite(), BodySuite::ChaCha20Poly1305);
    // 线字节必须与参考 `SecurityType` 枚举一致。
    assert_eq!(Tier::None.security().to_byte(), 5);
    assert_eq!(Tier::Aes.security().to_byte(), 3);
    assert_eq!(Tier::ChaCha.security().to_byte(), 4);
    // `none` 档必须带 ChunkStream（否则参考退化成无分帧裸流）。
    assert_ne!(Tier::None.request_option() & 0x01, 0);
    // `none` 档不吃 GlobalPadding（参考 NONE 分支整条 padding 路径被跳过）。
    assert_eq!(Tier::None.request_option() & 0x08, 0);
}
