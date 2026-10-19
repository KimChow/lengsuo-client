//! Rust 客户端 ↔ 真实 Xray VMess 入站的 ignored 集成测试。
//!
//! 运行方式（缺 `LENGSUO_XRAY` 时每个用例明确跳过并打印原因，不静默通过）：
//! ```text
//! LENGSUO_XRAY=/home/ubuntu/ref/bin/xray cargo test -p lengsuo-vmess --test xray_tcp --locked -- --ignored --nocapture
//! ```
//!
//! 判断口径：
//! - 用例 A 是「写请求 → Xray 解帧 → freedom 直连本地回显后端 → 回程加密封帧 →
//!   客户端解帧」的完整互通，回程与发送载荷逐字节比对；
//! - 用例 B/C 断言「服务端在超时内**主动关闭连接且未回任何有效响应头**」，
//!   而不是「没读到东西」：写入的是完整（或足以让入站 drain 后关闭的）字节，
//!   读侧必须观察到 EOF/RST 才算拒绝；超时或读到响应头都判失败。
//!
//! 用例 B/C 额外写入 > 3266 字节（下面统一 8192），是因为 Xray 入站拒绝时会按
//! `common/drain` 的 BehaviorSeedLimitedDrainer 读走 `54+Roll(3266)+Roll(64)` 再减
//! 已读字节（最多 3366 字节）后才关闭；请求体不够大时该 drain 会阻塞到握手超时，
//! 因此给足字节让它立即读完关闭（参照 `proxy/vmess/encoding/server.go` 与
//! `common/drain/drainer.go`）。

#[path = "support/mod.rs"]
mod support;

use std::path::PathBuf;
use std::time::Duration;

use lengsuo_vmess::{request::KeySource, Error};
use ss_core::target::TargetAddr;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;

use support::codec;
use support::XrayFixture;

/// 读回、测试里的超时上限（服务端本应在毫秒级关闭/回程）。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REJECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// 惰性获取参考二进制；未设置时打印原因并返回 None（调用方 `return` 跳过）。
fn xray_bin() -> Option<PathBuf> {
    match std::env::var_os("LENGSUO_XRAY") {
        Some(path) => Some(PathBuf::from(path)),
        None => {
            eprintln!(
                "SKIP: 环境变量 LENGSUO_XRAY 未设置，跳过依赖真实 Xray 的互通用例。\
                 原因：没有参考二进制可拉起，无法证明 Rust↔Xray 互通。"
            );
            None
        }
    }
}

/// 完整走一遍「请求 → Xray → 回显后端 → 回程」，返回回程字节数。
async fn echo_roundtrip(
    fixture: &XrayFixture,
    cmd_key: &[u8; 16],
    keys: &KeySource,
    target: &TargetAddr,
    payloads: &[&[u8]],
    expected: &[u8],
) -> Result<usize, String> {
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(fixture.address()))
        .await
        .map_err(|_| "连接 Xray 超时".to_string())?
        .map_err(|e| format!("连接 Xray 失败: {e}"))?;

    let echoed = tokio::time::timeout(RESPONSE_TIMEOUT, async {
        codec::write_request(&mut stream, cmd_key, keys, target, payloads)
            .await
            .map_err(|e| format!("写请求失败: {e:?}"))?;
        codec::read_response(
            &mut stream,
            &keys.body_key,
            &keys.body_iv,
            keys.response_header,
        )
        .await
        .map_err(|e| format!("读响应失败: {e:?}"))
    })
    .await
    .map_err(|_| "读响应超时".to_string())?
    .map_err(|msg| format!("{msg}\n{}", fixture.report()))?;

    if echoed != expected {
        return Err(format!(
            "回程逐字节不一致：期望 {} 字节，实得 {} 字节。\n{}",
            expected.len(),
            echoed.len(),
            fixture.report()
        ));
    }
    Ok(echoed.len())
}

/// 读侧拒绝判据：同一连接在超时内必须「关闭且无有效响应头」。
async fn expect_rejected_close(
    stream: &mut TcpStream,
    keys: &KeySource,
    fixture: &XrayFixture,
) -> Result<(), String> {
    let outcome = tokio::time::timeout(
        REJECT_TIMEOUT,
        codec::read_response_header(stream, &keys.body_key, &keys.body_iv),
    )
    .await;

    match outcome {
        Err(_) => Err(format!(
            "未被拒绝：连接在 {REJECT_TIMEOUT:?} 内未关闭，也没有回程。\n{}",
            fixture.report()
        )),
        Ok(Ok(_)) => Err(format!(
            "收到有效响应头，说明未被拒绝。\n{}",
            fixture.report()
        )),
        Ok(Err(e)) if codec::is_clean_close(&e) => Ok(()),
        Ok(Err(e)) => Err(format!(
            "读响应头得到非关闭错误 {e:?}，不是清晰的拒绝证据。\n{}",
            fixture.report()
        )),
    }
}

/// 用例 A：VMess AEAD（auto → AES-128-GCM）+ TCP，载荷 1B / 4KiB / 256KiB。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn client_to_xray_echo_roundtrip() {
    let Some(bin) = xray_bin() else { return };
    let (echo_addr, echo_handle) = codec::spawn_echo().await;

    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);

    let fixture = match XrayFixture::start(&bin, &uuid) {
        Ok(f) => f,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败（UUID 已打码）");
        }
    };

    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());

    let one = vec![0x2Au8];
    let four_kib: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    let big: Vec<u8> = (0..(256 * 1024)).map(|i| (i % 251) as u8).collect();
    let payloads: &[&[u8]] = &[&one, &four_kib, &big];
    let expected: Vec<u8> = one
        .iter()
        .chain(four_kib.iter())
        .chain(big.iter())
        .copied()
        .collect();

    let echoed = echo_roundtrip(&fixture, &cmd_key, &keys, &target, payloads, &expected)
        .await
        .unwrap_or_else(|msg| panic!("{msg}"));

    echo_handle.abort();
    eprintln!(
        "OK: 用例 A 回程与 {} 字节载荷逐字节一致（echoed={echoed}）。",
        expected.len()
    );
}

/// 用例 B：错误 UUID 连同一入站，必须在超时内被关闭且无有效回程。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn wrong_uuid_is_rejected() {
    let Some(bin) = xray_bin() else { return };

    let fixture_uuid_bytes = codec::generate_uuid_bytes();
    let fixture_uuid = codec::uuid_string(&fixture_uuid_bytes);
    let fixture = match XrayFixture::start(&bin, &fixture_uuid) {
        Ok(f) => f,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败（UUID 已打码）");
        }
    };

    let wrong_uuid_bytes = codec::generate_uuid_bytes();
    let wrong_cmd_key = codec::cmd_key_from_uuid(&wrong_uuid_bytes);
    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], 1);
    let payload = vec![0x5Au8; 8192]; // 足够让入站 drain 后立即关闭（见文件头注释）

    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(fixture.address()))
        .await
        .expect("连接超时")
        .expect("连接 Xray 失败");

    // 错误 UUID：服务端读 16 字节 AuthID 即查用户失败，随后 drain 并关闭。
    match codec::write_request(
        &mut stream,
        &wrong_cmd_key,
        &keys,
        &target,
        &[payload.as_slice()],
    )
    .await
    {
        // 写入中途就被对端关闭，本身就是拒绝证据，算通过。
        Err(e) if codec::is_clean_close(&e) => {
            eprintln!("OK: 用例 B 错误 UUID 在写入阶段即被服务端关闭。");
            return;
        }
        Err(e) => panic!("写请求以非关闭错误失败: {e:?}\n{}", fixture.report()),
        Ok(()) => {}
    }

    expect_rejected_close(&mut stream, &keys, &fixture)
        .await
        .unwrap_or_else(|msg| panic!("{msg}"));
    eprintln!("OK: 用例 B 错误 UUID 被拒绝（连接被关闭，无有效回程）。");
}

/// 用例 C：篡改请求头 AEAD 标签（末字节翻转）后发出，必须被拒。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn tampered_tag_is_rejected() {
    let Some(bin) = xray_bin() else { return };

    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);

    let fixture = match XrayFixture::start(&bin, &uuid) {
        Ok(f) => f,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败（UUID 已打码）");
        }
    };

    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], 1);

    // 正确的 UUID + 完整头，只翻转最后一个字节（载荷 AEAD 的 tag 末字节）。
    let mut header = codec::seal_request_header(&cmd_key, &keys, &target).expect("封装请求头");
    let last = header.len() - 1;
    header[last] ^= 0x01;

    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(fixture.address()))
        .await
        .expect("连接超时")
        .expect("连接 Xray 失败");

    // 写篡改头 + 足够字节让入站 drain 后立即关闭（服务端不再解析 body）。
    match async {
        stream
            .write_all(&header)
            .await
            .map_err(|e| Error::Io(format!("{:?}", e.kind())))?;
        stream
            .write_all(&vec![0u8; 8192])
            .await
            .map_err(|e| Error::Io(format!("{:?}", e.kind())))?;
        stream
            .flush()
            .await
            .map_err(|e| Error::Io(format!("{:?}", e.kind())))
    }
    .await
    {
        Err(e) if codec::is_clean_close(&e) => {
            eprintln!("OK: 用例 C 篡改 AEAD 标签在写入阶段即被服务端关闭。");
            return;
        }
        Err(e) => panic!("写篡改头以非关闭错误失败: {e:?}\n{}", fixture.report()),
        Ok(()) => {}
    }

    expect_rejected_close(&mut stream, &keys, &fixture)
        .await
        .unwrap_or_else(|msg| panic!("{msg}"));
    eprintln!("OK: 用例 C 篡改 AEAD 标签被拒绝（连接被关闭，无有效回程）。");
}
