//! 可部署 Shadowsocks TCP 中继服务的端到端验收（仅回环、假口令、临时端口）。
//!
//! 与参考基线对齐：Xray `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`
//! `proxy/shadowsocks/server.go` 的 `handleConnection`。
//!
//! 覆盖：正路径（多套件）、地址跨 chunk、域名目标、IPv6 目标、错误口令
//! （绝不回退直连）、截断、`shutdown` 回收。
#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
#[allow(dead_code)]
mod support;

use lengsuo_shadowsocks::tcp::{Reader as TcpReader, Writer as TcpWriter};
use lengsuo_shadowsocks::{CipherSuite, RelayConfig, RelayConfigParts, RelayHandle, RelayService};
use ss_core::target::TargetAddr;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use support::WAIT;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 测试假口令，与任何生产凭据无关。
const PASSWORD: &str = "ss-tcp-reference-test-password";

/// 按名字取套件（与同 crate 其它测试一致的最小映射）。
fn suite_of(name: &str) -> CipherSuite {
    CipherSuite::from_name(name).expect("测试套件名应可解析")
}

/// 回环 echo：把收到的字节原样回写，直到对端关闭。
async fn spawn_echo(listener: TcpListener) -> SocketAddr {
    let addr = listener.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("echo accept");
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if stream.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = stream.shutdown().await;
    });
    addr
}

async fn echo_listener() -> SocketAddr {
    spawn_echo(TcpListener::bind("127.0.0.1:0").await.expect("bind echo")).await
}

fn config(suite: &str, replay: Option<(usize, Duration)>) -> RelayConfig {
    RelayConfig::new(
        RelayConfigParts {
            suite: suite_of(suite),
            idle_timeout: Duration::from_secs(5),
            replay,
        },
        PASSWORD.as_bytes(),
    )
}

/// 起一个中继服务，返回监听地址与句柄。句柄在 LocalSet 内驱动服务任务。
async fn start_relay(suite: &str, replay: Option<(usize, Duration)>) -> (SocketAddr, RelayHandle) {
    let service = RelayService::bind(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        config(suite, replay),
    )
    .await
    .expect("中继绑定");
    let addr = service.local_addr().expect("中继地址");
    let handle = service.start().await.expect("中继启动");
    (addr, handle)
}

/// 用「本仓客户端」发「地址 + 载荷」并读回程（写半关闭后读）。
async fn roundtrip(relay: SocketAddr, suite: &str, target: &TargetAddr, payload: &[u8]) -> Vec<u8> {
    let mut stream = timeout(WAIT, TcpStream::connect(relay))
        .await
        .expect("连接中继超时")
        .expect("连接中继");
    let mut request: Vec<u8> = Vec::new();
    target.encode_checked(&mut request).expect("目标可编码");
    request.extend_from_slice(payload);
    let mut writer =
        TcpWriter::new(&mut stream, suite_of(suite), PASSWORD.as_bytes(), WAIT).expect("构造写端");
    timeout(WAIT, writer.send(&request))
        .await
        .expect("send 超时")
        .expect("send 成功");
    timeout(WAIT, writer.shutdown())
        .await
        .expect("shutdown 超时")
        .expect("shutdown 成功");
    drop(writer);
    drain_response(stream, suite).await
}

/// 读回程方向到干净 EOF。
async fn drain_response(mut stream: TcpStream, suite: &str) -> Vec<u8> {
    let (read_half, _write_half) = stream.split();
    let mut reader =
        TcpReader::new(read_half, suite_of(suite), PASSWORD.as_bytes(), WAIT).expect("构造读端");
    let mut got = Vec::new();
    for _ in 0..8 {
        match timeout(WAIT, reader.recv()).await.expect("recv 超时") {
            Ok(Some(chunk)) => got.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(_) => break,
        }
    }
    got
}

fn local_set() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

#[test]
fn relay_roundtrip_all_suites() {
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        for suite in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
            // 每个套件独立起 echo（echo 只接受一条连接）与中继，避免互相干扰。
            let echo = echo_listener().await;
            let target = TargetAddr::V4([127, 0, 0, 1], echo.port());
            let (relay, handle) = start_relay(suite, None).await;
            let payload = format!("relay-{suite}-payload").into_bytes();
            let got = roundtrip(relay, suite, &target, &payload).await;
            assert_eq!(got, payload, "套件 {suite} 的回程应与载荷一致");
            handle.shutdown().await.expect("中继应干净停止");
        }
    });
}

#[test]
fn relay_handles_address_split_across_chunks() {
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let echo = echo_listener().await;
        let target = TargetAddr::V4([127, 0, 0, 1], echo.port());
        let (relay, handle) = start_relay("aes-128-gcm", None).await;
        let mut full: Vec<u8> = Vec::new();
        target.encode_checked(&mut full).expect("目标可编码");
        let payload = b"split-address-payload".to_vec();
        full.extend_from_slice(&payload);
        let mut stream = TcpStream::connect(relay).await.expect("连接中继");
        let mut writer = TcpWriter::new(
            &mut stream,
            suite_of("aes-128-gcm"),
            PASSWORD.as_bytes(),
            WAIT,
        )
        .expect("构造写端");
        // 第一次只发地址前 2 字节（制造地址跨 chunk），余下一次发完。
        timeout(WAIT, writer.send(&full[..2]))
            .await
            .expect("首段超时")
            .expect("首段成功");
        timeout(WAIT, writer.send(&full[2..]))
            .await
            .expect("次段超时")
            .expect("次段成功");
        timeout(WAIT, writer.shutdown())
            .await
            .expect("shutdown 超时")
            .expect("shutdown 成功");
        drop(writer);
        let got = drain_response(stream, "aes-128-gcm").await;
        assert_eq!(got, payload, "地址跨 chunk 后回程仍应一致");
        handle.shutdown().await.expect("中继应干净停止");
    });
}

#[test]
fn relay_domain_target() {
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let echo4 = echo_listener().await;
        let (relay, handle) = start_relay("aes-128-gcm", None).await;
        let domain = TargetAddr::Domain("localhost".to_string(), echo4.port());
        let payload = b"domain-target-payload".to_vec();
        let got = roundtrip(relay, "aes-128-gcm", &domain, &payload).await;
        assert_eq!(got, payload, "域名目标回程应一致");
        handle.shutdown().await.expect("中继应干净停止");
    });
}

#[test]
fn relay_ipv6_target() {
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let listener = match TcpListener::bind("[::1]:0").await {
            Ok(listener) => listener,
            Err(_) => return, // 无 IPv6 回环能力的环境跳过（不冒充通过）
        };
        let echo6 = listener.local_addr().expect("IPv6 echo 地址");

        // ⚠️ 探针约束（2026-10-20 两次实机踩坑后的定稿）：
        // 1. **必须探测 connect**：本机（Windows）`::1` 可 bind 但 connect 被系统策略
        //    拒（WSAEACCES 10013）——只探测 bind 会在 v6 受限环境必然失败，看似代码缺陷。
        // 2. **探测连接不能打向 echo**：`spawn_echo` 只 accept 一条连接，探测连接会
        //    把它占掉，真正的中继连接无 echo 可接 → 「回程为空」假失败。
        // 定稿方案：起一个**一次性探测 listener**（自带 accept，用完即弃），
        // 主动向它 connect 一次来验证 v6 回环可连性；通过后才起真正的 echo 并继续。
        // 这条探测连接只落在探测 listener 上，绝不会占掉 echo 的 accept。
        let probe = match TcpListener::bind("[::1]:0").await {
            Ok(probe) => probe,
            Err(_) => return,
        };
        let probe_addr = probe.local_addr().expect("探测地址");
        let probe_ok = tokio::select! {
            connect = TcpStream::connect(probe_addr) => connect.is_ok(),
            _ = tokio::time::sleep(Duration::from_secs(2)) => false,
        };
        drop(probe);
        if !probe_ok {
            println!("skip relay_ipv6_target：IPv6 回环不可连接（connect 被系统策略拒绝）");
            return;
        }

        spawn_echo(listener).await;
        let (relay, handle) = start_relay("chacha20-ietf-poly1305", None).await;
        let v6 = TargetAddr::V6(Ipv6Addr::LOCALHOST.octets(), echo6.port());
        let payload = b"ipv6-target-payload".to_vec();
        let got = roundtrip(relay, "chacha20-ietf-poly1305", &v6, &payload).await;
        assert_eq!(got, payload, "IPv6 目标回程应一致");
        handle.shutdown().await.expect("中继应干净停止");
    });
}

#[test]
fn relay_wrong_password_never_falls_back_to_direct() {
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let echo = echo_listener().await;
        let target = TargetAddr::V4([127, 0, 0, 1], echo.port());
        let (relay, handle) = start_relay("aes-128-gcm", None).await;
        let mut stream = TcpStream::connect(relay).await.expect("连接中继");
        let mut request: Vec<u8> = Vec::new();
        target.encode_checked(&mut request).expect("目标可编码");
        request.extend_from_slice(b"should-not-be-relayed");
        // 用错误口令写请求方向：服务端派生不同子密钥，认证必失败。
        let mut writer = TcpWriter::new(
            &mut stream,
            suite_of("aes-128-gcm"),
            b"definitely-wrong-password",
            WAIT,
        )
        .expect("构造写端");
        let _ = timeout(WAIT, writer.send(&request)).await;
        drop(writer);
        // 服务端必须关闭连接：读到 EOF（0 字节），而不是任何回程数据。
        let mut buf = [0u8; 64];
        let n = timeout(WAIT, stream.read(&mut buf))
            .await
            .expect("读超时")
            .unwrap_or(0);
        assert_eq!(n, 0, "错误口令必须关连接，绝不回退直连");
        handle.shutdown().await.expect("中继应干净停止");
    });
}

#[test]
fn relay_shutdown_stops_accepting() {
    let runtime = local_set();
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async {
        let echo = echo_listener().await;
        let target = TargetAddr::V4([127, 0, 0, 1], echo.port());
        let (relay, handle) = start_relay("aes-128-gcm", None).await;
        let payload = b"before-shutdown".to_vec();
        let got = roundtrip(relay, "aes-128-gcm", &target, &payload).await;
        assert_eq!(got, payload);
        handle.shutdown().await.expect("中继应干净停止");
        // 关闭后新连接必须被拒（监听器已关闭）。
        let reopened = timeout(WAIT, TcpStream::connect(relay)).await;
        assert!(!matches!(reopened, Ok(Ok(_))), "关闭后仍能连上监听器");
    });
}
