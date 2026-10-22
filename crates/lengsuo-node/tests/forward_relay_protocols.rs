//! 转发层的**逐协议可转发性**验收：每个可转发协议两个用例。
//!
//! 每个协议两个用例：
//!
//! 1. **端到端转发**：本地 SOCKS5 CONNECT ⇒ 转发器 ⇒ 协议服务端 ⇒ 目标 echo
//!    ⇒ 回程载荷**逐字节一致**，且断言目标**确实被拨到**（数据真的穿过了
//!    转发器，而不是只握手成功）。
//! 2. **半关闭**：本地侧**只关写侧**（FIN）后，回程仍必须收到**完整**响应。
//!    夹具用「读到 EOF 才回内容」的延迟 echo ⇒ 响应能回来，就证明 FIN 穿过
//!    转发器到达了目标、且回程没有被提前掐断（`join!` 语义的核心）。
//!
//! 覆盖：trojan / shadowsocks（复用既有夹具）+ vless(TLS) / vless(REALITY) /
//! vmess / ss2022 / anytls / hysteria（本文件自建服务端）；外加 wireguard 的
//! **显式失败**反例（结构性不可转发 ⇒ 断开，**不得**静默直连）。
//!
//! 全部只绑回环、临时端口、假凭据；每个用例带总超时。
//!
//! **不声称与参考实现互通**：这里验证的是「本仓服务端 ↔ 本仓转发器」的端到端
//! 转发；与参考实现的互通结论见各协议 crate 的文档与 `docs/node-forward-relay.md`。

#[path = "forward_support/mod.rs"]
mod support;

#[path = "forward_relay_protocols/reality_proxy.rs"]
mod reality;

#[path = "forward_relay_protocols/servers.rs"]
mod servers;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lengsuo_node::config::NodeConfig;
use lengsuo_node::forward::{ForwardConfig, ForwardHandle, Forwarder, NodePool};
use lengsuo_node::route::RouteTable;
use servers::{
    anytls_node, anytls_server, hysteria_node, hysteria_server, ss2022_node, ss2022_server,
    vless_node, vless_tls_server, vmess_node, vmess_server, wireguard_node, ANYTLS_PASSWORD,
    HYSTERIA_PASSWORD, TEST_UUID,
};
use support::*;
use tokio::time::timeout;

/// 单用例总超时。
const TOTAL: Duration = Duration::from_secs(60);

/// 带总超时的用例包装（超时即失败，不允许挂死）。
macro_rules! case {
    ($body:block) => {
        timeout(TOTAL, async $body).await.expect("总超时")
    };
}

/// 转发器配置（测试用短超时）。
fn test_config() -> ForwardConfig {
    ForwardConfig {
        listen: "127.0.0.1:0".to_owned(),
        default_node: None,
        rules: Vec::new(),
        idle_timeout_secs: 5,
        session_timeout_secs: 10,
    }
}

/// 起一个转发器，返回（本地地址, 句柄）。
async fn start_forwarder(nodes: Vec<NodeConfig>) -> (SocketAddr, ForwardHandle) {
    let default_node = nodes
        .first()
        .map(|node| node.name.clone())
        .expect("至少一个节点");
    let routes = RouteTable::new(Vec::new(), Some(default_node)).expect("路由表");
    let forwarder = Forwarder::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodePool::new(nodes),
        routes,
        test_config(),
    )
    .await
    .expect("转发器绑定");
    let addr = forwarder.local_addr().expect("转发器地址");
    let handle = forwarder.start().await.expect("转发器启动");
    (addr, handle)
}

/// 端到端断言：回程载荷逐字节一致，且目标确实被拨到。
fn assert_echoed(
    result: &Socks5Result,
    payload: &[u8],
    counter: &std::sync::atomic::AtomicUsize,
    label: &str,
) {
    match result {
        Socks5Result::Replied { rep, payload: got } => {
            assert_eq!(*rep, 0x00, "{label}：SOCKS5 回复码应为成功");
            assert_eq!(got, payload, "{label}：回程载荷必须逐字节一致");
        }
        Socks5Result::Closed { .. } => panic!("{label}：转发应成功建立会话"),
    }
    assert_eq!(
        hits(counter),
        1,
        "{label}：目标必须被拨到一次（数据真的穿过转发器）"
    );
}

/// 半关闭断言：本地只关写侧后，回程仍收到**完整**响应。
fn assert_half_closed(
    result: &Socks5Result,
    expected: &[u8],
    counter: &std::sync::atomic::AtomicUsize,
    label: &str,
) {
    match result {
        Socks5Result::Replied { rep, payload: got } => {
            assert_eq!(*rep, 0x00, "{label}：SOCKS5 回复码应为成功");
            assert_eq!(got, expected, "{label}：半关闭后回程必须仍是完整响应");
        }
        Socks5Result::Closed { payload: got } => {
            panic!("{label}：半关闭后回程必须仍是完整响应，实得 {got:?}")
        }
    }
    assert_eq!(hits(counter), 1, "{label}：目标必须被拨到一次");
}

// ——— trojan ———

/// trojan 端到端：SOCKS5 ⇒ 转发器 ⇒ trojan 服务端 ⇒ echo ⇒ 载荷逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trojan_relay_end_to_end() {
    case!({
        let echo = spawn_echo().await;
        let (port, ca_pem) = trojan_server(TROJAN_PASSWORD).await;
        let node = trojan_node("trojan-node", port, &ca_pem, TROJAN_PASSWORD);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let payload = b"trojan-relay-payload-\x00\xff\xfe".to_vec();
        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), &payload).await;
        assert_echoed(&result, &payload, &echo.hits, "trojan");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// trojan 半关闭：本地只关写侧 ⇒ 目标收到 EOF 后才回内容 ⇒ 回程完整。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trojan_relay_half_close() {
    case!({
        let content = b"trojan-half-close-response";
        let echo = spawn_delayed_echo(content).await;
        let (port, ca_pem) = trojan_server(TROJAN_PASSWORD).await;
        let node = trojan_node("trojan-node", port, &ca_pem, TROJAN_PASSWORD);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), b"request").await;
        assert_half_closed(&result, content, &echo.hits, "trojan");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

// ——— shadowsocks ———

/// shadowsocks 端到端：载荷逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shadowsocks_relay_end_to_end() {
    case!({
        let echo = spawn_echo().await;
        let port = shadowsocks_server().await;
        let node = shadowsocks_node("ss-node", port, SS_PASSWORD);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let payload = b"shadowsocks-relay-payload".to_vec();
        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), &payload).await;
        assert_echoed(&result, &payload, &echo.hits, "shadowsocks");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// shadowsocks 半关闭：回程完整。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shadowsocks_relay_half_close() {
    case!({
        let content = b"shadowsocks-half-close-response";
        let echo = spawn_delayed_echo(content).await;
        let port = shadowsocks_server().await;
        let node = shadowsocks_node("ss-node", port, SS_PASSWORD);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), b"request").await;
        assert_half_closed(&result, content, &echo.hits, "shadowsocks");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

// ——— vless（TLS 承载） ———

/// vless(TLS) 端到端：载荷逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_tls_relay_end_to_end() {
    case!({
        let echo = spawn_echo().await;
        let (port, ca_pem) = vless_tls_server(TEST_UUID).await;
        let node = vless_node("vless-node", port, &ca_pem, TEST_UUID);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let payload = b"vless-tls-relay-payload-\x00\xff\xfe".to_vec();
        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), &payload).await;
        assert_echoed(&result, &payload, &echo.hits, "vless(TLS)");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// vless(TLS) 半关闭：回程完整。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_tls_relay_half_close() {
    case!({
        let content = b"vless-tls-half-close-response";
        let echo = spawn_delayed_echo(content).await;
        let (port, ca_pem) = vless_tls_server(TEST_UUID).await;
        let node = vless_node("vless-node", port, &ca_pem, TEST_UUID);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), b"request").await;
        assert_half_closed(&result, content, &echo.hits, "vless(TLS)");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

// ——— vless（REALITY 承载） ———

/// vless(REALITY) 端到端：REALITY 与明文 TLS 是两个不同的 `VlessStream`
/// 变体，两个都要能转发。载荷逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_reality_relay_end_to_end() {
    case!({
        let echo = spawn_echo().await;
        let server = Arc::new(reality::Server::new());
        let port = reality::reality_proxy_server(Arc::clone(&server)).await;
        let node = reality::reality_node("vless-reality-node", port, &server);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let payload = b"vless-reality-relay-payload-\x00\xff\xfe".to_vec();
        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), &payload).await;
        assert_echoed(&result, &payload, &echo.hits, "vless(REALITY)");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// vless(REALITY) 半关闭：回程完整。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_reality_relay_half_close() {
    case!({
        let content = b"vless-reality-half-close-response";
        let echo = spawn_delayed_echo(content).await;
        let server = Arc::new(reality::Server::new());
        let port = reality::reality_proxy_server(Arc::clone(&server)).await;
        let node = reality::reality_node("vless-reality-node", port, &server);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), b"request").await;
        assert_half_closed(&result, content, &echo.hits, "vless(REALITY)");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

// ——— vmess ———

/// vmess 端到端：载荷逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vmess_relay_end_to_end() {
    case!({
        let echo = spawn_echo().await;
        let (port, ca_pem) = vmess_server(TEST_UUID).await;
        let node = vmess_node("vmess-node", port, &ca_pem, TEST_UUID);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let payload = b"vmess-relay-payload-\x00\xff\xfe".to_vec();
        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), &payload).await;
        assert_echoed(&result, &payload, &echo.hits, "vmess");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// vmess 半关闭：EOF chunk 之后回程仍要完整。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vmess_relay_half_close() {
    case!({
        let content = b"vmess-half-close-response";
        let echo = spawn_delayed_echo(content).await;
        let (port, ca_pem) = vmess_server(TEST_UUID).await;
        let node = vmess_node("vmess-node", port, &ca_pem, TEST_UUID);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), b"request").await;
        assert_half_closed(&result, content, &echo.hits, "vmess");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

// ——— ss2022 ———

/// ss2022 端到端：载荷逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ss2022_relay_end_to_end() {
    case!({
        let echo = spawn_echo().await;
        let port = ss2022_server().await;
        let node = ss2022_node("ss2022-node", port);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let payload = b"ss2022-relay-payload-\x00\xff\xfe".to_vec();
        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), &payload).await;
        assert_echoed(&result, &payload, &echo.hits, "ss2022");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// ss2022 半关闭：终止 chunk 之后回程仍要完整。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ss2022_relay_half_close() {
    case!({
        let content = b"ss2022-half-close-response";
        let echo = spawn_delayed_echo(content).await;
        let port = ss2022_server().await;
        let node = ss2022_node("ss2022-node", port);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), b"request").await;
        assert_half_closed(&result, content, &echo.hits, "ss2022");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

// ——— anytls ———

/// anytls 端到端：载荷逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anytls_relay_end_to_end() {
    case!({
        let echo = spawn_echo().await;
        let (port, ca_pem) = anytls_server(ANYTLS_PASSWORD).await;
        let node = anytls_node("anytls-node", port, &ca_pem, ANYTLS_PASSWORD);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let payload = b"anytls-relay-payload-\x00\xff\xfe".to_vec();
        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), &payload).await;
        assert_echoed(&result, &payload, &echo.hits, "anytls");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// anytls 半关闭：回程完整。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anytls_relay_half_close() {
    case!({
        let content = b"anytls-half-close-response";
        let echo = spawn_delayed_echo(content).await;
        let (port, ca_pem) = anytls_server(ANYTLS_PASSWORD).await;
        let node = anytls_node("anytls-node", port, &ca_pem, ANYTLS_PASSWORD);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), b"request").await;
        assert_half_closed(&result, content, &echo.hits, "anytls");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

// ——— hysteria ———

/// hysteria 端到端：QUIC 双向流的两半穿过转发器，载荷逐字节一致。
///
/// 这一条同时证明「跨线程可行」：转发器把会话放进 `tokio::spawn` 的任务里，
/// 而 hysteria 的读写两半来自**另一条 QUIC 连接**的 `quinn::SendStream` /
/// `RecvStream`。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hysteria_relay_end_to_end() {
    case!({
        let echo = spawn_echo().await;
        let (port, ca_pem) = hysteria_server(HYSTERIA_PASSWORD).await;
        let node = hysteria_node("hysteria-node", port, &ca_pem, HYSTERIA_PASSWORD);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let payload = b"hysteria-relay-payload-\x00\xff\xfe".to_vec();
        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), &payload).await;
        assert_echoed(&result, &payload, &echo.hits, "hysteria");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

/// hysteria 半关闭：QUIC 流 FIN 之后回程仍要完整。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hysteria_relay_half_close() {
    case!({
        let content = b"hysteria-half-close-response";
        let echo = spawn_delayed_echo(content).await;
        let (port, ca_pem) = hysteria_server(HYSTERIA_PASSWORD).await;
        let node = hysteria_node("hysteria-node", port, &ca_pem, HYSTERIA_PASSWORD);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let result = socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), b"request").await;
        assert_half_closed(&result, content, &echo.hits, "hysteria");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}

// ——— wireguard（结构性不可转发） ———

/// wireguard 结构性不可转发 ⇒ 显式失败：连接被断开，**目标一次都没被拨到**
/// （不得静默直连）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wireguard_is_explicitly_unsupported() {
    case!({
        let echo = spawn_echo().await;
        let node = wireguard_node("wg-node", 9);
        let (proxy, handle) = start_forwarder(vec![node]).await;

        let result =
            socks5_roundtrip(proxy, socks5_connect_v4(echo.addr), b"must-not-arrive").await;
        assert_fail_closed(&result, &echo.hits, "wireguard 结构性不可转发");

        handle.shutdown().await.expect("转发器应干净停止");
    });
}
