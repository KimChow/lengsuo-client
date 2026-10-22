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
