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
