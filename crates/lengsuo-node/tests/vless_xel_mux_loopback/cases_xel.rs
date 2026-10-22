/// **1. XEL 正例**：node 的 VLESS 出口经 XEL 记录层连上本仓 XEL 服务端，
/// 握手成功、拿到成功响应头（`[0, 0]`）、载荷往返逐字节一致（**双向**）。
///
/// 认证判据与 Vision 侧**一致**：只有拿到成功响应头才算认证完成。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_xel_roundtrip_to_own_server() {
    timeout(DEADLINE, async {
        let fixture = server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vless_node(
            port,
            &ca_pem,
            Some(xel_section(XEL_UPLINK_HEX, XEL_DOWNLINK_HEX)),
            false,
        );
        assert!(node.validate().is_ok(), "配置应通过校验");

        let (client, server) = tokio::join!(
            async {
                let mut outbound = dial_vless(&node, WAIT)
                    .await
                    .expect("XEL 建流 + 握手应成功");
                assert!(
                    matches!(outbound.stream, VlessStream::Xel(_)),
                    "承载应是 XEL 记录层"
                );
                outbound.stream.write_all(PAYLOAD).await.expect("写载荷");
                let mut received = vec![0u8; PAYLOAD.len()];
                timeout(WAIT, outbound.stream.read_exact(&mut received))
                    .await
                    .expect("读回环载荷超时")
                    .expect("读回环载荷失败");
                received
            },
            support::serve_xel(
                fixture,
                KEY,
                XEL_SERVER_UPLINK_HEX,
                XEL_SERVER_DOWNLINK_HEX,
                PAYLOAD.len(),
                None,
            ),
        );
        assert_eq!(client, PAYLOAD, "下行回环载荷必须逐字节一致");
        assert_eq!(
            server.expect("服务端"),
            PAYLOAD,
            "服务端解出的上行明文必须逐字节一致"
        );
        println!("VLESS+XEL 记录层贯通：{} 字节逐字节一致", client.len());
    })
    .await
    .expect("用例总超时");
}

/// **2. XEL 负例**：错密钥 ⇒ 记录层 AEAD 认证失败 ⇒ 拨号失败（fail-closed）。
///
/// 客户端的上行密钥与服务端的下行密钥不匹配 ⇒ 服务端解不开请求头 ⇒ 服务端
/// 断开、**不**回成功响应头 ⇒ node 侧拨号必须失败；⛔ **不得**回落到明文、
/// **不得**把没认证的连接交出去。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_xel_wrong_key_fails_closed() {
    timeout(DEADLINE, async {
        let fixture = server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        // 客户端上行密钥用错的 ⇒ 与服务端下行密钥不匹配。
        let node = vless_node(
            port,
            &ca_pem,
            Some(xel_section(XEL_WRONG_HEX, XEL_DOWNLINK_HEX)),
            false,
        );

        let (result, server) = tokio::join!(
            async { dial_vless(&node, WAIT).await.map(|_| ()) },
            support::serve_xel(
                fixture,
                KEY,
                XEL_SERVER_UPLINK_HEX,
                XEL_SERVER_DOWNLINK_HEX,
                PAYLOAD.len(),
                None,
            ),
        );
        assert!(
            result.is_err(),
            "错密钥必须失败（不得静默成功、不得回落到明文）"
        );
        assert!(
            server.is_err(),
            "服务端必须因 AEAD 认证失败而拒绝：{:?}",
            server.err()
        );
    })
    .await
    .expect("用例总超时");
}

/// **3. XEL 负例**：XEL 配置非法（密钥长度不符）⇒ **在建立 TCP/TLS 之前**失败。
///
/// 判据：`outbound_vless_xel::precheck` 先失败 ⇒ **一条字节都不发**（连 TCP
/// 都不拨）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_xel_bad_config_fails_closed_without_connect() {
    timeout(DEADLINE, async {
        let (port, accepted, watcher) = accept_only_watcher().await;
        // 16 字节密钥 ⇒ 长度非法（AEAD 记录密钥要求 32 字节）。
        let node = vless_node(
            port,
            "",
            Some(xel_section("0011223344556677", XEL_DOWNLINK_HEX)),
            false,
        );
        assert!(
            node.validate().is_err(),
            "非法密钥长度必须在配置校验层就被拒"
        );

        let error = dial_vless(&node, WAIT).await.expect_err("坏配置必须失败");
        assert!(
            error.to_string().contains("xel"),
            "错误应点名 xel 配置非法：{error}"
        );
        let outcome = timeout(Duration::from_secs(2), watcher).await;
        assert!(
            outcome.is_err(),
            "坏配置下不该建立连接（已被 accept {} 次）",
            accepted.load(std::sync::atomic::Ordering::SeqCst)
        );
    })
    .await
    .expect("用例总超时");
}

/// **4. XEL 负例**：载荷篡改被拒 —— 在**记录层**里翻一个字节 ⇒ 对端必须检出
/// 并断连（AEAD 认证失败）。
///
/// 篡改点插在**记录层与传输层之间** ⇒ 线上被改的是记录层密文 ⇒ 对端是**记录层
/// 的 AEAD** 抓到失败（不是 TLS 的 MAC 先抓到）。
///
/// 判据：客户端读载荷必须**报错**（⛔ 不是干净的 EOF、⛔ 不是静默的坏数据）；
/// 之后再读也必须仍报错（fail-closed：记录层被永久 poison）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_xel_tampered_payload_is_rejected() {
    timeout(DEADLINE, async {
        let fixture = server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vless_node(
            port,
            &ca_pem,
            Some(xel_section(XEL_UPLINK_HEX, XEL_DOWNLINK_HEX)),
            false,
        );
        let payload_len = support::BIG_PAYLOAD_LEN;

        let (client, server) = tokio::join!(
            async {
                let mut outbound = dial_vless(&node, WAIT)
                    .await
                    .expect("XEL 建流 + 握手应成功");
                outbound
                    .stream
                    .write_all(&vec![0x5au8; payload_len])
                    .await
                    .expect("写载荷");
                let mut received = vec![0u8; payload_len];
                let first = timeout(WAIT, outbound.stream.read_exact(&mut received)).await;
                // 第一次读必须失败（AEAD 认证失败）。
                let first = first
                    .expect("读载荷超时（篡改后必须立刻失败，不得挂住）")
                    .expect_err("载荷被篡改后必须失败，不得返回数据");
                // 记录层 fail-closed：之后再读也必须失败（不得变成干净 EOF）。
                let mut again = vec![0u8; 1];
                let second = timeout(WAIT, outbound.stream.read_exact(&mut again))
                    .await
                    .expect("第二次读超时")
                    .expect_err("记录层被篡改后必须永久失败，不得回落到干净 EOF");
                format!("{first} / {second}")
            },
            support::serve_xel(
                fixture,
                KEY,
                XEL_SERVER_UPLINK_HEX,
                XEL_SERVER_DOWNLINK_HEX,
                payload_len,
                Some(TAMPER_OFFSET),
            ),
        );
        assert!(
            client.contains("XEL") || client.contains("认证"),
            "错误应点名记录层认证失败：{client}"
        );
        // 服务端侧不受影响：篡改发生在记录层与传输层之间，服务端照样把载荷写出去了。
        assert_eq!(
            server.expect("服务端"),
            vec![0x5au8; payload_len],
            "服务端读到的上行载荷应逐字节一致"
        );
        println!("XEL 载荷篡改被拒：{client}");
    })
    .await
    .expect("用例总超时");
}

