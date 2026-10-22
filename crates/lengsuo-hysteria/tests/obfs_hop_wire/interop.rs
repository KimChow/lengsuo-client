/// 方向⓪（可证伪基线）：参考服务端开了 Salamander，本仓客户端**不**混淆
/// ⇒ 必须连不上。若这条能连上，说明「混淆层根本没生效」，后续用例全无意义。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn baseline_plain_client_cannot_talk_to_masked_ref_server() {
    let world = start_ref_server("baseline", Some(PSK)).await;
    let echo = spawn_tcp_echo().await;
    // 不混淆 ⇒ 必须连不上。「连不上」有两种形态，**都算失败**：快速报错；
    // 或超时（参考服务端解不开混淆 ⇒ 丢包 ⇒ 握手永远完不成）—— 这恰恰是
    // 混淆层生效的表现，因此**不能**把超时当测试错误。
    let res = tokio::time::timeout(Duration::from_secs(10), connect_ref_server(&world, None)).await;
    match res {
        Ok(Ok(_)) => panic!("基线必须失败：不混淆却连上了参考服务端"),
        Ok(Err(e)) => assert!(
            !matches!(e, lengsuo_hysteria::quic::ConnectError::Bind(_)),
            "失败原因应是握手/认证层，而不是本地绑定: {e}"
        ),
        Err(_) => {}
    }
    // 混淆后同一服务端必须能连上（证明基线失败源于混淆层，而非服务端本身坏了）。
    let client = connect_ref_server(&world, Some(PSK))
        .await
        .expect("混淆后应能连上");
    let got = proxy_roundtrip(&client, echo).await;
    assert_eq!(got, PAYLOAD, "混淆后回显应逐字节一致");
}

/// 方向①：本仓客户端（真混淆）→ 参考服务端（参考 Salamander）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn our_client_obfuscates_towards_ref_server() {
    let world = start_ref_server("dir1", Some(PSK)).await;
    let echo = spawn_tcp_echo().await;
    let client = connect_ref_server(&world, Some(PSK))
        .await
        .expect("建连失败（本仓混淆 ↔ 参考 Salamander）");
    let got = proxy_roundtrip(&client, echo).await;
    assert_eq!(got, PAYLOAD, "回显应逐字节一致");
}

/// 方向②：参考客户端（参考 Salamander）→ 本仓服务端（真解混淆）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn ref_client_obfuscates_towards_our_server() {
    let server = start_our_server("dir2", Some(PSK)).await;
    let echo = spawn_tcp_echo().await;
    let (_ok_proc, socks_port) =
        start_ref_client("dir2", server.addr.port(), Some(PSK), &server.pin).await;
    // 参考客户端起来需要一点时间（socks 端口要能连）。
    let d = Duration::from_secs(3);
    let got = retry_until(80, d, || socks_roundtrip(socks_port, echo, PAYLOAD))
        .await
        .unwrap_or_else(|e| panic!("参考客户端 → 本仓服务端 未能完成回显；最后错误 {e}"));
    assert_eq!(got, PAYLOAD, "回显应逐字节一致");
}

/// 方向③：口令不符 ⇒ 必须失败。
///
/// 三个方向，**先立对照组**再测失败，否则「失败」无法归因：
/// - A：本仓服务端（正确口令）+ 参考客户端（**正确**口令）⇒ **必须成功**；
/// - B：同一个本仓服务端 + 参考客户端（**错误**口令）⇒ 必须失败；
/// - C：参考服务端（正确口令）+ 本仓客户端（**错误**口令）⇒ 必须失败。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn wrong_password_is_rejected() {
    // ── 方向 A：对照组，必须成功。
    let server = start_our_server("dir3b", Some(PSK)).await;
    let echo = spawn_tcp_echo().await;
    let (_ok_proc, ok_port) =
        start_ref_client("dir3b-ok", server.addr.port(), Some(PSK), &server.pin).await;
    let d = Duration::from_secs(3);
    let got = retry_until(80, d, || socks_roundtrip(ok_port, echo, PAYLOAD))
        .await
        .unwrap_or_else(|e| panic!("对照组失败：本仓服务端 + 正确口令的参考客户端 未能回显；{e}"));
    assert_eq!(got, PAYLOAD, "回显应逐字节一致");

    // ── 方向 B：同一个本仓服务端 + 错误口令的参考客户端 ⇒ 必须失败。
    let (_bad_proc, bad_port) = start_ref_client(
        "dir3b-bad",
        server.addr.port(),
        Some(WRONG_PSK),
        &server.pin,
    )
    .await;
    let bad = retry_until(10, d, || socks_roundtrip(bad_port, echo, PAYLOAD)).await;
    assert!(
        bad.is_err(),
        "错误口令时参考客户端竟能通过本仓服务端完成回显（解混淆没有 fail-closed）"
    );

    // ── 方向 C：参考服务端（正确口令）+ 本仓客户端（错误口令）⇒ 必须失败。
    let world = start_ref_server("dir3", Some(PSK)).await;
    let ten = Duration::from_secs(10);
    let res = tokio::time::timeout(ten, connect_ref_server(&world, Some(WRONG_PSK))).await;
    match res {
        Ok(Ok(_)) => panic!("错误口令必须失败：却连上了参考服务端"),
        Ok(Err(e)) => assert!(
            !matches!(e, lengsuo_hysteria::quic::ConnectError::Bind(_)),
            "失败原因应是握手/认证层（服务端解混淆丢弃了报文），而不是本地绑定: {e}"
        ),
        Err(_) => {}
    }
}
