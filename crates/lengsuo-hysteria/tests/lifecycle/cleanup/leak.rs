// 无资源泄漏（会话表归零）+ 承载收尾（半关闭 ⇒ 出站 TCP 写端关闭）。
/// B6：无资源泄漏 —— 每条用例前后各取一次「会话表条目数」，断言**归零**
/// （不是「不增加」）。
///
/// 这条是「清理」格的硬判据：跑完一轮完整交互（TCP + UDP）后，
/// 客户端与服务端的会话表都必须**归零**。
#[tokio::test]
async fn cleanup_no_session_table_leak_after_full_interaction() {
    let server = start_server("cl6", 60).await;

    // 前置计数：服务端连接表必须从 0 开始。
    assert_eq!(server.open_connections(), 0, "前置：服务端会话表应为 0");

    let client = connect_with(&server, &server.auth).await.expect("建连失败");
    let connected = wait_until(RECLAIM_DEADLINE, || async {
        server.open_connections() >= 1
    })
    .await;
    assert!(connected, "建连后服务端应至少有一条连接");

    // 完整交互：TCP 一轮 + UDP 一轮。
    let target = spawn_tcp_target(TargetScript::ReplyThenDrain(pattern(32))).await;
    let mut stream = proxy::tcp_connect(&client, &target.addr.to_string())
        .await
        .expect("tcp_connect 失败");
    let tcp_fut = async {
        stream.write_all(b"roundtrip").await.expect("写入失败");
        stream.finish().expect("半关闭失败");
        let mut buf = vec![0u8; 32];
        let mut got = Vec::new();
        while got.len() < 32 {
            let n = stream.read(&mut buf).await.expect("读取失败");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got
    };
    let got = tokio::time::timeout(IO_TIMEOUT, tcp_fut)
        .await
        .expect("TCP 交互超时");
    assert_eq!(got, pattern(32), "TCP 回包内容不符");

    let udp_target = spawn_udp_target().await;
    let mut session = client.open_udp().await.expect("打开 UDP 会话");
    let payload = pattern(128);
    let dgrams = proxy::udp_out_datagrams(
        session.id,
        &udp_target.addr.to_string().into_bytes(),
        &payload,
        1200,
    )
    .expect("组 UDP datagram");
    for d in &dgrams {
        session.send_raw(d).expect("UDP 发送失败");
    }
    let mut defrag = proxy::OwnedDefragger::default();
    let back = tokio::time::timeout(IO_TIMEOUT, proxy::udp_recv(&mut session, &mut defrag))
        .await
        .expect("等待 UDP 回包超时")
        .expect("会话关闭")
        .expect("UDP 报文解析失败");
    assert_eq!(back.data, payload, "UDP 回包内容不符");

    // 断开：显式关连接（对齐参考 `dialer.go` 的 `CloseWithError`）。
    client
        .connection()
        .close(quinn::VarInt::from_u32(super::CLOSE_ERR_CODE_OK), b"");
    drop(session);
    drop(stream);

    // 后置计数：客户端与服务端的会话表都必须**归零**。
    let client_cleared = wait_until(RECLAIM_DEADLINE, || async {
        client_udp_table(&client).await == ClientUdpTable::Closed
    })
    .await;
    assert!(client_cleared, "客户端会话表应被清空并关闭");
    assert_eq!(
        client_udp_table(&client).await,
        ClientUdpTable::Closed,
        "后置：客户端会话表应归零（已关闭）"
    );

    let server_cleared = wait_until(RECLAIM_DEADLINE, || async {
        server.open_connections() == 0
    })
    .await;
    assert!(server_cleared, "服务端会话表应归零");
    assert_eq!(
        server.open_connections(),
        0,
        "后置：服务端会话表应归零（不增加）"
    );
}

/// B7：承载收尾 —— 客户端**正常半关闭**（发 FIN）后，服务端把 FIN 转成
/// 出站 TCP 的 `shutdown(Write)` ⇒ 目标端读到**干净 EOF**。
///
/// 这是「清理」在**承载级**的证据：服务端 `proxy::relay` 的上行协程
/// 读到 QUIC 流的 EOF ⇒ `otx.shutdown()` ⇒ 目标端读到 EOF。
///
/// ⚠️ 口径说明：服务端**异常**断开（`conn.close()`）时，`proxy::relay`
/// 的下行协程会因写失败而 `break` ⇒ 丢弃 `otx` ⇒ tokio 的
/// `OwnedWriteHalf` drop 也会 `shutdown(Write)`。但**读侧**协程仍在等待
/// 出站 socket 的数据，目标端**不会**立刻看到 EOF（要等目标自己发数据
/// 或关闭）。因此「异常断开 ⇒ 目标端立刻 EOF」不是本仓的语义，
/// 本用例验的是**可确定**的那条路径：正常半关闭 ⇒ 干净 EOF。
#[tokio::test]
async fn cleanup_outbound_tcp_released_on_client_half_close() {
    let server = start_server("cl7", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    // 目标：一直读、不主动关闭（这样目标端看到的 EOF 一定来自服务端）。
    let mut target = spawn_tcp_target(TargetScript::KeepOpen).await;
    let mut stream = proxy::tcp_connect(&client, &target.addr.to_string())
        .await
        .expect("tcp_connect 失败");
    let write_fut = async {
        stream.write_all(b"bye").await.expect("写入失败");
        // 半关闭：只关 QUIC 流的写端（FIN），读方向留着。
        stream.finish().expect("半关闭失败");
    };
    tokio::time::timeout(IO_TIMEOUT, write_fut)
        .await
        .expect("写入 + 半关闭超时");

    // 客户端半关闭 ⇒ 服务端 `relay` 上行读到 EOF ⇒ `otx.shutdown()` ⇒
    // 目标端读到干净 EOF。
    let saw_eof = target.wait_event(|ev| ev == TargetEvent::Eof).await;
    assert!(
        saw_eof,
        "客户端半关闭后服务端的出站 TCP 写端应被关闭（目标端读到干净 EOF）"
    );
}
