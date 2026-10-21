// 半关闭后的连接复用、UDP 侧不适用、以及半关闭不触发会话回收。
/// A3：半关闭后的复用 —— 同一 QUIC 连接上，半关闭一个 stream 后**还能开
/// 新 stream 并正常收发**（会话表未因半关闭而整体销毁）。
///
/// 这条直接对应矩阵「半关闭」格的关键风险：半关闭若被实现成「拆连接」，
/// 新流就开不出来。
#[tokio::test]
async fn half_close_then_reuse_same_connection() {
    let server = start_server("hc3", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    // 第一条流：正常交互后半关闭。
    let first_target = spawn_tcp_target(TargetScript::ReplyThenDrain(pattern(64))).await;
    let mut first = proxy::tcp_connect(&client, &first_target.addr.to_string())
        .await
        .expect("第一条流 tcp_connect 失败");
    let payload = pattern(128);
    let first_fut = async {
        first.write_all(&payload).await.expect("写入失败");
        first.finish().expect("半关闭失败");
        let mut buf = vec![0u8; 64];
        let mut got = Vec::new();
        while got.len() < 64 {
            let n = first.read(&mut buf).await.expect("读取失败");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got
    };
    let got = tokio::time::timeout(IO_TIMEOUT, first_fut)
        .await
        .expect("第一条流交互超时");
    assert_eq!(got, pattern(64), "第一条流回包内容不符");

    // 第二条流：同一条 QUIC 连接上重新开流，必须能正常收发。
    let second_target = spawn_tcp_target(TargetScript::ReplyThenDrain(pattern(32))).await;
    let mut second = proxy::tcp_connect(&client, &second_target.addr.to_string())
        .await
        .expect("半关闭后应仍能开新流并建连");
    let second_fut = async {
        second.write_all(b"second").await.expect("写入失败");
        second.finish().expect("半关闭失败");
        let mut buf = vec![0u8; 32];
        let mut got = Vec::new();
        while got.len() < 32 {
            let n = second.read(&mut buf).await.expect("读取失败");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got
    };
    let got = tokio::time::timeout(IO_TIMEOUT, second_fut)
        .await
        .expect("第二条流交互超时");
    assert_eq!(got, pattern(32), "半关闭后新流的回包内容不符");

    // 连接本身仍然活着：客户端 UDP 会话表未被清空。
    assert_eq!(
        client_udp_table(&client).await,
        ClientUdpTable::Open,
        "半关闭一个 stream 不应影响整条连接（客户端会话表仍开着）"
    );
}

/// A4：UDP 侧的对应语义 —— UDP 无连接，半关闭**不适用**。
///
/// 本用例把这一格从「❌」变成「**明确的『不适用 + 有据』**」：
/// 1. UDP 路径**不暴露**半关闭概念：`proxy::udp_out_datagrams` /
///    `UdpSession` 的 API 里没有任何 FIN/half-close 入口（只有
///    `send_raw` / `recv_raw`，收发的是**完整数据报**）；
/// 2. 实证：一次 UDP 往返收到的是**完整数据报**（载荷逐字节相符），
///    不存在「半个数据报」这种半关闭中间态。
#[tokio::test]
async fn half_close_is_not_applicable_to_udp_datagrams() {
    let server = start_server("hc4", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");
    let target = spawn_udp_target().await;

    let mut session = client.open_udp().await.expect("打开 UDP 会话");
    let payload = pattern(512);
    let addr_bytes = target.addr.to_string().into_bytes();
    let dgrams =
        proxy::udp_out_datagrams(session.id, &addr_bytes, &payload, 1200).expect("组 UDP datagram");
    for d in &dgrams {
        session.send_raw(d).expect("UDP 发送失败");
    }
    let mut defrag = proxy::OwnedDefragger::default();
    let got = tokio::time::timeout(IO_TIMEOUT, proxy::udp_recv(&mut session, &mut defrag))
        .await
        .expect("等待 UDP 回包超时")
        .expect("会话关闭")
        .expect("UDP 报文解析失败");

    // 断言 1：收到的是**完整数据报**（逐字节相符，无半截）。
    assert_eq!(
        got.data, payload,
        "UDP 收到的是完整数据报，不存在半关闭的中间态"
    );

    // 断言 2：UDP 路径不暴露半关闭概念 —— 会话句柄只有数据报收发，
    // 没有任何 FIN/half-close 入口（类型上就没有）。
    //
    // 编译期证据：`UdpSession` 的公开方法集是
    // `recv_raw` / `send_raw` / `max_datagram_size`（见
    // `quic/client.rs`），没有 `finish` / `shutdown`。
    // 运行期证据：同一会话在「发完一批」之后仍能继续收发 ⇒ 会话没有被
    // 半关闭掉。
    let payload2 = pattern(256);
    let dgrams2 = proxy::udp_out_datagrams(session.id, &addr_bytes, &payload2, 1200)
        .expect("组 UDP datagram");
    for d in &dgrams2 {
        session.send_raw(d).expect("UDP 发送失败");
    }
    let got2 = tokio::time::timeout(IO_TIMEOUT, proxy::udp_recv(&mut session, &mut defrag))
        .await
        .expect("等待 UDP 回包超时")
        .expect("会话关闭")
        .expect("UDP 报文解析失败");
    assert_eq!(got2.data, payload2, "同一 UDP 会话应能继续收发完整数据报");

    // 断言 3：UDP 会话全程未被「半关闭」：客户端会话表仍开着。
    assert_eq!(
        client_udp_table(&client).await,
        ClientUdpTable::Open,
        "UDP 路径不应出现半关闭导致的会话关闭"
    );
}

/// A5：半关闭**不**触发会话回收（半关闭 ≠ 清理）。
///
/// 半关闭一个 stream 之后，承载（QUIC 连接）仍然存活 ⇒ 服务端的连接级
/// 会话表**不应**归零。这条把「半关闭」与「清理」两格在语义上分开：
/// 半关闭只关一个方向，清理才拆连接。
#[tokio::test]
async fn half_close_does_not_reclaim_sessions() {
    let server = start_server("hc5", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    // 先建一条 TCP 承载，确认服务端连接数 ≥ 1。
    let target = spawn_tcp_target(TargetScript::CloseAfterFirstRead).await;
    let mut stream = proxy::tcp_connect(&client, &target.addr.to_string())
        .await
        .expect("tcp_connect 失败");
    let write_fut = async {
        stream.write_all(b"x").await.expect("写入失败");
        stream.finish().expect("半关闭失败");
    };
    tokio::time::timeout(IO_TIMEOUT, write_fut)
        .await
        .expect("写入 + 半关闭超时");

    // 服务端连接数不为 0（承载还活着）。
    let reclaimed = wait_until(RECLAIM_DEADLINE, || async {
        server.open_connections() == 0
    })
    .await;
    assert!(
        !reclaimed,
        "半关闭不应导致会话被回收（服务端连接数应仍 > 0，实际 {}）",
        server.open_connections()
    );
    assert!(
        server.open_connections() >= 1,
        "半关闭后承载仍应存活，服务端连接数 = {}",
        server.open_connections()
    );
}
