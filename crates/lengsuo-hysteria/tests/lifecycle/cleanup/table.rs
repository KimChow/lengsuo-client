// 客户端侧回收：服务端主动关闭 ⇒ 客户端会话表清空并关闭。
/// B4：客户端侧回收 —— 服务端主动关闭 ⇒ 客户端会话表同样清空。
///
/// 对应参考 `dialer.go` `udpSessionManagerClient.run()`：连接断开 ⇒
/// `m.closed = true` + 关闭全部会话；`udp()` 随后返回 `closed` 错误。
///
/// 判据：
/// 1. 客户端 `open_udp()` 从「能开」变成「已关闭」（`UdpManager.closed`
///    为真 ⇒ `close_all()` 已清空 `sessions`）；
/// 2. 已开出的 UDP 会话 `recv_raw()` 返回 `None`（该条目的 sender 被丢弃
///    ⇒ 逐条证据）。
#[tokio::test]
async fn cleanup_client_table_cleared_when_server_closes() {
    let server = start_server("cl4", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    // 先开一个 UDP 会话（往客户端表里放一个条目）。
    let mut session = client.open_udp().await.expect("打开 UDP 会话");
    assert_eq!(
        client_udp_table(&client).await,
        ClientUdpTable::Open,
        "断开前客户端会话表应开着"
    );

    // 服务端主动关闭（对齐参考 `Listener.Close()`：关端点 ⇒ 所有连接关闭）。
    server.close();

    // 判据 1：客户端会话表被清空并关闭（`open_udp()` 必失败）。
    let cleared = wait_until(RECLAIM_DEADLINE, || async {
        client_udp_table(&client).await == ClientUdpTable::Closed
    })
    .await;
    assert!(cleared, "服务端关闭后客户端会话表应被清空并关闭");
    assert_eq!(
        client_udp_table(&client).await,
        ClientUdpTable::Closed,
        "客户端会话表应已关闭（表已清空）"
    );

    // 判据 2：已开出的会话 `recv_raw()` 返回 `None`（条目被丢弃）。
    let closed = tokio::time::timeout(IO_TIMEOUT, session.recv_raw())
        .await
        .expect("等待会话关闭超时");
    assert!(closed.is_none(), "会话表条目应被丢弃（recv_raw 返回 None）");
}
