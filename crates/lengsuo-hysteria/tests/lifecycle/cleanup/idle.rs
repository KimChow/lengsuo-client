// 服务端 UDP 会话表的**按条目**空闲回收（对应参考 `clean()`）。
/// B5：服务端 UDP 会话表的**按条目**空闲回收（对应参考 `clean()`）。
///
/// 参考 `hub.go` `clean()`：每 `idleCleanupInterval` 扫一次表，把超过
/// `udpIdleTimeout` 未活跃的会话 `close()`（`delete(m.m, id)`）。本仓
/// 对应 `quic::server::UdpManager::clean`，由
/// `UDP_IDLE_CLEANUP_INTERVAL_SECS`（5s）的 ticker 驱动。
///
/// 外部可观测等价物：服务端为**每个** UDP 会话绑定一条**独立的出站
/// socket**（`proxy::serve_udp_session` 里 `UdpSocket::bind` + `connect`）
/// ⇒ 条目被移除后重建会换源端口。因此：
/// 1. 会话**活跃**时源端口**不变**（对照组：条目还在表里，没被误回收）；
/// 2. 空闲超阈后，同一会话 ID 的下一次投递**换源端口**
///    （= 旧条目已从表里移除、会话被重建）。
///
/// ⚠️ 时序：回收由 5s 的 ticker 驱动 ⇒ 空闲阈值 1s 时，最早也要等到
/// 下一个 tick 才会回收 ⇒ 轮询窗口必须留足（`RECLAIM_DEADLINE` = 25s）。
#[tokio::test]
async fn cleanup_server_udp_session_reclaimed_by_idle_timeout() {
    // 空闲阈值 1s（回收动作由 5s 的 ticker 驱动 ⇒ 需留足轮询时间）。
    let server = start_server("cl5", 1).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");
    let target = spawn_udp_target().await;

    let mut session = client.open_udp().await.expect("打开 UDP 会话");
    let addr_bytes = target.addr.to_string().into_bytes();
    let payload = pattern(64);
    let mut defrag = proxy::OwnedDefragger::default();

    // 第一次投递：记录服务端出站 socket 的源端口。
    let dgrams =
        proxy::udp_out_datagrams(session.id, &addr_bytes, &payload, 1200).expect("组 UDP datagram");
    for d in &dgrams {
        session.send_raw(d).expect("UDP 发送失败");
    }
    tokio::time::timeout(IO_TIMEOUT, proxy::udp_recv(&mut session, &mut defrag))
        .await
        .expect("等待 UDP 回包超时")
        .expect("会话关闭")
        .expect("UDP 报文解析失败");

    let first_src = target
        .packets()
        .first()
        .map(|(from, _)| *from)
        .expect("目标应至少收到一个数据报");
    // 活跃时源端口不变（对照组：条目仍在表里）。
    let second_fut = async {
        let dgrams = proxy::udp_out_datagrams(session.id, &addr_bytes, &payload, 1200)
            .expect("组 UDP datagram");
        for d in &dgrams {
            session.send_raw(d).expect("UDP 发送失败");
        }
        proxy::udp_recv(&mut session, &mut defrag).await
    };
    let back = tokio::time::timeout(IO_TIMEOUT, second_fut)
        .await
        .expect("等待 UDP 回包超时")
        .expect("会话关闭")
        .expect("UDP 报文解析失败");
    assert_eq!(back.data, payload, "UDP 回包内容不符");
    let second_src = target
        .packets()
        .last()
        .map(|(from, _)| *from)
        .expect("目标应至少收到一个数据报");
    assert_eq!(
        first_src, second_src,
        "会话活跃时服务端不应重建出站 socket（源端口不该变）"
    );
    let mut seen = target.packets().len();

    // 静默超过空闲阈值 ⇒ 服务端条目被回收 ⇒ 下一次投递换源端口。
    //
    // 关键：投递本身会刷新服务端的 `last_seen`（`UdpManager::feed`）⇒
    // **边轮询边投递会让会话永远不空闲**。所以每次尝试必须先**静默**
    // 一个完整窗口（> 空闲阈值 1s，且跨过 5s 的回收 tick），再投递一次
    // 看源端口是否变了。
    //
    // 断言仍是「轮询 + 条件成立」：每次尝试都有单次上限，总时长受
    // `RECLAIM_DEADLINE` 约束，不是「睡够就直接断言」。
    const IDLE_GAP: Duration = Duration::from_secs(7);
    let mut third_src = second_src;
    let deadline = tokio::time::Instant::now() + RECLAIM_DEADLINE;
    while tokio::time::Instant::now() < deadline {
        // 静默窗口：让服务端把这条会话判定为空闲并回收。
        tokio::time::sleep(IDLE_GAP).await;
        let dgrams = proxy::udp_out_datagrams(session.id, &addr_bytes, &payload, 1200)
            .expect("组 UDP datagram");
        for d in &dgrams {
            session.send_raw(d).expect("UDP 发送失败");
        }
        // 等目标收到新数据报（源端口就在里面）。
        let got_new = tokio::time::timeout(IO_TIMEOUT, async {
            loop {
                if target.packets().len() > seen {
                    return true;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .unwrap_or(false);
        if !got_new {
            break;
        }
        seen = target.packets().len();
        third_src = target
            .packets()
            .last()
            .map(|(from, _)| *from)
            .expect("目标应至少收到一个数据报");
        if third_src != first_src {
            break;
        }
    }
    assert_ne!(
        third_src, first_src,
        "空闲超时后服务端应回收该 UDP 会话条目（出站 socket 应重建，源端口应变化）"
    );
}
