//! B 组：清理（cleanup）—— 对应 `docs/audit-all1.md` §3 矩阵的
//! 「清理」格（原为 ❌：只有「错误/debug 不泄漏」，无会话回收）。
//!
//! 语义基线（参考实现）：
//! - `transport/internet/hysteria/hub.go` `udpSessionManagerServer.run()`：
//!   QUIC 连接读错误 ⇒ `break` ⇒ `close(m.stopCh)` ⇒ **关闭全部 UDP 会话**
//!   （`close()` 里 `close(udpConn.ch)` + `delete(m.m, udpConn.id)`）。
//! - 同文件 `clean()`：每 `idleCleanupInterval`（参考 1s）扫一次表，
//!   超过 `udpIdleTimeout` 未活跃的会话被 `close()`（**按条目**回收）。
//! - `transport/internet/hysteria/dialer.go` `udpSessionManagerClient.run()`：
//!   客户端侧同样在连接断开时 `m.closed = true` + 关闭全部会话；
//!   `udp()` 在 `m.closed` 时返回 `errors.New("closed")`。
//! - `proxy/hysteria/server.go`：TCP 承载交给 `DispatchLink`，连接关闭时
//!   `buf.Copy` 读到 EOF ⇒ 出站连接被 `defer conn.Close()` 释放。
//!
//! 本仓对应实现：`quic::server::run_udp_manager`（连接错误 ⇒ `close_all()`
//! 清空 `sessions`）、`quic::server::UdpManager::clean`（空闲按条目回收）、
//! `quic::client` 的 `UdpManager::close_all`（客户端侧清空 + `closed`）、
//! `proxy::relay`（承载收尾 ⇒ 出站 socket 释放）。
//!
//! # 客户端会话表的「归零」判据
//!
//! 客户端 `UdpManager`（`quic/client.rs`）的 `sessions` 是私有字段，集成
//! 测试读不到条目数；但 `close_all()` 是**唯一**把 `closed` 置真的地方，
//! 且它与 `sessions.clear()` 在同一临界区内完成 ⇒
//! **`open_udp()` 返回 `Err(LocallyClosed)` ⟺ 表已被清空**。
//! 再配合「已开出的会话 `recv_raw()` 返回 `None`」（该条目的 sender 已被
//! 丢弃）⇒ 逐条证据 + 整体证据都齐。

use super::{
    client_udp_table, connect_with, pattern, spawn_tcp_target, spawn_udp_target, start_server,
    wait_until, ClientUdpTable, TargetEvent, TargetScript, IO_TIMEOUT, POLL_INTERVAL,
    RECLAIM_DEADLINE,
};
use std::time::Duration;

use lengsuo_hysteria::proxy;

/// B1：服务端会话回收 —— 客户端完成一轮 TCP + UDP 交互后断开 ⇒ 服务端的
/// 会话表**最终为空**。
///
/// 判据（服务端**连接级**会话表）：`Server::open_connections()` 归零。
/// 服务端 `quic::server::run_udp_manager` 在 QUIC 连接断开时 `close_all()`，
/// `h3_server::serve_connection` 返回后 `conn.close(...)` ⇒ 端点上的连接
/// 归零。
///
/// 归零判据是「**归零**」而不是「不增加」（任务书第 8 条硬判据）。
#[tokio::test]
async fn cleanup_server_reclaims_sessions_after_client_disconnect() {
    let server = start_server("cl1", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    // 前置：连接建立后服务端连接数 ≥ 1（否则「归零」是空断言）。
    let connected = wait_until(RECLAIM_DEADLINE, || async {
        server.open_connections() >= 1
    })
    .await;
    assert!(connected, "建连后服务端应至少有一条连接");

    // --- 一轮 TCP 交互 ---
    let target = spawn_tcp_target(TargetScript::ReplyThenDrain(pattern(64))).await;
    let mut stream = proxy::tcp_connect(&client, &target.addr.to_string())
        .await
        .expect("tcp_connect 失败");
    let tcp_fut = async {
        stream.write_all(b"hello").await.expect("写入失败");
        stream.finish().expect("半关闭失败");
        let mut buf = vec![0u8; 64];
        let mut got = Vec::new();
        while got.len() < 64 {
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
    assert_eq!(got, pattern(64), "TCP 回包内容不符");

    // --- 一轮 UDP 交互 ---
    let udp_target = spawn_udp_target().await;
    let mut session = client.open_udp().await.expect("打开 UDP 会话");
    let payload = pattern(256);
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

    // --- 客户端断开 ---
    // 对齐参考 `dialer.go` 的 `c.conn.CloseWithError(closeErrCodeOK, "")`：
    // 主动关掉 QUIC 连接 ⇒ 服务端侧连接读错误 ⇒ 会话表整体回收。
    client
        .connection()
        .close(quinn::VarInt::from_u32(super::CLOSE_ERR_CODE_OK), b"");
    drop(session);
    drop(stream);
    drop(client);

    // --- 判据：服务端会话表最终归零 ---
    let reclaimed = wait_until(RECLAIM_DEADLINE, || async {
        server.open_connections() == 0
    })
    .await;
    assert!(
        reclaimed,
        "客户端断开后服务端会话表应归零，实际连接数 = {}",
        server.open_connections()
    );
    assert_eq!(server.open_connections(), 0, "服务端会话表应归零");
}

/// B2：异常断开也回收 —— 客户端在载荷中途强制断开 ⇒ 服务端**不残留会话**
/// （且不 panic、不泄漏任务）。
///
/// 「强制断开」= 直接把 QUIC 连接 `close()` 掉（不走正常 FIN），
/// 对应参考 `hub.go` 里 `ReceiveDatagram` 返回错误 ⇒ `run()` 退出 ⇒
/// `close_all()`。
#[tokio::test]
async fn cleanup_server_reclaims_after_abrupt_disconnect() {
    let server = start_server("cl2", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    let connected = wait_until(RECLAIM_DEADLINE, || async {
        server.open_connections() >= 1
    })
    .await;
    assert!(connected, "建连后服务端应至少有一条连接");

    // 建一条承载，只写一半载荷就强制断开。
    let target = spawn_tcp_target(TargetScript::CloseAfterFirstRead).await;
    let mut stream = proxy::tcp_connect(&client, &target.addr.to_string())
        .await
        .expect("tcp_connect 失败");
    let half = pattern(1024);
    let write_fut = async {
        stream.write_all(&half).await.expect("写入失败");
    };
    tokio::time::timeout(IO_TIMEOUT, write_fut)
        .await
        .expect("写入超时");

    // 强制断开：直接关掉 QUIC 连接（应用错误码 0x100 = 参考 closeErrCodeOK）。
    client
        .connection()
        .close(quinn::VarInt::from_u32(super::CLOSE_ERR_CODE_OK), b"");

    // 判据：服务端会话表最终归零（异常路径同样回收）。
    let reclaimed = wait_until(RECLAIM_DEADLINE, || async {
        server.open_connections() == 0
    })
    .await;
    assert!(
        reclaimed,
        "强制断开后服务端不应残留会话，实际连接数 = {}",
        server.open_connections()
    );
    assert_eq!(server.open_connections(), 0, "服务端会话表应归零");

    // 不 panic：服务端的 accept_loop 任务仍应存活。
    assert!(
        !server.task.is_finished(),
        "服务端 accept_loop 任务不应因异常断开而结束（不得 panic）"
    );
}

/// B3：畸形帧 ⇒ 服务端不残留会话（且不 panic）。
///
/// 「畸形帧」= 一条**残缺的 TCPRequest**：帧类型 `0x401` 正确，但请求体
/// 只写了一半（地址长度声明 64 字节、只给 4 字节）就结束流。
///
/// 对应参考 `protocol.go` `ReadTCPRequest` 的 `io.ReadFull` 短读 ⇒ 错误；
/// 本仓 `proxy::server_read_tcp_request` 短读 ⇒ `Truncated` ⇒
/// `recv.read()` 得 `None` ⇒ `ProxyError::PrematureEof` ⇒ **不建立出站
/// 连接**、不建承载。
///
/// 判据：
/// 1. 服务端**没有**建立任何出站 TCP 连接（`target.accepts() == 0`）⇒
///    畸形帧没被当成合法请求放行；
/// 2. 客户端读到的是**干净 EOF**（服务端没写任何响应帧 ⇒ 缓冲空），
///    而不是「EOF 且有残留」；
/// 3. 断开后服务端会话表归零。
#[tokio::test]
async fn cleanup_server_rejects_malformed_frame_without_residue() {
    let server = start_server("cl3", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    let connected = wait_until(RECLAIM_DEADLINE, || async {
        server.open_connections() >= 1
    })
    .await;
    assert!(connected, "建连后服务端应至少有一条连接");

    // 本地目标：只要服务端**建立**了出站连接，这里就会被接入一次。
    let target = spawn_tcp_target(TargetScript::CloseAfterFirstRead).await;

    // 开一条双向流，写一条**残缺的 TCPRequest** 后立刻结束流。
    let (mut send, recv) = client.open_tcp().await.expect("开流失败");
    // 帧类型 0x401（TCPRequest）= varint 编码 [0x44, 0x01]；
    // 地址长度 varint：64（2 字节编码 [0x40, 0x40]）；
    // 只给 4 字节地址（声明要 64 字节）⇒ 残帧。
    let mut malformed = vec![0x44, 0x01, 0x40, 0x40];
    malformed.extend_from_slice(b"127.");
    let write_fut = async {
        send.write_all(&malformed).await.expect("写入畸形帧失败");
        send.finish().expect("关闭流失败");
    };
    tokio::time::timeout(IO_TIMEOUT, write_fut)
        .await
        .expect("写入畸形帧超时");

    // 服务端应结束这条流，且**没写任何响应帧** ⇒ 客户端读到干净 EOF。
    let outcome = tokio::time::timeout(IO_TIMEOUT, super::read_to_eof(recv))
        .await
        .expect("等待畸形帧流结束超时");
    match outcome {
        super::ReadOutcome::CleanEof { data } => assert!(
            data.is_empty(),
            "畸形帧路径服务端不应写出任何响应帧（读到 {} 字节）",
            data.len()
        ),
        super::ReadOutcome::EofWithResidue { data } => {
            panic!("畸形帧被当成了带响应的请求（残留 {data:?}）——协议错误被放行")
        }
        super::ReadOutcome::ReadError { err, .. } => {
            panic!("畸形帧路径应读到干净 EOF，而不是读错误：{err}");
        }
    }

    // 判据 1：服务端**没有**建立出站连接（畸形帧没被当成合法请求）。
    assert_eq!(
        target.accepts(),
        0,
        "残缺 TCPRequest 不得让服务端建立出站连接（不得放行）"
    );

    // 断开连接后，服务端会话表归零。
    client
        .connection()
        .close(quinn::VarInt::from_u32(super::CLOSE_ERR_CODE_OK), b"");
    let reclaimed = wait_until(RECLAIM_DEADLINE, || async {
        server.open_connections() == 0
    })
    .await;
    assert!(
        reclaimed,
        "畸形帧后断开，服务端不应残留会话，实际连接数 = {}",
        server.open_connections()
    );
    assert_eq!(server.open_connections(), 0, "服务端会话表应归零");
}

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
