// 断开路径：正常断开 / 载荷中途强制断开 ⇒ 服务端会话表归零。
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
