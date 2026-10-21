// 用例 C：同一 mux 会话表内 TCP/UDP 两条并发 session，不串包。
//
// 本文件由 `tests/xray_mux.rs` 用 `include!` 文本并入同一模块；`use` 与共享
// 助手都在入口文件。

// ---------------------------------------------------------------------------
// 用例 C：同一 mux 会话表内 TCP/UDP 两条并发 session，不串包。
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn mux_multi_session_parallel() {
    let Some(bin) = xray_bin() else { return };
    let (tcp_echo_addr, _tcp_task) = codec::spawn_echo().await;
    let udp_echo_addr = spawn_udp_echo().await;
    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = start_fixture(&bin, &uuid);
    let keys = KeySource::generate().expect("生成会话密钥");

    let tcp_target = TargetAddr::V4([127, 0, 0, 1], tcp_echo_addr.port());
    let udp_target = TargetAddr::V4([127, 0, 0, 1], udp_echo_addr.port());

    let mut conn = MuxConn::connect(&fixture, &cmd_key, &keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "Mux 建连", e));
    let mut client = ClientSession::new(SessionStrategy::default());
    let (tcp_id, tcp_capture) = open_session(&mut client, TargetNetwork::Tcp, tcp_target.clone());
    let (udp_id, udp_capture) = open_session(&mut client, TargetNetwork::Udp, udp_target.clone());
    assert_eq!((tcp_id, udp_id), (1, 2), "id 必须按分配顺序自增");
    assert_eq!(
        client.table().ids(),
        vec![1, 2],
        "两条会话必须同时登记在表内"
    );
    assert_eq!(client.table().count(), 2, "累计分配数必须为 2");

    let tcp_marker = b"tcp-session-marker".to_vec();
    let udp_marker = b"udp-session-marker".to_vec();

    let mut tcp_sender = StreamSender::new(tcp_id, TargetNetwork::Tcp, tcp_target.clone());
    let mut udp_sender = StreamSender::new(udp_id, TargetNetwork::Udp, udp_target.clone());
    let mut wire = Vec::new();
    tcp_sender
        .send_new(&mut wire, Some(&tcp_marker))
        .expect("TCP New");
    udp_sender
        .send_new(&mut wire, Some(&udp_marker))
        .expect("UDP New");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写两条 New", e));
    conn.read_response_header(&keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "读响应头", e));

    pump_until(
        &mut conn,
        &mut client,
        || tcp_capture.len() >= tcp_marker.len() && udp_capture.len() >= udp_marker.len(),
        "双会话回程",
    )
    .await
    .unwrap_or_else(|e| fail(&fixture, "双会话回程", e));

    assert_eq!(
        tcp_capture.snapshot(),
        tcp_marker,
        "TCP 会话不得收到 UDP 回程\n{}",
        fixture.report()
    );
    assert_eq!(
        udp_capture.snapshot(),
        udp_marker,
        "UDP 会话不得收到 TCP 回程\n{}",
        fixture.report()
    );

    let tcp_end = client.close_local(tcp_id, false);
    let udp_end = client.close_local(udp_id, false);
    conn.send_wire(&tcp_end)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 TCP End", e));
    conn.send_wire(&udp_end)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 UDP End", e));

    let mut ended = BTreeSet::new();
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    while ended.len() < 2 {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("等待两条 End 帧超时");
        let (meta, payload) = tokio::time::timeout(remaining, conn.next_frame())
            .await
            .expect("等待两条 End 帧超时")
            .unwrap_or_else(|e| fail(&fixture, "等待 End 帧", e));
        if meta.status == SessionStatus::End {
            ended.insert(meta.session_id);
        }
        client
            .handle_frame(&meta, payload.as_deref())
            .unwrap_or_else(|e| fail(&fixture, "处理 End 帧", e.to_string()));
    }
    assert_eq!(
        ended,
        BTreeSet::from([tcp_id, udp_id]),
        "服务端必须逐条回 End"
    );
    assert!(client.table().ids().is_empty(), "两条会话必须全部回收");
    assert_eq!(
        client.table().count(),
        2,
        "回收不得重置累计分配数（参考 Count()）"
    );
    eprintln!("OK: 用例 C 双会话（TCP+UDP）并行、无串包、id 分配/回收断言通过。");
}
