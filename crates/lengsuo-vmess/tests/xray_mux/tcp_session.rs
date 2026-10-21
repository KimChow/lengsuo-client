// 用例 A：TCP over mux（含「首包 100ms 超时 → 只发 New 元数据」路径与 8KiB
// 分片边界）。
//
// 本文件由 `tests/xray_mux.rs` 用 `include!` 文本并入同一模块（用例名不带模块
// 前缀，与拆分前逐字一致）；`use` 与共享助手都在入口文件。

// ---------------------------------------------------------------------------
// 用例 A：TCP over mux（含「首包 100ms 超时 → 只发 New 元数据」路径与 8KiB
// 分片边界）。
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn mux_tcp_single_session() {
    let Some(bin) = xray_bin() else { return };
    let (echo_addr, _echo_task) = codec::spawn_echo().await;
    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = start_fixture(&bin, &uuid);
    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());

    let mut conn = MuxConn::connect(&fixture, &cmd_key, &keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "Mux 建连", e));
    let mut client = ClientSession::new(SessionStrategy::default());
    let (id, capture) = open_session(&mut client, TargetNetwork::Tcp, target.clone());
    assert_eq!(id, 1, "参考 `SessionManager.Allocate` 从 count=1 起分配");
    assert_eq!(client.table().ids(), vec![id], "首个会话 id 必须从 1 开始");

    // 1) 模拟 `writeFirstPayload` 的 100ms 超时：New 只写元数据（无 OptionData）。
    let mut sender = StreamSender::new(id, TargetNetwork::Tcp, target.clone());
    let mut wire = Vec::new();
    sender.send_new(&mut wire, None).expect("New 元数据帧");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 New 元数据帧", e));
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 2) 首个 Keep 帧携带首包；此时服务端才会以首个回程数据刷出响应头。
    let first = b"hello-mux-tcp";
    wire.clear();
    sender.send_keep(&mut wire, first).expect("Keep 首包");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 Keep 首包", e));
    conn.read_response_header(&keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "读响应头", e));

    pump_until(
        &mut conn,
        &mut client,
        || capture.len() >= first.len(),
        "TCP 首包回程",
    )
    .await
    .unwrap_or_else(|e| fail(&fixture, "TCP 首包回程", e));
    assert_eq!(
        capture.snapshot().as_slice(),
        first,
        "TCP 首包必须逐字节回显\n{}",
        fixture.report()
    );

    // 3) 跨 8KiB 分片：参考 `Writer.WriteMultiBuffer` 对 Stream 按 8KiB 切帧。
    let large: Vec<u8> = (0..9000).map(|i| (i % 251) as u8).collect();
    wire.clear();
    sender.send_keep(&mut wire, &large).expect("Keep 大载荷");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写大载荷", e));

    let expected_len = first.len() + large.len();
    pump_until(
        &mut conn,
        &mut client,
        || capture.len() >= expected_len,
        "TCP 大载荷回程",
    )
    .await
    .unwrap_or_else(|e| fail(&fixture, "TCP 大载荷回程", e));
    let got = capture.snapshot();
    assert_eq!(got.len(), expected_len, "回程字节数不一致");
    assert_eq!(&got[..first.len()], first, "首段逐字节不一致");
    assert_eq!(&got[first.len()..], &large[..], "大载荷段逐字节不一致");

    // 4) 本地 End：发 End 帧，服务端应回 End 帧并回收该 session。
    let end = client.close_local(id, false);
    conn.send_wire(&end)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 End 帧", e));
    let mut remote_end = None;
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    while remote_end.is_none() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("等待服务端 End 帧超时");
        let (meta, payload) = tokio::time::timeout(remaining, conn.next_frame())
            .await
            .expect("等待服务端 End 帧超时")
            .unwrap_or_else(|e| fail(&fixture, "等待服务端 End 帧", e));
        if meta.status == SessionStatus::End && meta.session_id == id {
            remote_end = Some(meta.option);
        }
        client
            .handle_frame(&meta, payload.as_deref())
            .unwrap_or_else(|e| fail(&fixture, "处理 End 帧", e.to_string()));
    }
    // 参考 `server.go:111-120`：handleStatusEnd → `s.Close(false)` 中断
    // `s.input`，`handle()` 的 `buf.Copy` 报错并置 `writer.hasError`
    // （`writer.go:122-135`）→ 客户端主动 End 时回程 End 带 OptionError。
    assert_eq!(
        remote_end,
        Some(OPTION_ERROR),
        "客户端主动 End 后，参考实现回程 End 带 OptionError"
    );
    assert!(
        client.table().ids().is_empty(),
        "本地会话表必须回收干净: {:?}",
        client.table().ids()
    );
    eprintln!("OK: 用例 A TCP over mux（含首包超时/8KiB 分片/End 回收）通过。");
}
