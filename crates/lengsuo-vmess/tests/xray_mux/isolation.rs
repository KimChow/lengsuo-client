// 用例 D①：未知 session id 的 Keep 帧 → 不得 panic、不得投递到错误 session。
//
// 本文件由 `tests/xray_mux.rs` 用 `include!` 文本并入同一模块；`use` 与共享
// 助手都在入口文件。

// ---------------------------------------------------------------------------
// 用例 D①：未知 session id 的 Keep 帧 → 不得 panic、不得投递到错误 session。
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn mux_unknown_session_keep_is_isolated() {
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
    let mut sender = StreamSender::new(id, TargetNetwork::Tcp, target.clone());

    let alive = b"alive-session";
    let mut wire = Vec::new();
    sender.send_new(&mut wire, Some(alive)).expect("New");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 New", e));
    conn.read_response_header(&keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "读响应头", e));
    pump_until(
        &mut conn,
        &mut client,
        || capture.len() >= alive.len(),
        "存活会话首包",
    )
    .await
    .unwrap_or_else(|e| fail(&fixture, "存活会话首包", e));

    // 未知 id 的 Keep：参考 `server.go:300-312` 回 End 并丢弃数据。
    let ghost = encode_frame_with_payload(
        0xFFFF,
        SessionStatus::Keep,
        OPTION_DATA,
        None,
        Some(b"ghost-payload"),
    )
    .expect("构造未知会话 Keep");
    conn.send_wire(&ghost)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写未知会话 Keep", e));

    let mut saw_end = false;
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    while !saw_end {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("未知会话未回 End（超时）");
        let (meta, payload) = tokio::time::timeout(remaining, conn.next_frame())
            .await
            .expect("未知会话未回 End（超时）")
            .unwrap_or_else(|e| fail(&fixture, "读未知会话响应", e));
        if meta.status == SessionStatus::End && meta.session_id == 0xFFFF {
            saw_end = true;
        }
        client
            .handle_frame(&meta, payload.as_deref())
            .unwrap_or_else(|e| fail(&fixture, "处理未知会话帧", e.to_string()));
    }
    assert!(
        !capture
            .snapshot()
            .windows(b"ghost-payload".len())
            .any(|w| w == b"ghost-payload"),
        "未知会话的数据不得投递到存活会话\n{}",
        fixture.report()
    );

    // 存活会话必须仍可用。
    let still = b"-still-alive";
    wire.clear();
    sender.send_keep(&mut wire, still).expect("Keep");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写存活会话 Keep", e));
    let expected_len = alive.len() + still.len();
    pump_until(
        &mut conn,
        &mut client,
        || capture.len() >= expected_len,
        "存活会话续传",
    )
    .await
    .unwrap_or_else(|e| fail(&fixture, "存活会话续传", e));
    assert_eq!(
        capture.snapshot().as_slice(),
        [alive.as_slice(), still.as_slice()].concat(),
        "存活会话回程必须完整\n{}",
        fixture.report()
    );
    eprintln!("OK: 用例 D① 未知 session id Keep 被隔离（回 End、无串包、无 panic）。");
}
