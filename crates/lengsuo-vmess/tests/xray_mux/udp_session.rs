// 用例 B：UDP over mux（mux 内 UDP 会话，`TransferTypePacket`）。
//
// 本文件由 `tests/xray_mux.rs` 用 `include!` 文本并入同一模块；`use` 与共享
// 助手都在入口文件。

// ---------------------------------------------------------------------------
// 用例 B：UDP over mux（mux 内 UDP 会话，`TransferTypePacket`）。
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn mux_udp_single_session() {
    let Some(bin) = xray_bin() else { return };
    let echo_addr = spawn_udp_echo().await;
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
    let (id, capture) = open_session(&mut client, TargetNetwork::Udp, target.clone());

    let mut sender = StreamSender::new(id, TargetNetwork::Udp, target.clone());
    let first = b"udp-mux-datagram-1";
    let mut wire = Vec::new();
    sender
        .send_new(&mut wire, Some(first))
        .expect("New + 首数据报");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 New + 首数据报", e));
    conn.read_response_header(&keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "读响应头", e));
    pump_until(
        &mut conn,
        &mut client,
        || capture.len() >= first.len(),
        "UDP 第 1 个数据报",
    )
    .await
    .unwrap_or_else(|e| fail(&fixture, "UDP 第 1 个数据报", e));
    assert_eq!(
        capture.snapshot().as_slice(),
        first,
        "第 1 个数据报必须逐字节回显\n{}",
        fixture.report()
    );

    let second = b"udp-mux-datagram-2-with-different-len";
    wire.clear();
    sender
        .send_keep(&mut wire, second)
        .expect("Keep 第 2 个数据报");
    conn.send_wire(&wire)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写第 2 个数据报", e));
    let expected_len = first.len() + second.len();
    pump_until(
        &mut conn,
        &mut client,
        || capture.len() >= expected_len,
        "UDP 第 2 个数据报",
    )
    .await
    .unwrap_or_else(|e| fail(&fixture, "UDP 第 2 个数据报", e));
    assert_eq!(
        capture.snapshot().as_slice(),
        [first.as_slice(), second.as_slice()].concat(),
        "两个数据报必须逐字节回显且不串包\n{}",
        fixture.report()
    );

    let end = client.close_local(id, false);
    conn.send_wire(&end)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写 End 帧", e));
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("等待服务端 End 帧超时");
        let (meta, payload) = tokio::time::timeout(remaining, conn.next_frame())
            .await
            .expect("等待服务端 End 帧超时")
            .unwrap_or_else(|e| fail(&fixture, "等待服务端 End 帧", e));
        let is_end = meta.status == SessionStatus::End && meta.session_id == id;
        client
            .handle_frame(&meta, payload.as_deref())
            .unwrap_or_else(|e| fail(&fixture, "处理 End 帧", e.to_string()));
        if is_end {
            break;
        }
    }
    assert!(client.table().ids().is_empty(), "UDP 会话必须回收");
    eprintln!("OK: 用例 B UDP over mux（2 个数据报逐字节）通过。");
}
