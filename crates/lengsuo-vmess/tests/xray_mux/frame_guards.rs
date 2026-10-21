// 用例 D②③④：帧层 fail-closed —— 超限 metaLen、半帧关流、会话上限。
//
// 本文件由 `tests/xray_mux.rs` 用 `include!` 文本并入同一模块；`use` 与共享
// 助手都在入口文件。

// ---------------------------------------------------------------------------
// 用例 D②：帧 length 字段超限 → 本端 fail-closed；Xray 侧断整条 mux 连接。
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn mux_oversized_meta_is_rejected() {
    let Some(bin) = xray_bin() else { return };

    // 本地判据：`FrameMetadata::decode_from` 对 metaLen > 512 必须拒绝
    // （参考 `frame.go:119-121`）。
    let mut oversized = (MAX_META_LEN as u16 + 1).to_be_bytes().to_vec();
    oversized.extend_from_slice(&vec![0u8; MAX_META_LEN + 1]);
    let local = FrameMetadata::decode_from(&mut &oversized[..], false);
    assert!(
        matches!(local, Err(lengsuo_vmess::muxframe::FrameError::MetaTooLong)),
        "本端必须 fail-closed 拒绝超限 metaLen，实际 {local:?}"
    );

    // 互通判据：把同一条超限帧封进 VMess chunk 发给 Xray，参考
    // `frame.go:119-121` 报 invalid metalen → `server.go:363-384` 退出并断连接。
    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = start_fixture(&bin, &uuid);
    let keys = KeySource::generate().expect("生成会话密钥");
    let mut conn = MuxConn::connect(&fixture, &cmd_key, &keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "Mux 建连", e));
    conn.send_wire(&oversized)
        .await
        .unwrap_or_else(|e| fail(&fixture, "写超限帧", e));
    conn.expect_peer_close("超限 metaLen")
        .await
        .unwrap_or_else(|e| fail(&fixture, "超限 metaLen", e));
    eprintln!("OK: 用例 D② 超限 metaLen 本端拒绝且 Xray 关闭连接（读侧 EOF/RST）。");
}

// ---------------------------------------------------------------------------
// 用例 D③：写半个帧后关流 → 服务端关闭且无残留数据（未拨号目标）。
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn mux_truncated_frame_closes_stream() {
    let Some(bin) = xray_bin() else { return };
    let (target_addr, accepted, received) = spawn_counting_listener().await;
    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = start_fixture(&bin, &uuid);
    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], target_addr.port());

    let mut conn = MuxConn::connect(&fixture, &cmd_key, &keys)
        .await
        .unwrap_or_else(|e| fail(&fixture, "Mux 建连", e));

    // 完整 New 帧（含数据段）截成两半，只写前半段后 FIN。
    let mut sender = StreamSender::new(1, TargetNetwork::Tcp, target);
    let mut frame = Vec::new();
    sender
        .send_new(&mut frame, Some(b"must-not-arrive"))
        .expect("New 帧");
    let half = frame.len() / 2;
    assert!(half >= 2, "截断点必须落在帧长度字段之后");
    conn.send_wire(&frame[..half])
        .await
        .unwrap_or_else(|e| fail(&fixture, "写半帧", e));
    conn.shutdown_write().await;

    conn.expect_peer_close("截断帧")
        .await
        .unwrap_or_else(|e| fail(&fixture, "截断帧", e));

    // 截断点 = 完整 New 元数据 + 数据长度前缀（14+2=16 字节），载荷本体缺失。
    // 参考会先 dispatch 再读数据，故允许拨号；但半截载荷绝不能写到后端。
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        received.load(Ordering::Relaxed),
        0,
        "截断帧的数据段不得有任何字节到达后端\n{}",
        fixture.report()
    );
    assert!(
        accepted.load(Ordering::Relaxed) <= 1,
        "半帧最多触发一次拨号，不得重复派发\n{}",
        fixture.report()
    );
    eprintln!("OK: 用例 D③ 半帧 + FIN 后服务端关闭（EOF/RST），后端零字节。");
}

// ---------------------------------------------------------------------------
// 用例 D④：会话上限触顶 → 按 SessionStrategy 拒绝，而非无限分配。
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn mux_session_limit_rejects_not_unbounded() {
    let Some(_bin) = xray_bin() else { return };

    // 参考 `session.go:54-73` Allocate：MaxConcurrency 限并发、
    // MaxConnection 限累计，0 表示不限。
    let mut client = ClientSession::new(SessionStrategy {
        max_concurrency: 1,
        max_connection: 2,
    });
    let target = TargetAddr::V4([127, 0, 0, 1], 9);

    let first = client
        .open(TargetNetwork::Tcp, target.clone())
        .expect("第 1 条应分配成功");
    assert_eq!(first.id, 1);
    assert!(
        client.open(TargetNetwork::Tcp, target.clone()).is_none(),
        "并发上限 1 时第 2 条必须被拒"
    );
    assert_eq!(client.table().size(), 1);
    assert_eq!(client.table().count(), 1, "被拒的分配不得递增 count");

    client.close_local(first.id, false);
    assert_eq!(client.table().size(), 0);

    let second = client
        .open(TargetNetwork::Tcp, target.clone())
        .expect("释放并发后应可再分配");
    assert_eq!(second.id, 2);
    assert!(
        client.open(TargetNetwork::Tcp, target.clone()).is_none(),
        "累计上限 2 时第 3 条必须被拒"
    );
    assert_eq!(client.table().count(), 2);
    eprintln!("OK: 用例 D④ 会话上限按 SessionStrategy 拒绝（concurrency/connection 双限）。");
}
