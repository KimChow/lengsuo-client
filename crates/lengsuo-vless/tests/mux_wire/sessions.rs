// ③ 会话与并发：上限、未命中帧的应答、多会话隔离、目标地址可查。
/// 会话并发上限：达到 `MaxConcurrency` 后必须显式报错（参考 `Allocate` 返回 nil）。
#[tokio::test]
async fn mux_wire_enforces_concurrency_limit() {
    let (carrier, _peer) = carrier();
    let strategy = Strategy {
        max_concurrency: 1,
        max_connection: 0,
    };
    let mut wire = MuxWire::new(carrier, strategy);
    let _first = wire
        .open(target(443), None, DEFAULT_DEADLINE)
        .await
        .expect("首个会话可开");
    let error = wire
        .open(target(443), None, DEFAULT_DEADLINE)
        .await
        .expect_err("超过并发上限必须报错");
    assert!(matches!(error, Error::Allocate(_)), "实际错误：{error}");
    assert_eq!(wire.active_sessions().await, 1);
    assert_eq!(wire.total_sessions().await, 1);
}

/// 下行派发：未命中会话的 `Keep` 帧必须回一个 `End` 帧（参考 `handleStatusKeep`）。
#[tokio::test]
async fn mux_wire_answers_unknown_keep_frame_with_end() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    // 对端发一个未命中会话的 `Keep` 帧（带数据段）。
    peer.write_all(&keep_frame(99, SessionStatus::Keep, Some(PAYLOAD)))
        .await
        .expect("可写");
    peer.flush().await.expect("可刷");

    let inbound = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect("可读下行帧");
    assert!(matches!(inbound.action, Action::SendEnd { id: 99 }));

    // 本仓必须回一个 `End` 帧。
    let (closing, _) = read_frame(&mut peer, true).await;
    assert_eq!(closing.session_id, 99);
    assert_eq!(closing.status, SessionStatus::End);
}

/// 下行派发：`KeepAlive` 帧只丢数据（参考 `handleStatueKeepAlive`）。
#[tokio::test]
async fn mux_wire_discards_keep_alive_frame() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    peer.write_all(&keep_frame(0, SessionStatus::KeepAlive, Some(PAYLOAD)))
        .await
        .expect("可写");
    peer.flush().await.expect("可刷");

    let inbound = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect("可读下行帧");
    assert!(matches!(inbound.action, Action::None));

    // 数据段必须已被消费（承载连接不错位）：再读一帧应能拿到后续内容。
    peer.write_all(&keep_frame(0, SessionStatus::KeepAlive, None))
        .await
        .expect("可写");
    peer.flush().await.expect("可刷");
    let inbound = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect("可读第二帧");
    assert_eq!(inbound.meta.status, SessionStatus::KeepAlive);
}

/// 多会话并发：两条会话的帧不串（会话 ID 各自独立）。
#[tokio::test]
async fn mux_wire_keeps_sessions_separated() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    let mut first = wire
        .open(target(1001), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    let mut second = wire
        .open(target(1002), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    assert_eq!(first.id(), 1);
    assert_eq!(second.id(), 2);
    assert_eq!(wire.active_sessions().await, 2);

    first.write(b"first", DEFAULT_DEADLINE).await.expect("可写");
    second
        .write(b"second", DEFAULT_DEADLINE)
        .await
        .expect("可写");

    // 依次读回：首帧 ×2 + 数据帧 ×2。
    let mut seen = Vec::new();
    for _ in 0..4 {
        let (meta, data) = read_frame(&mut peer, true).await;
        seen.push((meta.session_id, data.unwrap_or_default()));
    }
    assert_eq!(seen[0], (1, Vec::new()));
    assert_eq!(seen[1], (2, Vec::new()));
    assert_eq!(seen[2], (1, b"first".to_vec()));
    assert_eq!(seen[3], (2, b"second".to_vec()));
}

/// 收发双向：下行 `Keep` 帧命中已登记会话时派发 `Deliver`（参考 `handleStatusKeep`）。
#[tokio::test]
async fn mux_wire_delivers_keep_frame_to_known_session() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let _session = wire
        .open(target(443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");

    // 先把首帧（`New`）从对端读掉，避免后续读错位。
    let _ = read_frame(&mut peer, true).await;

    // 对端发 `Keep` 帧（会话 1，已登记）。
    peer.write_all(&keep_frame(1, SessionStatus::Keep, Some(PAYLOAD)))
        .await
        .expect("可写");
    peer.flush().await.expect("可刷");

    let inbound = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect("可读下行帧");
    match inbound.action {
        Action::Deliver { id, payload, new } => {
            assert_eq!(id, 1);
            assert!(!new);
            assert_eq!(payload, PAYLOAD, "下行载荷必须逐字节一致");
        }
        other => panic!("期望 Deliver，实际 {other:?}"),
    }
}

/// 目标地址可查：上层据此把下行数据路由回对应的上游连接。
#[tokio::test]
async fn mux_wire_exposes_session_target() {
    let (carrier, _peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let _session = wire
        .open(target(9443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    assert_eq!(wire.session_target(1).await, Some(target(9443)));
    assert_eq!(wire.session_target(42).await, None);
}
