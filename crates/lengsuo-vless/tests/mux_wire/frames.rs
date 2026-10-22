// ① 出站帧的编解码：往返一致、与既有原语逐字节相同、分片与首包语义。
/// 正常往返：`MuxWire::open` + `MuxSession::write` → 对端逐字节收到同样的帧。
///
/// 断言的是**线上字节**：`New` 帧带目标地址、`Keep` 帧带数据段，载荷逐字节一致。
#[tokio::test]
async fn mux_wire_roundtrip_payload_is_byte_exact() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    let mut session = wire
        .open(target(443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    assert_eq!(session.id(), 1, "首个会话 ID 从 1 起（参考 `m.count++`）");
    session
        .write(PAYLOAD, DEFAULT_DEADLINE)
        .await
        .expect("可写");

    // 对端先读首帧（`New`）：带目标地址、无数据段。
    let (meta, data) = read_frame(&mut peer, true).await;
    assert_eq!(meta.session_id, 1);
    assert_eq!(meta.status, SessionStatus::New);
    assert_eq!(meta.target, Some(target(443)));
    assert!(data.is_none(), "首帧只带地址（参考 `writeMetaOnly`）");

    // 对端再读数据帧（`Keep`）：带数据段，载荷逐字节一致。
    let (meta, data) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::Keep);
    assert!(meta.has_data());
    assert_eq!(data.expect("有数据段"), PAYLOAD, "载荷必须逐字节一致");

    // 收尾：写 `End` 帧，然后关闭承载连接写方向（参考 `ClientWorker.Close`）。
    session.close(DEFAULT_DEADLINE).await.expect("可收尾");
    wire.shutdown(DEFAULT_DEADLINE).await.expect("可关闭");

    // `End` 帧：metaLen=4，无数据段。
    let (end, data) = read_frame(&mut peer, true).await;
    assert_eq!(end.status, SessionStatus::End);
    assert!(!end.has_error());
    assert!(data.is_none());
    assert_eq!(wire.active_sessions().await, 0, "关闭后会话应从表里摘除");
}

/// 与既有实现的等价性：同一会话 ID 下，新 API 写出的字节与 `worker::SessionWriter`
/// 逐字节相同。
///
/// 这是「接线正确、没改语义」的硬证据：新 API 只是把既有原语接到异步写半边上。
#[tokio::test]
async fn mux_wire_output_is_identical_to_existing_session_writer() {
    // 既有原语：首帧 + 数据帧 + 收尾帧（会话 ID 手工给 1，与新 API 分配到的相同）。
    let mut expected = Vec::new();
    let mut legacy = SessionWriter::request(1, target(8443), TCP);
    legacy.write_meta_only(&mut expected).expect("可编码");
    legacy.write_data(&mut expected, PAYLOAD).expect("可编码");
    legacy.close(&mut expected).expect("可编码");

    // 新 API：同样的会话、同样的目标、同样的载荷。
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let mut session = wire
        .open(target(8443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    assert_eq!(session.id(), 1, "新 API 分配的首个会话 ID 也是 1");
    session
        .write(PAYLOAD, DEFAULT_DEADLINE)
        .await
        .expect("可写");
    session.close(DEFAULT_DEADLINE).await.expect("可收尾");
    wire.shutdown(DEFAULT_DEADLINE).await.expect("可关闭");

    let mut actual = Vec::new();
    peer.read_to_end(&mut actual).await.expect("可读");
    assert_eq!(actual, expected, "同一会话 ID 下必须逐字节相同");
}

/// 等价性（会话 ID 不同）：除会话 ID 两字节外，其余必须逐字节相同。
#[tokio::test]
async fn mux_wire_output_differs_only_in_session_id() {
    let mut expected = Vec::new();
    let mut legacy = SessionWriter::request(7, target(8443), TCP);
    legacy.write_meta_only(&mut expected).expect("可编码");
    legacy.write_data(&mut expected, PAYLOAD).expect("可编码");
    legacy.close(&mut expected).expect("可编码");

    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let mut session = wire
        .open(target(8443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    session
        .write(PAYLOAD, DEFAULT_DEADLINE)
        .await
        .expect("可写");
    session.close(DEFAULT_DEADLINE).await.expect("可收尾");
    wire.shutdown(DEFAULT_DEADLINE).await.expect("可关闭");

    let mut actual = Vec::new();
    peer.read_to_end(&mut actual).await.expect("可读");

    assert_eq!(actual.len(), expected.len(), "总长度必须一致");
    let diffs: Vec<usize> = actual
        .iter()
        .zip(expected.iter())
        .enumerate()
        .filter(|(_, (left, right))| left != right)
        .map(|(index, _)| index)
        .collect();
    // 每帧的第 2..4 字节是会话 ID（BE16）：三个帧的 ID 低字节都必须不同，
    // 其余字节必须完全一致。
    assert_eq!(
        diffs,
        vec![3, 17, 50],
        "除会话 ID 外必须逐字节相同，实际差异位置 {diffs:?}"
    );
    assert_eq!(actual[2..4], [0x00, 0x01], "新 API 的会话 ID 是 1");
    assert_eq!(expected[2..4], [0x00, 0x07], "既有原语的会话 ID 是 7");
}

/// 首包语义：`open` 带首包时，首帧就是 `New` + 数据段（参考 `writeFirstPayload`）。
#[tokio::test]
async fn mux_wire_first_payload_is_carried_in_new_frame() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let _session = wire
        .open(target(443), Some(PAYLOAD), DEFAULT_DEADLINE)
        .await
        .expect("可开会话");

    let (meta, data) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::New);
    assert!(meta.has_data(), "带首包时首帧含数据段");
    assert_eq!(data.expect("有数据段"), PAYLOAD);
}

/// 错误收尾：标记 `has_error` 后 `End` 帧带 `OptionError`（参考 `Writer.Close`）。
#[tokio::test]
async fn mux_wire_close_with_error_sets_option_error() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let mut session = wire
        .open(target(443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    session.mark_error();
    session.close(DEFAULT_DEADLINE).await.expect("可收尾");

    // 首帧是 `open` 写出的 `New`。
    let (first, _) = read_frame(&mut peer, true).await;
    assert_eq!(first.status, SessionStatus::New);
    // 收尾帧是 `End`。
    let (meta, _) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::End);
    assert!(meta.has_error(), "出错收尾必须带 OptionError");
    assert_eq!(meta.option & OPTION_ERROR, OPTION_ERROR);
}

/// 大载荷分片：TCP 会话按 8 KiB 分片，每片一帧（参考 `buf.SplitSize(mb, 8*1024)`）。
#[tokio::test]
async fn mux_wire_splits_stream_payload_into_8kib_frames() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let mut session = wire
        .open(target(443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");

    let big = vec![0xA5u8; 8 * 1024 + 7];
    session.write(&big, DEFAULT_DEADLINE).await.expect("可写");

    // 跳过首帧（`New`，无数据）。
    let (meta, _) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::New);

    // 第一片：8 KiB。
    let (meta, data) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::Keep);
    let first = data.expect("有数据段");
    assert_eq!(first.len(), 8 * 1024, "第一片应是 8 KiB");

    // 第二片：余下 7 字节。
    let (meta, data) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::Keep);
    let second = data.expect("有数据段");
    assert_eq!(second.len(), 7, "第二片是余量");
    let mut joined = first.clone();
    joined.extend_from_slice(&second);
    assert_eq!(joined, big, "分片后拼接必须逐字节一致");
}

/// 分组（UDP）会话：一帧一包，不按 8 KiB 分片（参考 `buf.SplitFirst`）。
#[tokio::test]
async fn mux_wire_packet_session_writes_single_frame() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let udp_target = (TargetAddr::V4([127, 0, 0, 1], 53), UDP);
    let mut session = wire
        .open(udp_target.clone(), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");

    // 参考的 `PacketReader` 上限是 `buf.Size`（8192）：分组会话一帧一包，
    // 超过 8192 的包参考读侧会报 `packet size too large`，故用上限内的载荷。
    let packet = vec![0x5Au8; 8 * 1024];
    session
        .write(&packet, DEFAULT_DEADLINE)
        .await
        .expect("可写");

    // 首帧 `New`（带 UDP 网络类型）。
    let (meta, _) = read_frame(&mut peer, false).await;
    assert_eq!(meta.status, SessionStatus::New);
    assert_eq!(meta.target, Some(udp_target));

    // 之后只有一帧：整个载荷（不按 8 KiB 切成两帧）。
    let (meta, data) = read_frame(&mut peer, false).await;
    assert_eq!(meta.status, SessionStatus::Keep);
    assert_eq!(data.expect("有数据段"), packet, "分组会话一帧一包");
}

/// 空载荷：只发元数据帧，不带数据段（参考 `writeMetaOnly`）。
#[tokio::test]
async fn mux_wire_empty_payload_writes_meta_only() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    let mut session = wire
        .open(target(443), None, DEFAULT_DEADLINE)
        .await
        .expect("可开会话");
    session.write(b"", DEFAULT_DEADLINE).await.expect("可写");

    // 首帧 `New`。
    let (meta, _) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::New);

    // 第二帧：`Keep` 但无数据段。
    let (meta, data) = read_frame(&mut peer, true).await;
    assert_eq!(meta.status, SessionStatus::Keep);
    assert!(!meta.has_data(), "空载荷只发元数据帧");
    assert!(data.is_none());
}

/// 既有原语与新 API 的读侧等价：既有解码器与 `next_inbound` 解出同一帧。
#[tokio::test]
async fn mux_wire_inbound_matches_existing_decoder() {
    // 用既有原语造两帧：首帧 `New`（带地址）+ 续帧 `Keep`（带数据段）。
    let mut wire_bytes = Vec::new();
    let mut legacy = SessionWriter::request(3, target(443), TCP);
    legacy.write_meta_only(&mut wire_bytes).expect("可编码");
    legacy.write_data(&mut wire_bytes, PAYLOAD).expect("可编码");

    // 既有读侧（`mux::frame` 的异步解码器）解同一段字节。
    let mut cursor = &wire_bytes[..];
    let first = decode_from_async(&mut cursor, false)
        .await
        .expect("可解帧头");
    let second = decode_from_async(&mut cursor, false)
        .await
        .expect("可解帧头");
    let data = read_data_async(&mut cursor, true)
        .await
        .expect("可解数据段");
    assert_eq!(first.status, SessionStatus::New);
    assert_eq!(second.status, SessionStatus::Keep);
    assert_eq!(data, PAYLOAD);

    // 新 API：同一段字节喂进承载连接。
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());
    peer.write_all(&wire_bytes).await.expect("可写");
    peer.flush().await.expect("可刷");

    // 首帧 `New`：客户端侧只丢数据（参考 `handleStatusNew`）。
    let inbound = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect("可读下行帧");
    assert_eq!(inbound.meta.session_id, first.session_id);
    assert_eq!(inbound.meta.status, first.status);
    assert_eq!(inbound.meta.option, first.option);
    assert!(matches!(inbound.action, Action::None));

    // 续帧 `Keep`：会话 3 未登记 ⇒ 参考回 `End` 通知。
    let inbound = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect("可读下行帧");
    assert_eq!(inbound.meta.session_id, second.session_id);
    assert_eq!(inbound.meta.status, second.status);
    assert_eq!(inbound.meta.option, second.option);
    assert!(matches!(inbound.action, Action::SendEnd { id: 3 }));
}
