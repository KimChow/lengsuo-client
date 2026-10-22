// ② fail-closed：非法参数 / 截断输入 / 承载连接断开 ⇒ 显式报错。
/// fail-closed：非法截止时间（0）必须显式报错，不能静默写出任何字节。
#[tokio::test]
async fn mux_wire_rejects_zero_deadline() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    let error = wire
        .open(target(443), None, Duration::ZERO)
        .await
        .expect_err("零截止时间必须报错");
    assert!(matches!(error, Error::InvalidDeadline));

    // 不得产生任何字节：读侧必须一直拿不到数据（超时），而不是读到内容。
    let mut buf = [0u8; 8];
    let outcome = tokio::time::timeout(WAIT, peer.read(&mut buf)).await;
    assert!(
        outcome.is_err(),
        "报错后不得写出任何字节，实际读到了 {:?}",
        outcome.ok()
    );
}

/// fail-closed：截断的承载连接读必须报错（参考 `Unmarshal` 读不满即返回错误）。
#[tokio::test]
async fn mux_wire_rejects_truncated_inbound_frame() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    // 只写半个帧头就断开 ⇒ 读侧必然失败。
    peer.write_all(&[0x00, 0x20]).await.expect("可写");
    peer.flush().await.expect("可刷");
    drop(peer);

    let error = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect_err("截断输入必须报错");
    assert!(matches!(error, Error::Frame(_)), "实际错误：{error}");
}

/// fail-closed：未知的会话状态必须报错（参考 `fetchOutput` 的 default 分支）。
#[tokio::test]
async fn mux_wire_rejects_unknown_session_status() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    // metaLen=4，status=0x09（未知），option=0。
    peer.write_all(&[0x00, 0x04, 0x00, 0x01, 0x09, 0x00])
        .await
        .expect("可写");
    peer.flush().await.expect("可刷");
    drop(peer);

    let error = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect_err("未知状态必须报错");
    assert!(matches!(error, Error::Frame(_)), "实际错误：{error}");
}

/// fail-closed：`metaLen > 512` 必须报错（参考 `invalid metalen`）。
#[tokio::test]
async fn mux_wire_rejects_oversized_meta_length() {
    let (carrier, mut peer) = carrier();
    let mut wire = MuxWire::new(carrier, Strategy::default());

    peer.write_all(&[0x02, 0x01, 0x00, 0x01, 0x01, 0x00])
        .await
        .expect("可写");
    peer.flush().await.expect("可刷");
    drop(peer);

    let error = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect_err("超长 metaLen 必须报错");
    assert!(matches!(error, Error::Frame(_)), "实际错误：{error}");
}

/// 承载连接断开：读侧必须报错（fail-closed），不得返回空帧。
#[tokio::test]
async fn mux_wire_reports_closed_carrier() {
    let (carrier, peer) = carrier();
    drop(peer);
    let mut wire = MuxWire::new(carrier, Strategy::default());

    let error = wire
        .next_inbound(DEFAULT_DEADLINE)
        .await
        .expect_err("承载连接断开必须报错");
    assert!(matches!(error, Error::Frame(_)), "实际错误：{error}");
}
