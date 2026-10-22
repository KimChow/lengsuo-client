// 端点主题：漫游更新 endpoint、认证失败不更新 endpoint。
//
// 本文件由入口 `assembly_roundtrip.rs` 用 `include!` **文本并入**同一模块，
// 故不写 `use`（入口已全部引入），用例名也不带模块前缀。

// --------------------------------------------------------- 4. 漫游更新 endpoint

#[tokio::test]
async fn roam_updates_peer_endpoint() {
    let (mut initiator, mut responder, _, _) = handshake_over_udp().await;

    // 首次：还没有 endpoint。
    assert!(
        responder.peer_endpoint().is_none(),
        "初始状态不得有 endpoint"
    );

    // 模拟一次**已认证**的收包（源地址 = 对端的新地址）。
    let new_src: SocketAddr = "203.0.113.9:40001".parse().expect("测试地址可解析");
    let frame = initiator
        .seal_frame(FrameType::Data, 1, b"roam-payload")
        .expect("应当能封装");
    let event = responder
        .receive_frame(new_src, frame)
        .expect("装配层应当能处理该帧");
    assert!(
        event.roamed(),
        "源地址变了 ⇒ 必须是漫游事件，实际 {event:?}"
    );
    assert_eq!(
        responder.peer_endpoint(),
        Some(new_src),
        "漫游后 peer endpoint 必须更新为新源地址"
    );

    // 同一地址再来一次 ⇒ **不再**漫游（幂等）。
    let frame = initiator
        .seal_frame(FrameType::Data, 2, b"same-addr-payload")
        .expect("应当能封装");
    let event = responder
        .receive_frame(new_src, frame)
        .expect("装配层应当能处理该帧");
    assert!(
        !event.roamed(),
        "地址未变 ⇒ 不得再判定为漫游，实际 {event:?}"
    );
    assert_eq!(
        responder.peer_endpoint(),
        Some(new_src),
        "endpoint 必须保持为同一个地址"
    );
}

// --------------------------------------------- 5. 认证失败不更新 endpoint

#[tokio::test]
async fn failed_auth_does_not_update_endpoint() {
    let (mut initiator, mut responder, _, _) = handshake_over_udp().await;

    // 先建立一个已知的 endpoint。
    let known: SocketAddr = "198.51.100.7:51820".parse().expect("测试地址可解析");
    responder
        .set_peer_endpoint(Some(known))
        .expect("设置 endpoint 应当成功");
    assert_eq!(responder.peer_endpoint(), Some(known));

    // 让响应方先收到一个数据报文（触发 next → current 晋升，它才能封装）。
    let warmup = initiator
        .seal_frame(FrameType::Data, 1, b"warmup-payload")
        .expect("应当能封装");
    responder
        .receive_frame(known, warmup)
        .expect("装配层应当能处理该帧");

    // 一个**认证失败**的报文（密文被篡改）⇒ 丢弃，⛔ **不**更新 endpoint。
    let mut frame = responder
        .seal_frame(FrameType::Data, 2, b"will-be-tampered")
        .expect("应当能封装");
    let last = frame.payload.len() - 1;
    frame.payload[last] ^= 0xFF;
    let forged: SocketAddr = "203.0.113.66:1234".parse().expect("测试地址可解析");

    let event = responder
        .receive_frame(forged, frame)
        .expect("认证失败的报文不该让装配层报错（只丢这一包）");
    assert!(
        matches!(event, AssemblyEvent::Dropped { .. }),
        "篡改后的报文必须被丢弃，实际 {event:?}"
    );
    assert!(!event.roamed(), "认证失败的报文不得判定为漫游");
    assert_eq!(
        responder.peer_endpoint(),
        Some(known),
        "⛔ 认证失败的报文绝不允许更新 endpoint"
    );
}
