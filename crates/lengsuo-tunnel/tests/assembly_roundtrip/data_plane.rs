// 数据面主题：装配层收发数据往返、会话未就绪时数据面拒绝收发。
//
// 本文件由入口 `assembly_roundtrip.rs` 用 `include!` **文本并入**同一模块，
// 故不写 `use`（入口已全部引入），用例名也不带模块前缀。

// --------------------------------------------------- 3. 数据往返（装配层）

#[tokio::test]
async fn data_round_trip_through_assembly() {
    let (mut initiator, mut responder, _, _) = handshake_over_udp().await;
    let (a_socket, b_socket) = pair().await;

    let plain = b"assembly-round-trip-payload";
    let seq = 42u64;

    // 发起方封装 → 装帧 → 发出。
    let frame = initiator
        .seal_frame(FrameType::Data, seq, plain)
        .expect("应当能封装数据帧");
    let bytes = frame.encode().expect("帧应当能编码");
    a_socket.send_raw(&bytes).await.expect("数据帧应当发出");

    // 响应方收字节 → 装配层处理 → 拿到明文。
    let mut buf = buffer();
    let got = tokio::time::timeout(TIMEOUT, b_socket.recv_frame(&mut buf))
        .await
        .expect("响应方必须在超时内收到数据")
        .expect("数据必须是一个合法帧");
    let src = b_socket.local_addr().expect("取源地址");
    let event = responder
        .receive_frame(src, got)
        .expect("装配层应当能处理数据帧");
    match event {
        AssemblyEvent::Delivered {
            frame_type,
            seq: got_seq,
            plaintext_len,
            ..
        } => {
            assert_eq!(frame_type, FrameType::Data);
            assert_eq!(got_seq, seq, "帧序号必须原样传下去");
            assert_eq!(plaintext_len, plain.len(), "明文长度必须正确");
        }
        other => panic!("期望 Delivered，实际 {other:?}"),
    }

    // 响应方的 keypair 在收到这个报文时**晋升**为 current（对照参考
    // `ReceivedWithKeypair`）⇒ 现在它也能发。
    assert!(
        responder.device().keypairs().current().is_some(),
        "响应方收到首个数据报文后，keypair 应当晋升为 current"
    );

    // 反向：响应方回一帧。
    let frame = responder
        .seal_frame(FrameType::Data, seq + 1, b"reply-payload")
        .expect("响应方应当能封装");
    let bytes = frame.encode().expect("帧应当能编码");
    b_socket.send_raw(&bytes).await.expect("回帧应当发出");
    let mut buf = buffer();
    let got = tokio::time::timeout(TIMEOUT, a_socket.recv_frame(&mut buf))
        .await
        .expect("发起方必须在超时内收到回帧")
        .expect("回帧必须是一个合法帧");
    let src = a_socket.local_addr().expect("取源地址");
    let event = initiator
        .receive_frame(src, got)
        .expect("装配层应当能处理回帧");
    assert!(
        matches!(event, AssemblyEvent::Delivered { .. }),
        "反向也必须成功解密，实际 {event:?}"
    );
}

// --------------------------------- 附加：会话未就绪时数据面拒绝收发

#[tokio::test]
async fn session_not_established_rejects_data_plane() {
    let mut initiator = Assembly::new(initiator_config()).expect("发起方装配层可建");
    assert!(!initiator.is_established());

    let err = initiator
        .seal_frame(FrameType::Data, 1, b"nope")
        .expect_err("会话未就绪必须拒绝封装");
    assert!(
        matches!(err, AssemblyError::SessionNotEstablished),
        "期望 SessionNotEstablished，实际 {err:?}"
    );

    let src: SocketAddr = "127.0.0.1:1".parse().expect("测试地址可解析");
    let frame = Frame::new(FrameType::Data, 1, vec![0u8; 32]);
    let err = initiator
        .receive_frame(src, frame)
        .expect_err("会话未就绪必须拒绝收包");
    assert!(
        matches!(err, AssemblyError::SessionNotEstablished),
        "期望 SessionNotEstablished，实际 {err:?}"
    );
}
