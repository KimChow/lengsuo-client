// 会话方向约束：写端只许请求方向带身份头、服务端缺 EIH 不得回退单用户
// PSK、EIH 服务端与客户端回环互通。
//
// 本文件由 `tests/eih.rs` 用 `include!` 文本并入同一模块；
// 共享助手在 `tests/eih.rs` 入口文件，`use` 全部写在入口文件。
#[tokio::test]
async fn writer_accepts_identity_headers_only_in_request_direction() {
    let user = key(Method::Aes256, 0x22);
    assert!(matches!(
        Writer::random(&user, Direction::Response)
            .expect("写端")
            .with_identity_headers(vec![0u8; IDENTITY_HEADER_LEN]),
        Err(Error::EihDirection)
    ));
    assert!(matches!(
        Writer::random(&user, Direction::Request)
            .expect("写端")
            .with_identity_headers(Vec::new()),
        Err(Error::EihShape)
    ));
    assert!(matches!(
        Writer::random(&user, Direction::Request)
            .expect("写端")
            .with_identity_headers(vec![0u8; IDENTITY_HEADER_LEN - 1]),
        Err(Error::EihShape)
    ));

    let mut writer = Writer::random(&user, Direction::Request)
        .expect("写端")
        .with_identity_headers(vec![0xAB; IDENTITY_HEADER_LEN])
        .expect("合法身份头");
    let target = TargetAddr::V4([127, 0, 0, 1], 9);
    writer
        .write_request_header(&mut Vec::new(), &target, b"x", now_secs(), 0)
        .await
        .expect("开场可写");
    // 开场后不得再改身份头。
    assert!(matches!(
        writer.set_identity_headers(vec![0xCD; IDENTITY_HEADER_LEN]),
        Err(Error::SessionPolicy)
    ));
}

#[tokio::test]
async fn server_accept_never_falls_back_to_single_user_psk() {
    let identity = key(Method::Aes256, 0x11);
    let user = key(Method::Aes256, 0x22);
    let server = EihServer::new(
        identity.clone(),
        table(user.clone(), 7),
        Duration::from_secs(2),
    )
    .expect("服务端可构造");

    // 没有 EIH 的单用户开场：服务端必须拒绝，不能当成 user PSK 直接解密。
    let (mut client, mut server_stream) = loopback_pair().await;
    let mut writer = Writer::random(&user, Direction::Request).expect("写端");
    let mut plain = Vec::new();
    writer
        .write_request_header(
            &mut plain,
            &TargetAddr::V4([127, 0, 0, 1], 9),
            b"no-eih\n",
            now_secs(),
            0,
        )
        .await
        .expect("可写");
    client.write_all(&plain).await.expect("可写回环");
    let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
    let outcome = timeout(
        WAIT,
        server.accept(&mut server_stream, &mut replay, clock()),
    )
    .await
    .expect("拒绝判定超时");
    match outcome {
        Ok(_) => panic!("缺少 EIH 时服务端不得回退单用户 PSK"),
        Err(error) => assert!(
            matches!(error, Error::IdentityUnknown | Error::EihTruncated),
            "缺 EIH 应 fail-closed，实际 {error:?}"
        ),
    }

    // 截断到只有 salt：必须明确报 EihTruncated，而不是挂起。
    let (mut client, mut server_stream) = loopback_pair().await;
    client.write_all(&[0x5A; 32]).await.expect("只写 salt");
    client.shutdown().await.expect("关写半");
    let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
    let outcome = timeout(
        WAIT,
        server.accept(&mut server_stream, &mut replay, clock()),
    )
    .await
    .expect("截断判定超时");
    match outcome {
        Ok(_) => panic!("截断身份头必须失败"),
        Err(error) => assert!(
            matches!(error, Error::EihTruncated),
            "截断应报 EihTruncated，实际 {error:?}"
        ),
    }
}

#[tokio::test]
async fn eih_server_and_client_roundtrip_over_loopback() {
    let identity = key(Method::Aes256, 0x11);
    let user = key(Method::Aes256, 0x22);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("回环可监听");
    let address = listener.local_addr().expect("有地址");
    let server_identity = identity.clone();
    let server_user = user.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.expect("可接受");
        let server = EihServer::new(
            server_identity,
            table(server_user.clone(), 7),
            Duration::from_secs(5),
        )
        .expect("服务端");
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let (_reader, opened, uid) = server
            .accept(&mut stream, &mut replay, clock())
            .await
            .expect("EIH 开场应通过");
        assert_eq!(uid, 7);
        assert!(
            matches!(opened.association, Association::Request(_)),
            "请求方向应带目标地址"
        );
        assert_eq!(opened.payload, b"ping\n");
        let mut writer = Writer::random(&server_user, Direction::Response).expect("写端");
        writer
            .write_response_header(&mut stream, &opened.request_salt, b"pong\n", now_secs())
            .await
            .expect("响应头");
        writer.write_finish(&mut stream).await.expect("响应收尾");
    });

    let mut stream = TcpStream::connect(address).await.expect("连接回环");
    let mut writer = Writer::random(&user, Direction::Request).expect("写端");
    let chain = IdentityChain::new(vec![identity], user.clone()).expect("身份链");
    writer
        .set_identity_headers(chain.headers(writer.salt()).expect("身份头"))
        .expect("挂载身份头");
    writer
        .write_request_header(
            &mut stream,
            &TargetAddr::V4([127, 0, 0, 1], 9),
            b"ping\n",
            now_secs(),
            0,
        )
        .await
        .expect("请求开场");
    writer.write_finish(&mut stream).await.expect("请求收尾");

    let mut reader =
        Reader::new(user.clone(), Direction::Response, Duration::from_secs(5)).expect("读端");
    let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
    let opened = timeout(
        WAIT,
        reader.open(&mut stream, &mut replay, clock(), Some(writer.salt())),
    )
    .await
    .expect("响应开场超时")
    .expect("响应开场应通过");
    let mut reply = opened.payload;
    while let Some(chunk) = reader.read_payload(&mut stream).await.expect("读载荷") {
        reply.extend_from_slice(&chunk);
    }
    assert_eq!(reply, b"pong\n");
    timeout(WAIT, server)
        .await
        .expect("服务任务超时")
        .expect("服务任务");
}
