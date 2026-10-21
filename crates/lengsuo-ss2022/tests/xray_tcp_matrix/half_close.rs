// 半关闭用例：客户端侧关写半后仍读到完整响应；服务端侧写完释放连接后客户端
// 读端必须见 EOF。
//
// 本文件由 `tests/xray_tcp_matrix.rs` 用 `include!` 文本并入同一模块；
// 共享常量与 `use` 全部留在 `tests/xray_tcp_matrix.rs` 入口文件。
/// 半关闭（客户端侧）：`shutdown(Write)` 之后仍按有限超时读到完整响应。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn half_close_rust_client_still_reads_response() {
    let method = Method::Aes256;
    let name = "2022-blake3-aes-256-gcm";
    timeout(WAIT, async {
        let psk = vec![0x33; method.key_len()];
        let key = Key::new(method, &psk).expect("假 PSK 应可用");
        let echo = TcpListener::bind(BIND).await.expect("echo 应可监听");
        let echo_port = echo.local_addr().expect("echo 应有地址").port();
        let echo_task = tokio::spawn(serve_echo(echo, 1));
        let port = free_port();
        let reference = launch(server_config(port, name, &psk), port).await;

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("连接 Xray");
        let target = TargetAddr::V4(LOOPBACK, echo_port);
        let want: &[u8] = b"half-close-ping\n";
        let mut writer = Writer::random(&key, Direction::Request).expect("可构造写端");
        let mut opening = Vec::new();
        writer
            .write_request_header(&mut opening, &target, want, now_secs(), 8)
            .await
            .expect("请求开场可写");
        client.write_all(&opening).await.expect("开场应可落盘");
        writer
            .write_finish(&mut client)
            .await
            .expect("EOF 帧应可写出");
        // 关键：先关写半，再读回程；读半必须仍然可用并读到完整响应。
        client.shutdown().await.expect("关写半失败");

        let mut reader = Reader::new(key.clone(), Direction::Response, Duration::from_secs(5))
            .expect("可构造读端");
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let request_salt = writer.salt().to_vec();
        let opened = reader
            .open(&mut client, &mut replay, clock(), Some(&request_salt))
            .await
            .expect("关写半后仍应能读响应开场");
        let mut got = opened.payload;
        while got.len() < want.len() {
            match reader
                .read_payload(&mut client)
                .await
                .expect("响应载荷可读")
            {
                Some(chunk) => got.extend_from_slice(&chunk),
                None => break,
            }
        }
        assert_eq!(got, want, "关写半后回程必须完整一致");
        timeout(WAIT, echo_task)
            .await
            .expect("echo 任务超时")
            .expect("echo 任务失败");
        drop(reference);
    })
    .await
    .expect("半关闭客户端读响应总超时");
}

/// 半关闭（服务端侧）：Rust 服务端写完整条响应后释放连接，Xray 客户端读端必须见 EOF。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn half_close_rust_server_close_gives_client_eof() {
    let method = Method::Aes256;
    let name = "2022-blake3-aes-256-gcm";
    timeout(OVERALL, async {
        let psk = vec![0x44; method.key_len()];
        let key = Key::new(method, &psk).expect("假 PSK 应可用");
        let echo = TcpListener::bind(BIND).await.expect("echo 应可监听");
        let echo_port = echo.local_addr().expect("echo 应有地址").port();
        let echo_task = tokio::spawn(serve_echo(echo, 1));
        let server = TcpListener::bind(BIND).await.expect("本端应可监听");
        let rust_port = server.local_addr().expect("本端应有地址").port();
        let served_task = tokio::spawn(async move {
            let (stream, _peer) = timeout(OVERALL, server.accept())
                .await
                .expect("本端监听器接受超时")
                .expect("本端监听器应可接受连接");
            let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
            // wait_peer=false：写完响应即释放连接，不等待对端 EOF。
            serve_one_matrix(stream, key, &mut replay, false).await
        });
        let port = free_port();
        let reference = launch(xray_client_config(port, rust_port, name, &psk), port).await;
        let target = TargetAddr::V4(LOOPBACK, echo_port);
        let want: Vec<u8> = b"server-close-eof\n".to_vec();
        let mut stream = socks5_connect(port, &target).await;
        timeout(WAIT, stream.write_all(&want))
            .await
            .expect("SOCKS 写载荷超时")
            .expect("SOCKS 写载荷失败");
        let reply = read_line(&mut stream, ECHO_LIMIT).await;
        assert_eq!(reply, want, "响应载荷必须完整读回");
        // 客户端也半关闭写方向：让 Xray 上传方向收尾，服务端关闭才会完整传播为 EOF。
        timeout(WAIT, stream.shutdown())
            .await
            .expect("SOCKS 关写半超时")
            .expect("SOCKS 关写半失败");
        // 服务端已释放连接：读端必须在有限超时内拿到 EOF（0 字节），而非悬挂。
        let mut label = [0u8; 1];
        let n = timeout(WAIT, stream.read(&mut label))
            .await
            .expect("等待服务端关闭给出 EOF 超时")
            .expect("读 EOF 失败");
        assert_eq!(n, 0, "服务端关闭后客户端读端必须读到 EOF");
        let row = served_task.await.expect("本端服务任务");
        assert_eq!(row.request, want, "服务端记录的请求方向载荷不符");
        drop(stream);
        drop(reference);
        timeout(WAIT, echo_task)
            .await
            .expect("echo 服务任务超时")
            .expect("echo 服务任务失败");
    })
    .await
    .expect("服务端关闭给出 EOF 总超时");
}
