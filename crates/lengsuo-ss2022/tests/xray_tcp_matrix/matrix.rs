// 双向矩阵用例：方向一（Rust 客户端 → Xray 服务端）与方向二（Xray 客户端 SOCKS
// → Rust 服务端），三套件 × 三载荷。
//
// 本文件由 `tests/xray_tcp_matrix.rs` 用 `include!` 文本并入同一模块；
// 共享常量与 `use` 全部留在 `tests/xray_tcp_matrix.rs` 入口文件。
/// 方向一：Rust 客户端 → Xray SS2022 服务端。三套件 × 三载荷，记录首包长与双向 chunk 数。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn matrix_forward_rust_client_to_xray() {
    timeout(OVERALL, async {
        for (method, name) in matrix_methods() {
            let psk = vec![0x11; method.key_len()];
            let key = Key::new(method, &psk).expect("假 PSK 应可用");
            let port = free_port();
            let reference = launch(server_config(port, name, &psk), port).await;
            for size in matrix_sizes() {
                let echo = TcpListener::bind(BIND).await.expect("echo 应可监听");
                let echo_port = echo.local_addr().expect("echo 应有地址").port();
                let echo_task = tokio::spawn(serve_echo(echo, 1));
                let target = TargetAddr::V4(LOOPBACK, echo_port);

                let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    .await
                    .expect("连接 Xray");
                let mut writer = Writer::random(&key, Direction::Request).expect("可构造写端");
                // 首个 SS2022 写块整体成型，量出其线长即为首包长。
                let mut opening = Vec::new();
                writer
                    .write_request_header(&mut opening, &target, b"", now_secs(), 8)
                    .await
                    .unwrap_or_else(|error| panic!("{name}/{size} 请求开场写出：{error:?}"));
                let first_packet_len = opening.len();
                // IPv4 变长头 = 7(ATYP+addr+port)+2(padding 字段)+8(padding)+0(首批载荷)；
                // 加 16B AEAD tag 与固定头 11+16B。锁定首包线长即锁定线格式。
                assert_eq!(
                    first_packet_len,
                    method.key_len() + 60,
                    "{name}/{size} 请求开场线长偏离规范"
                );
                client.write_all(&opening).await.expect("开场应可落盘");

                let want = line(size);
                let mut request_chunks = 0usize;
                for piece in want.chunks(MAX_CHUNK_PAYLOAD) {
                    writer
                        .write_payload(&mut client, piece)
                        .await
                        .expect("载荷应可写出");
                    request_chunks += 1;
                }
                assert_eq!(
                    request_chunks,
                    want.chunks(MAX_CHUNK_PAYLOAD).count(),
                    "{name}/{size} 请求分块数应自洽"
                );
                writer.write_finish(&mut client).await.expect("EOF 帧应可写出");

                let mut reader =
                    Reader::new(key.clone(), Direction::Response, Duration::from_secs(5))
                        .expect("可构造读端");
                let mut replay =
                    SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
                let request_salt = writer.salt().to_vec();
                let opened = reader
                    .open(&mut client, &mut replay, clock(), Some(&request_salt))
                    .await
                    .unwrap_or_else(|error| panic!("{name}/{size} 响应开场校验：{error:?}"));
                assert!(
                    matches!(&opened.association, Association::Response(salt) if salt == &request_salt),
                    "{name}/{size} 响应回指 salt 必须等于请求 salt"
                );
                let mut got = opened.payload.clone();
                let mut response_chunks = usize::from(!opened.payload.is_empty());
                while got.len() < want.len() {
                    match reader.read_payload(&mut client).await.expect("响应载荷可读") {
                        Some(chunk) => {
                            got.extend_from_slice(&chunk);
                            response_chunks += 1;
                        }
                        None => break,
                    }
                }
                assert_eq!(got, want, "{name}/{size} 回程载荷逐字节一致");
                println!(
                    "cell forward {name} {size}: first_packet={first_packet_len} \
                     request_chunks={request_chunks} response_chunks={response_chunks}"
                );
                timeout(WAIT, echo_task)
                    .await
                    .expect("echo 任务超时")
                    .expect("echo 任务失败");
            }
            drop(reference);
        }
    })
    .await
    .expect("正向矩阵总超时");
}

/// 方向二：Xray 客户端 SOCKS → Rust 服务端。三套件 × 三载荷，记录首包长与双向 chunk 数。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn matrix_reverse_xray_client_to_rust_server() {
    timeout(OVERALL, async {
        for (method, name) in matrix_methods() {
            let psk = vec![0x11; method.key_len()];
            let key = Key::new(method, &psk).expect("假 PSK 应可用");
            let echo = TcpListener::bind(BIND).await.expect("echo 应可监听");
            let echo_port = echo.local_addr().expect("echo 应有地址").port();
            let server = TcpListener::bind(BIND).await.expect("本端应可监听");
            let rust_port = server.local_addr().expect("本端应有地址").port();
            let specs = matrix_sizes();
            let echo_task = tokio::spawn(serve_echo(echo, specs.len()));
            let served_task = tokio::spawn(async move {
                let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
                let mut rows: Vec<Row> = Vec::new();
                for _ in 0..specs.len() {
                    let (stream, _peer) = timeout(OVERALL, server.accept())
                        .await
                        .expect("本端监听器接受超时")
                        .expect("本端监听器应可接受连接");
                    rows.push(serve_one_matrix(stream, key.clone(), &mut replay, true).await);
                }
                rows
            });
            let port = free_port();
            let reference = launch(xray_client_config(port, rust_port, name, &psk), port).await;
            let target = TargetAddr::V4(LOOPBACK, echo_port);
            for size in specs {
                let want = line(size);
                let mut stream = socks5_connect(port, &target).await;
                timeout(WAIT, stream.write_all(&want))
                    .await
                    .expect("SOCKS 写载荷超时")
                    .expect("SOCKS 写载荷失败");
                let mut reply = read_line(&mut stream, ECHO_LIMIT).await;
                while reply.len() < want.len() {
                    reply.extend_from_slice(&read_line(&mut stream, ECHO_LIMIT).await);
                }
                assert_eq!(reply, want, "{name}/{size} 端到端载荷不符");
                timeout(WAIT, stream.shutdown())
                    .await
                    .expect("SOCKS 关写半超时")
                    .expect("SOCKS 关写半失败");
                drop(stream);
            }
            let rows = served_task.await.expect("本端服务任务");
            assert_eq!(rows.len(), specs.len(), "本端应处理每条互通连接");
            for (index, row) in rows.iter().enumerate() {
                let want = line(specs[index]);
                assert_eq!(
                    row.request, want,
                    "{name}/{} 请求方向载荷不符",
                    specs[index]
                );
                assert_eq!(row.reply, want, "{name}/{} 响应方向载荷不符", specs[index]);
                assert!(
                    row.first_packet_len > method.key_len() + 27,
                    "{name}/{} 首包长过短：{}",
                    specs[index],
                    row.first_packet_len
                );
                println!(
                    "cell reverse {name} {}: first_packet={} request_chunks={} \
                     response_chunks={}",
                    specs[index], row.first_packet_len, row.request_chunks, row.response_chunks
                );
            }
            drop(reference);
            timeout(WAIT, echo_task)
                .await
                .expect("echo 服务任务超时")
                .expect("echo 服务任务失败");
        }
    })
    .await
    .expect("反向矩阵总超时");
}
