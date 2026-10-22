/// ss2022 服务端：读请求流开场（真实目标）→ 连目标 → 回响应流开场 → 双向回显。
///
/// 返回端口。`Reader` / `Writer` 是对称原语：服务端请求方向用 `Direction::Request`
/// 读、响应方向用 `Direction::Response` 写，响应固定头原样回带请求 salt。
pub async fn ss2022_server() -> u16 {
    let key = Key::new(Method::Aes128, &SS2022_PSK_BYTES).expect("ss2022 密钥");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ss2022");
    let port = listener.local_addr().expect("ss2022 地址").port();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let key = key.clone();
            tokio::spawn(async move {
                let (mut read_half, mut write_half) = tokio::io::split(socket);
                let Ok(mut reader) = Reader::new(key.clone(), Direction::Request, WAIT) else {
                    return;
                };
                let Ok(mut replay) = SessionReplay::new(Duration::from_secs(60)) else {
                    return;
                };
                let clock = clock_at(now_secs(), Instant::now());
                let Ok(opened) = reader.open(&mut read_half, &mut replay, clock, None).await else {
                    return;
                };
                let Association::Request(target) = &opened.association else {
                    return;
                };
                let Ok(mut target_stream) = TcpStream::connect(target_addr(target)).await else {
                    return;
                };
                let Ok(mut writer) = Writer::new(
                    &key,
                    Direction::Response,
                    Opening::injected(&opened.request_salt),
                ) else {
                    return;
                };
                if writer
                    .write_response_header(&mut write_half, &opened.request_salt, &[], now_secs())
                    .await
                    .is_err()
                {
                    return;
                }
                if !opened.payload.is_empty()
                    && target_stream.write_all(&opened.payload).await.is_err()
                {
                    return;
                }
                let (mut target_read, mut target_write) = tokio::io::split(target_stream);
                let to_target = async {
                    loop {
                        match reader.read_payload(&mut read_half).await {
                            Ok(Some(chunk)) => {
                                if target_write.write_all(&chunk).await.is_err() {
                                    return;
                                }
                            }
                            // 终止 chunk ⇒ 半关闭目标写侧，回程继续。
                            Ok(None) => {
                                let _ = target_write.shutdown().await;
                                return;
                            }
                            Err(_) => return,
                        }
                    }
                };
                let to_client = async {
                    let mut buf = [0u8; 8192];
                    loop {
                        match target_read.read(&mut buf).await {
                            Ok(0) | Err(_) => {
                                let _ = writer.write_finish(&mut write_half).await;
                                return;
                            }
                            Ok(n) => {
                                if writer
                                    .write_payload(&mut write_half, &buf[..n])
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        }
                    }
                };
                tokio::join!(to_target, to_client);
            });
        }
    });
    port
}
