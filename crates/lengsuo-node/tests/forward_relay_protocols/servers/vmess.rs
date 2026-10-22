/// 服务端侧读 vmess 请求头。
///
/// `decode_request_header` 是同步 `std::io::Read` 接口，异步流没法直接喂；
/// 这里用公开的分段解密原语（`aead::open_request_header_*`）按线序
/// `AuthID(16) + 长度段(18) + nonce(8) + 载荷段(len+16)` 异步读，
/// 再交给公开的纯解析段 `server::parse_request_payload`（重放过滤注入恒真，
/// 每条连接只来一次，不存在重放窗口）。
async fn read_vmess_header<S: AsyncRead + Unpin>(
    stream: &mut S,
    cmd_key: &[u8; 16],
) -> Result<lengsuo_vmess::server::DecodedRequest, String> {
    async fn read_exact<S: AsyncRead + Unpin>(
        stream: &mut S,
        buf: &mut [u8],
    ) -> Result<(), String> {
        timeout(WAIT, stream.read_exact(buf))
            .await
            .map_err(|_| "读请求头超时".to_owned())?
            .map_err(|err| err.to_string())?;
        Ok(())
    }
    let mut auth_id = [0u8; 16];
    read_exact(stream, &mut auth_id).await?;
    let mut length_ct = [0u8; 18];
    read_exact(stream, &mut length_ct).await?;
    let mut nonce = [0u8; 8];
    read_exact(stream, &mut nonce).await?;
    let plain_len =
        lengsuo_vmess::aead::open_request_header_length(cmd_key, &auth_id, &length_ct, &nonce)
            .map_err(|err| err.to_string())?;
    let mut payload_ct = vec![0u8; usize::from(plain_len) + 16];
    read_exact(stream, &mut payload_ct).await?;
    let plain =
        lengsuo_vmess::aead::open_request_header_payload(cmd_key, &auth_id, &nonce, &payload_ct)
            .map_err(|err| err.to_string())?;
    let mut filter = |_: &[u8; 16], _: &[u8; 16], _: &[u8; 16]| true;
    parse_request_payload(std::slice::from_ref(cmd_key), 0, &plain, &mut filter)
        .map_err(|err| err.to_string())
}

/// vmess 服务端：TLS → 解请求头 → 回响应头 → 数据段双向回显（join! 两方向）。
///
/// 请求方向解 chunk 写目标；回程读目标封 chunk；任一侧 EOF 对另一侧半关闭
/// （与转发器 `relay.rs` 的 `join!` 语义对称）。
pub async fn vmess_server(uuid: &'static str) -> (u16, String) {
    let cert = self_signed();
    let tls = tls_server(&cert, WAIT);
    let cmd_key = vmess_cmd_key(uuid);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vmess");
    let port = listener.local_addr().expect("vmess 地址").port();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let tls = Arc::clone(&tls);
            tokio::spawn(async move {
                let Ok(mut stream) = tls.accept(socket).await else {
                    return;
                };
                let Ok(request) = read_vmess_header(&mut stream, &cmd_key).await else {
                    return;
                };
                let Some(target) = request.target else {
                    return;
                };
                let Ok(target_stream) = TcpStream::connect(target_addr(&target)).await else {
                    return;
                };
                let mut head = Vec::new();
                if encode_response_header(
                    request.response_header,
                    &request.request_body_key,
                    &request.request_body_iv,
                    &ResponseHeader::new(),
                    &mut head,
                )
                .is_err()
                {
                    return;
                }
                if stream.write_all(&head).await.is_err() {
                    return;
                }
                let (mut read_half, mut write_half) = tokio::io::split(stream);
                let (mut target_read, mut target_write) = tokio::io::split(target_stream);
                let mut request_cipher = DataCipher::new(
                    SECURITY_AES_128_GCM,
                    &request.request_body_key,
                    &request.request_body_iv,
                );
                let (resp_key, resp_iv) = lengsuo_vmess::server::respond::response_key_iv(
                    &request.request_body_key,
                    &request.request_body_iv,
                );
                let mut response_cipher =
                    DataCipher::new(SECURITY_AES_128_GCM, &resp_key, &resp_iv);
                let to_target = async {
                    loop {
                        match chunkframe::read_data_chunk(&mut request_cipher, None, &mut read_half)
                            .await
                        {
                            Ok(Some(chunk)) => {
                                if target_write.write_all(&chunk).await.is_err() {
                                    return;
                                }
                            }
                            // 请求方向 EOF ⇒ 半关闭目标写侧，回程继续。
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
                                let _ = chunkframe::write_eof(
                                    &mut response_cipher,
                                    None,
                                    &mut write_half,
                                )
                                .await;
                                return;
                            }
                            Ok(n) => {
                                if chunkframe::write_data_chunk(
                                    &mut response_cipher,
                                    None,
                                    &mut write_half,
                                    &buf[..n],
                                )
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
    (port, cert.cert.pem())
}
