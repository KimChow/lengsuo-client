/// vless(TLS) 服务端：TLS → 读 VLESS 请求头 → 连目标 → 回成功头 → 双向回显。
///
/// 返回（端口, CA PEM）。
pub async fn vless_tls_server(uuid: &'static str) -> (u16, String) {
    let cert = self_signed();
    let tls = tls_server(&cert, WAIT);
    let credential = uuid_bytes(uuid);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind vless");
    let port = listener.local_addr().expect("vless 地址").port();
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
                let Ok(request) =
                    vless_stream::receive_request(&mut stream, &credential, WAIT).await
                else {
                    return;
                };
                let Ok(mut target) = TcpStream::connect(target_addr(&request.target)).await else {
                    return;
                };
                // 目标建立成功才回成功头（主链路契约，与参考一致）。
                if vless_stream::send_response(&mut stream, WAIT)
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
            });
        }
    });
    (port, cert.cert.pem())
}
