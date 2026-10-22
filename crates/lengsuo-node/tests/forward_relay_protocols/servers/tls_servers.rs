/// anytls 服务端：TLS → 本仓 `server::serve`（认证 / SYN / PUSH 地址解析 / 帧中继）。
///
/// 返回（端口, CA PEM）。
pub async fn anytls_server(password: &'static str) -> (u16, String) {
    let cert = self_signed();
    let tls = tls_server(&cert, WAIT);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind anytls");
    let port = listener.local_addr().expect("anytls 地址").port();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let tls = Arc::clone(&tls);
            tokio::spawn(async move {
                let Ok(stream) = tls.accept(socket).await else {
                    return;
                };
                let _ = anytls_server::serve(
                    stream,
                    anytls_server::ServerConfig::new(password.as_bytes(), WAIT),
                )
                .await;
            });
        }
    });
    (port, cert.cert.pem())
}

/// hysteria 服务端：QUIC/H3 → 本仓 `HysteriaServer::accept_loop`
/// （认证 + TCP 承载请求 + 连目标）。返回（UDP 端口, CA PEM）。
pub async fn hysteria_server(auth: &'static str) -> (u16, String) {
    let cert = self_signed();
    let server = Arc::new(
        HysteriaServer::bind(HysteriaServerConfig::new(
            "127.0.0.1:0".parse().expect("回环地址"),
            vec![cert.cert.der().clone().to_vec()],
            cert.key_pair.serialize_der(),
            auth.to_owned(),
        ))
        .expect("hysteria 服务端"),
    );
    let port = server.local_addr().expect("hysteria 地址").port();
    tokio::spawn(async move {
        server.accept_loop().await;
    });
    (port, cert.cert.pem())
}
