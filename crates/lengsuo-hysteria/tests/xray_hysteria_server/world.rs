// 世界装配：本仓服务端 + 官方 Xray 客户端（socks）/ 本地 echo 目标 / SOCKS5 CONNECT。
async fn start_world(tag: &str, server_auth: &str, client_auth: &str) -> World {
    let dir = test_dir(tag);
    let (cert, key) = gen_cert(&dir);
    let der = cert_der(&cert, &dir);
    // 本仓服务端：UDP 端口由系统分配后写进 Xray 客户端配置。
    let listen: SocketAddr = "127.0.0.1:0".parse().expect("监听地址");
    let config = ServerConfig {
        listen_addr: listen,
        cert_chain_der: vec![der],
        key_der: key_der(&key),
        auth: server_auth.to_string(),
        brutal_down: 0,
        brutal_up: 0,
        udp_enabled: true,
        udp_idle_timeout_secs: 60,
        congestion: String::new(),
    };
    let server = Arc::new(HysteriaServer::bind(config).expect("服务端绑定失败"));
    let server_port = server.local_addr().expect("读取监听地址").port();
    let srv = Arc::clone(&server);
    tokio::spawn(async move { srv.accept_loop().await });

    let socks_port = free_tcp_port();
    let cfg_path = dir.join("xray.json");
    std::fs::write(
        &cfg_path,
        xray_client_config(socks_port, server_port, client_auth, &cert),
    )
    .expect("写 xray 配置");
    let log_out = std::fs::File::create(dir.join("xray-stdout.log")).expect("建日志文件");
    let log_err = std::fs::File::create(dir.join("xray-stderr.log")).expect("建日志文件");
    let client = Command::new(xray_bin())
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("启动 xray");
    let world = World {
        client,
        socks_port,
        server,
        dir,
    };
    // 就绪探测：socks 端口可连。
    for _ in 0..80 {
        if StdTcpStream::connect(("127.0.0.1", socks_port)).is_ok() {
            return world;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "xray socks 端口 20s 内未就绪；参考服务端日志:\n{}",
        support::server_logs(&world.dir)
    );
}

/// 本地 TCP echo（本仓服务端直连出站的目标）。
async fn spawn_tcp_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定 echo 端口");
    let addr = listener.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => {
                            let _ = sock.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

/// SOCKS5 CONNECT 到 `target`，返回已连接的 TCP 流。
fn socks5_connect(socks_port: u16, target: SocketAddr) -> StdTcpStream {
    let mut s = StdTcpStream::connect(("127.0.0.1", socks_port)).expect("连 socks 端口");
    s.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("设读超时");
    // 问候：无认证
    s.write_all(&[0x05, 0x01, 0x00]).expect("写问候");
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).expect("读问候响应");
    assert_eq!(resp, [0x05, 0x00], "socks 未接受无认证");
    // CONNECT（IPv4）
    let ip = match target {
        SocketAddr::V4(v4) => v4.ip().octets(),
        SocketAddr::V6(_) => panic!("仅支持 IPv4 目标"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).expect("写 CONNECT");
    let mut head = [0u8; 4];
    s.read_exact(&mut head).expect("读 CONNECT 响应头");
    assert_eq!(head[1], 0x00, "socks CONNECT 失败，reply={}", head[1]);
    // 消费绑定地址（IPv4 = 4 + 2）
    let mut tail = [0u8; 6];
    s.read_exact(&mut tail).expect("读绑定地址");
    s
}
