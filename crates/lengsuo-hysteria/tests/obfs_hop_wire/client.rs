async fn start_our_server(tag: &str, psk: Option<&str>) -> OurServer {
    let dir = test_dir(tag);
    let (cert, key) = gen_cert(&dir);
    let der = cert_der(&cert, &dir);
    let pin = cert_sha256_hex(&dir);
    let out = Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(&key)
        .args(["-outform", "DER", "-out", "-"])
        .output()
        .expect("执行 openssl pkey");
    assert!(out.status.success(), "openssl 转私钥 DER 失败");
    let listen: SocketAddr = "127.0.0.1:0".parse().expect("监听地址");
    let config = ServerConfig::new(listen, vec![der], out.stdout, AUTH.to_string());
    let server = match psk {
        Some(p) => HysteriaServer::bind_with_obfs(config, p.as_bytes().to_vec()),
        None => HysteriaServer::bind(config),
    }
    .expect("服务端绑定失败");
    let addr = server.local_addr().expect("读取监听地址");
    // `accept_loop` 的接收者是 `Arc<Self>`（对齐 `keepAccepting` 的共享端点）。
    let server = Arc::new(server);
    let handle = tokio::spawn(async move { server.accept_loop().await });
    OurServer { addr, pin, handle }
}

/// 起参考客户端（socks 入站 → hysteria 出站）。
async fn start_ref_client(tag: &str, port: u16, psk: Option<&str>, pin: &str) -> (RefProc, u16) {
    let dir = test_dir(tag);
    let socks_port = free_tcp_port();
    let cfg = ref_client_config(socks_port, port, psk, pin);
    let proc = spawn_ref(&dir, "xray-client.json", &cfg);
    (proc, socks_port)
}

/// SOCKS5 的 ATYP + 地址字节（1 = IPv4，4 = IPv6）。
fn socks_atyp(addr: IpAddr) -> (u8, Vec<u8>) {
    match addr {
        IpAddr::V4(v4) => (0x01, v4.octets().to_vec()),
        IpAddr::V6(v6) => (0x04, v6.octets().to_vec()),
    }
}

/// 通过参考客户端的 socks 入站做一次 TCP 回显，返回读到的字节。
///
/// 失败（socks 协商失败 / CONNECT 被拒 / 读写错误）统一返回 `Err`，
/// 由调用方决定是重试还是判失败 —— 「口令不符」时参考客户端会**拒绝**
/// SOCKS CONNECT，这属于预期失败，不能 panic。
fn io_err(e: std::io::Error) -> String {
    e.to_string()
}

async fn socks_roundtrip(
    socks_port: u16,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .map_err(|e| format!("连参考客户端 socks: {e}"))?;
    // SOCKS5 握手：认证协商（只支持「无认证」）。
    sock.write_all(&[5, 1, 0]).await.map_err(io_err)?;
    let mut resp = [0u8; 2];
    sock.read_exact(&mut resp).await.map_err(io_err)?;
    if resp[0] != 0x05 {
        return Err(format!("socks 版本不符: {resp:?}"));
    }
    if resp[1] != 0x00 {
        return Err(format!("socks 认证方法不接受: {resp:?}"));
    }
    // SOCKS5 CONNECT 请求：ATYP 由目标地址族决定。
    let (atyp, ip) = socks_atyp(target.ip());
    let mut req = vec![5, 1, 0, atyp];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&target.port().to_be_bytes());
    sock.write_all(&req).await.map_err(io_err)?;
    let mut head = [0u8; 4];
    sock.read_exact(&mut head).await.map_err(io_err)?;
    if head[0] != 0x05 {
        return Err(format!("socks 版本不符: {head:?}"));
    }
    if head[1] != 0x00 {
        return Err(format!("socks CONNECT 被拒（状态 {:#04x}）", head[1]));
    }
    // 绑定地址长度随 ATYP 变化（IPv4 6 / IPv6 18 / 域名 1+n）⇒ 读掉即可。
    let bound = match head[3] {
        0x01 => 6,
        0x04 => 18,
        0x03 => {
            let mut l = [0u8; 1];
            sock.read_exact(&mut l).await.map_err(io_err)?;
            l[0] as usize + 2
        }
        other => return Err(format!("socks atyp 非法: {other}")),
    };
    let mut rest = vec![0u8; bound];
    sock.read_exact(&mut rest).await.map_err(io_err)?;
    sock.write_all(payload).await.map_err(io_err)?;
    sock.flush().await.map_err(io_err)?;
    let mut got = vec![0u8; payload.len()];
    sock.read_exact(&mut got).await.map_err(io_err)?;
    Ok(got)
}

/// 本仓客户端 → 目标 TCP 的回显（走 Hysteria 代理）。
async fn proxy_roundtrip(client: &HysteriaClient, target: SocketAddr) -> Vec<u8> {
    let mut stream = proxy::tcp_connect(client, &target.to_string())
        .await
        .expect("tcp_connect 失败");
    stream.write_all(PAYLOAD).await.expect("写载荷");
    stream.finish().expect("半关闭");
    // `TcpProxyStream` 提供的是**固有方法** `read`（不是 `AsyncRead`），
    // 没有 `read_exact` ⇒ 这里手工读满。
    let mut got = vec![0u8; PAYLOAD.len()];
    let mut filled = 0usize;
    while filled < got.len() {
        let n = stream.read(&mut got[filled..]).await.expect("读回显");
        if n == 0 {
            break;
        }
        filled += n;
    }
    assert_eq!(filled, PAYLOAD.len(), "回显长度不足");
    got
}

async fn spawn_tcp_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定 echo");
    let addr = listener.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 16 * 1024];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}
