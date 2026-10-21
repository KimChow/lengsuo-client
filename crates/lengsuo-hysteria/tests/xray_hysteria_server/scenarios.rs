// 对照场景 A/B/C：TCP echo / UDP 往返 / 错误 auth 不得建隧道。
/// 用例 A：TCP echo 三档载荷，经官方 Xray 客户端 → 本仓服务端。
#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn a_tcp_echo_via_xray_client() {
    let world = start_world("tcp-a", AUTH, AUTH).await;
    let echo_addr = spawn_tcp_echo().await;
    let socks = world.socks_port;
    for size in [1usize, 4 * 1024, 256 * 1024] {
        let payload = pattern(size);
        let echo = echo_addr;
        let to_send = payload.clone();
        let got = tokio::task::spawn_blocking(move || {
            let mut s = socks5_connect(socks, echo);
            s.write_all(&to_send).expect("写载荷");
            s.shutdown(std::net::Shutdown::Write).expect("半关闭");
            let mut out = Vec::with_capacity(to_send.len());
            s.read_to_end(&mut out).expect("读回包");
            out
        })
        .await
        .expect("join");
        assert_eq!(got.len(), payload.len(), "回包长度不符（size={size}）");
        assert_eq!(got, payload, "回包内容不符（size={size}）");
    }
}

/// 用例 B：UDP 往返（socks5 UDP associate），经官方 Xray 客户端 → 本仓服务端。
#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn b_udp_echo_via_xray_client() {
    let world = start_world("udp-b", AUTH, AUTH).await;
    // 本地 UDP echo（本仓服务端直连出站的目标）。
    let echo = StdUdpSocket::bind("127.0.0.1:0").expect("绑定 UDP echo");
    let echo_addr = echo.local_addr().expect("echo 地址");
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, from)) = echo.recv_from(&mut buf) {
            if echo.send_to(&buf[..n], from).is_err() {
                return;
            }
        }
    });
    let socks = world.socks_port;
    let payload = pattern(64);
    let to_send = payload.clone();
    let got = tokio::task::spawn_blocking(move || {
        // TCP 控制连接申请 UDP associate
        let mut ctrl = StdTcpStream::connect(("127.0.0.1", socks)).expect("连 socks");
        ctrl.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("读超时");
        ctrl.write_all(&[0x05, 0x01, 0x00]).expect("写问候");
        let mut resp = [0u8; 2];
        ctrl.read_exact(&mut resp).expect("读问候响应");
        assert_eq!(resp, [0x05, 0x00]);
        // UDP ASSOCIATE，绑定地址 0.0.0.0:0
        ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .expect("写 ASSOCIATE");
        let mut head = [0u8; 4];
        ctrl.read_exact(&mut head).expect("读 ASSOCIATE 响应头");
        assert_eq!(head[1], 0x00, "UDP ASSOCIATE 失败，reply={}", head[1]);
        let mut tail = [0u8; 6];
        ctrl.read_exact(&mut tail).expect("读中继地址");
        let relay = SocketAddr::from((
            [tail[0], tail[1], tail[2], tail[3]],
            u16::from_be_bytes([tail[4], tail[5]]),
        ));
        // 经中继发一条 UDP 报文到 echo
        let udp = StdUdpSocket::bind("127.0.0.1:0").expect("绑定本地 UDP");
        udp.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("读超时");
        let ip = match echo_addr {
            SocketAddr::V4(v4) => v4.ip().octets(),
            SocketAddr::V6(_) => panic!("仅支持 IPv4"),
        };
        let mut pkt = vec![0x00, 0x00, 0x00, 0x01];
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&echo_addr.port().to_be_bytes());
        pkt.extend_from_slice(&to_send);
        udp.send_to(&pkt, relay).expect("发 UDP 报文");
        let mut buf = [0u8; 4096];
        let (n, _) = udp.recv_from(&mut buf).expect("收 UDP 回包");
        // SOCKS5 UDP 响应头：RSV(2) FRAG(1) ATYP(1) + 地址 + 数据
        assert!(n > 10, "UDP 回包过短: {n}");
        let atyp = buf[3];
        let hdr = match atyp {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => 1 + buf[4] as usize + 2,
            other => panic!("未知 ATYP {other:#x}"),
        };
        buf[4 + hdr..n].to_vec()
    })
    .await
    .expect("join");
    assert_eq!(got, payload, "UDP 回包内容不符");
}

/// 用例 C：错误 auth。官方 Xray 客户端用错口令 → 本仓服务端回 masquerade
/// 404，客户端无法完成 SOCKS CONNECT（连接被关闭/拒绝）。
#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 指向参考 xray 二进制"]
async fn c_wrong_auth_no_tunnel() {
    // 服务端口令与客户端口令**不同**：客户端应被拒。
    let world = start_world("auth-c", "server-side-secret", "wrong-client-secret").await;
    // 目标用真实 echo：若认证被绕过，客户端能连通并回包，用例即失败。
    let echo_addr = spawn_tcp_echo().await;
    let socks = world.socks_port;
    let payload = pattern(16);
    let tunneled = tokio::task::spawn_blocking(move || {
        let mut s = StdTcpStream::connect(("127.0.0.1", socks)).expect("连 socks");
        s.set_read_timeout(Some(Duration::from_secs(15)))
            .expect("读超时");
        s.write_all(&[0x05, 0x01, 0x00]).expect("写问候");
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).expect("读问候响应");
        // CONNECT 到真实 echo（IPv4 + 端口）
        let ip = match echo_addr {
            SocketAddr::V4(v4) => v4.ip().octets(),
            SocketAddr::V6(_) => panic!("仅支持 IPv4"),
        };
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&ip);
        req.extend_from_slice(&echo_addr.port().to_be_bytes());
        s.write_all(&req).expect("写 CONNECT");
        let mut head = [0u8; 4];
        let Ok(()) = s.read_exact(&mut head) else {
            return false; // 连接被关闭 = 未建立隧道
        };
        if head[1] != 0x00 {
            return false; // 明确拒绝
        }
        // 声称成功，再验数据是否真能往返（防「假成功」）
        let mut tail = [0u8; 6];
        if s.read_exact(&mut tail).is_err() {
            return false;
        }
        if s.write_all(&payload).is_err() {
            return false;
        }
        let _ = s.shutdown(std::net::Shutdown::Write);
        let mut out = Vec::new();
        s.read_to_end(&mut out).is_ok() && out == payload
    })
    .await
    .expect("join");
    assert!(
        !tunneled,
        "错误 auth 下不应建立可用隧道（认证未 fail-closed：回包成功）"
    );
}
