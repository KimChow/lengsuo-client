// 用例 B：Xray 侧配错 UUID → 本仓 invalid user 拒绝：断连且无回显。
// 本文件由 `tests/xray_vmess_server.rs` 用 `include!` 文本并入同一模块（用例名
// 不带模块前缀，与拆分前逐字一致）；`use` 全部留在入口文件。

/// 用例 B：Xray 侧配错 UUID → 本仓 invalid user 拒绝：断连且无回显。
#[test]
#[ignore = "需要 LENGSUO_XRAY 指向真实 xray 二进制"]
fn xray_client_wrong_uuid_is_rejected() {
    let Some(bin) = xray_bin() else {
        eprintln!("LENGSUO_XRAY 未设置或不存在，跳过");
        return;
    };
    let server_uuid = generate_uuid_bytes();
    let mut client_uuid = generate_uuid_bytes();
    client_uuid[0] ^= 0xFF;
    let (echo_addr, _echo) = spawn_echo_backend();
    let echo_v4 = match echo_addr {
        SocketAddr::V4(addr) => addr,
        _ => panic!("回显后端必须是 IPv4"),
    };
    let inbound = start_vmess_inbound(vec![cmd_key_from_uuid(&server_uuid)], Some(echo_addr));
    let xray = XrayClient::start(&bin, &uuid_string(&client_uuid), inbound.addr.port())
        .expect("xray 客户端启动");

    // CONNECT 可能成功（xray 先建链再发 vmess 头），失败也是有效拒绝证据。
    let Ok(mut tunnel) = socks5_connect(xray.socks_port, echo_v4) else {
        assert!(!inbound.panicked.load(Ordering::SeqCst));
        eprintln!("socks CONNECT 即被拒（同样构成拒绝证据）");
        return;
    };
    let probe = b"must-not-echo";
    tunnel.write_all(probe).expect("写出探针");
    tunnel.shutdown(Shutdown::Write).expect("半关闭");

    let mut got = Vec::new();
    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let now = Instant::now();
        if now >= deadline {
            panic!("错误 UUID 的连接 10s 内未被关闭");
        }
        tunnel
            .set_read_timeout(Some(deadline - now))
            .expect("读超时");
        match tunnel.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buffer[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                panic!("错误 UUID 的连接 10s 内未被关闭（读超时）");
            }
            Err(_) => break, // RST/ABORT 等强制关闭
        }
    }
    assert!(
        !got.starts_with(probe),
        "错误 UUID 不得得到探针回显（读到 {} 字节）",
        got.len()
    );
    assert!(
        !inbound.panicked.load(Ordering::SeqCst),
        "拒绝路径不得 panic"
    );
}
