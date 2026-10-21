// 负例：档位错配必须失败——本仓入站按 **AES-128-GCM** 解，但参考出口发
// **ChaCha20-Poly1305**；载荷必须解不出来（回程为空 / 连接被关）。
// 本文件由 `tests/xray_multitier_server.rs` 用 `include!` 文本并入同一模块（用例名
// 不带模块前缀，与拆分前逐字一致）；`use` 全部留在入口文件。

/// 负例：档位错配必须失败——本仓入站按 **AES-128-GCM** 解，但参考出口发
/// **ChaCha20-Poly1305**；载荷必须解不出来（回程为空 / 连接被关）。
#[test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
fn xray_chacha_client_against_forced_aes_server_is_rejected() {
    let Some(bin) = xray_bin() else { return };

    let uuid = generate_uuid_bytes();
    let (echo_addr, _echo) = spawn_echo_backend();
    let echo_v4 = match echo_addr {
        SocketAddr::V4(addr) => addr,
        _ => panic!("回显后端必须是 IPv4"),
    };
    // 强制按 AES 解（忽略请求头里的档位）。
    let inbound = start_vmess_inbound(
        vec![cmd_key_from_uuid(&uuid)],
        Some(echo_addr),
        Some(BodySuite::Aes128Gcm),
    );
    let xray = XrayClient::start(
        &bin,
        &uuid_string(&uuid),
        inbound.addr.port(),
        Tier::ChaCha.xray_name(),
    )
    .expect("xray 客户端启动");

    let Ok(mut tunnel) = socks5_connect(xray.socks_port, echo_v4) else {
        eprintln!("OK: 档位错配在 socks CONNECT 阶段即被拒。");
        return;
    };
    let probe = b"must-not-echo";
    tunnel.write_all(probe).expect("写出探针");
    tunnel.shutdown(Shutdown::Write).expect("半关闭");
    tunnel.set_read_timeout(Some(IO_TIMEOUT)).expect("读超时");

    let mut got = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match tunnel.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buffer[..n]),
            Err(_) => break,
        }
    }
    assert!(
        !got.starts_with(probe),
        "档位错配不得得到探针回显（读到 {} 字节）",
        got.len()
    );
    assert!(
        !inbound.panicked.load(Ordering::SeqCst),
        "拒绝路径不得 panic"
    );
    eprintln!("OK: 档位错配（ChaCha 客户端 → 强制 AES 入站）被拒绝，无有效回程。");
}
