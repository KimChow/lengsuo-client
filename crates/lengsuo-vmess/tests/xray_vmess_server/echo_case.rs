// 用例 A：1B/4KiB/256KiB 经 Xray socks→vmess 全链路回显，逐字节一致。
// 本文件由 `tests/xray_vmess_server.rs` 用 `include!` 文本并入同一模块（用例名
// 不带模块前缀，与拆分前逐字一致）；`use` 全部留在入口文件。

/// 用例 A：1B/4KiB/256KiB 经 Xray socks→vmess 全链路回显，逐字节一致。
#[test]
#[ignore = "需要 LENGSUO_XRAY 指向真实 xray 二进制"]
fn xray_client_to_rust_server_echo() {
    let Some(bin) = xray_bin() else {
        eprintln!("LENGSUO_XRAY 未设置或不存在，跳过");
        return;
    };
    let uuid = generate_uuid_bytes();
    let (echo_addr, _echo) = spawn_echo_backend();
    let echo_v4 = match echo_addr {
        SocketAddr::V4(addr) => addr,
        _ => panic!("回显后端必须是 IPv4"),
    };
    let inbound = start_vmess_inbound(vec![cmd_key_from_uuid(&uuid)], Some(echo_addr));
    let xray =
        XrayClient::start(&bin, &uuid_string(&uuid), inbound.addr.port()).expect("xray 客户端启动");

    let mut tunnel = socks5_connect(xray.socks_port, echo_v4).expect("socks 隧道建立");
    let payload = payload_1b_4kib_256kib();
    tunnel
        .set_read_timeout(Some(Duration::from_secs(60)))
        .expect("读超时");
    tunnel.write_all(&payload).expect("写出载荷");
    tunnel.shutdown(Shutdown::Write).expect("半关闭写端");

    let mut echoed = Vec::new();
    tunnel.read_to_end(&mut echoed).expect("读到对端关闭");
    assert_eq!(echoed.len(), payload.len(), "回显长度必须相等");
    assert_eq!(echoed, payload, "回显内容必须逐字节一致");
    assert!(
        !inbound.panicked.load(Ordering::SeqCst),
        "入站处理线程不得 panic"
    );
}
