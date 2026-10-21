// 方向 B / B'：**Xray 客户端 → 本仓入站**，逐档位跑一遍完整回显
//（含认证长度段变体）。
// 本文件由 `tests/xray_multitier_server.rs` 用 `include!` 文本并入同一模块（用例名
// 不带模块前缀，与拆分前逐字一致）；`use` 全部留在入口文件。

/// 方向 B：**Xray 客户端 → 本仓入站**，逐档位跑一遍完整回显。
#[test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
fn xray_client_to_rust_server_every_tier() {
    let Some(bin) = xray_bin() else { return };
    run_reverse_every_tier(&bin, false);
}

/// 方向 B'：**认证长度段**（`RequestOptionAuthenticatedLength`）下的逐档位互通。
///
/// 参考出口在账号开 `experiments: "AuthenticatedLength"` 时置上该选项
/// （`proxy/vmess/outbound/outbound.go`），此时长度段走 AEAD 认证
/// （`proxy/vmess/encoding/client.go` 的 `EncodeRequestBody`）。
#[test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
fn xray_client_to_rust_server_authenticated_length_every_tier() {
    let Some(bin) = xray_bin() else { return };
    run_reverse_every_tier(&bin, true);
}

/// 逐档位跑一遍「Xray 客户端 → 本仓入站 → 回显后端」的全链路。
fn run_reverse_every_tier(bin: &Path, auth_len: bool) {
    for tier in Tier::ALL {
        let uuid = generate_uuid_bytes();
        let (echo_addr, _echo) = spawn_echo_backend();
        let echo_v4 = match echo_addr {
            SocketAddr::V4(addr) => addr,
            _ => panic!("回显后端必须是 IPv4"),
        };
        let inbound = start_vmess_inbound(vec![cmd_key_from_uuid(&uuid)], Some(echo_addr), None);
        let xray = XrayClient::start_with_experiments(
            bin,
            &uuid_string(&uuid),
            inbound.addr.port(),
            tier.xray_name(),
            auth_len,
        )
        .expect("xray 客户端启动");

        let mut tunnel = socks5_connect(xray.socks_port, echo_v4).expect("socks 隧道建立");
        let payload = payloads();
        tunnel.set_read_timeout(Some(IO_TIMEOUT)).expect("读超时");
        tunnel.write_all(&payload).expect("写出载荷");
        tunnel.shutdown(Shutdown::Write).expect("半关闭写端");

        let mut echoed = Vec::new();
        tunnel.read_to_end(&mut echoed).expect("读到对端关闭");
        assert_eq!(
            echoed.len(),
            payload.len(),
            "档位 {} 回程长度必须相等",
            tier.xray_name()
        );
        assert_eq!(
            echoed,
            payload,
            "档位 {} 回程必须逐字节一致",
            tier.xray_name()
        );
        assert!(
            !inbound.panicked.load(Ordering::SeqCst),
            "档位 {} 入站处理线程不得 panic",
            tier.xray_name()
        );
        eprintln!(
            "OK: 方向 B 档位 {}（认证长度段={auth_len}）回程 {} 字节逐字节一致。",
            tier.xray_name(),
            echoed.len()
        );
    }
}
