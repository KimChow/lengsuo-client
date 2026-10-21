// 公网用例：两条通路的逐档重组取证，以及公网对端 SSH banner 取证。
//
// 本文件由 `tests/vps_reassembly.rs` 用 `include!` 文本并入同一模块；
// 共享常量与环境探测在 `tests/vps_reassembly.rs` 入口文件，`use` 全部写在入口文件。
/// 路径 A：本仓原语 ↔ 本机 Xray SS2022 入站；载荷经 anytls TLS 隧道过公网到 VPS。
#[tokio::test]
#[ignore = "需要公网 VPS 环境"]
async fn public_link_reassembly_via_local_xray() {
    if !public_link_enabled() {
        eprintln!("跳过：需要 SS2022_VPS=1 与公网隧道");
        return;
    }
    timeout(
        Duration::from_secs(CASE_TIMEOUT_SECS),
        run_ladder(Transport::LocalXray),
    )
    .await
    .expect("路径 A 总超时");
}

/// 路径 B：本仓 SS2022 线上字节本身经 anytls TLS 隧道过公网，由 VPS 参考 Xray
/// SS2022 入站收发。
#[tokio::test]
#[ignore = "需要公网 VPS 环境"]
async fn public_link_reassembly_via_vps_reference_server() {
    if !public_link_enabled() {
        eprintln!("跳过：需要 SS2022_VPS=1 与公网隧道");
        return;
    }
    if vps_relay().is_none() {
        eprintln!("跳过：需要 SS2022_VPS_RELAY 指向 VPS 参考 Xray SS2022 入站");
        return;
    }
    timeout(
        Duration::from_secs(CASE_TIMEOUT_SECS),
        run_ladder(Transport::VpsReference),
    )
    .await
    .expect("路径 B 总超时");
}

/// 公网对端身份取证：同一条公网链路上读到**另一台机器**的 SSH banner。
#[tokio::test]
#[ignore = "需要公网 VPS 环境"]
async fn public_link_reads_remote_ssh_banner() {
    if !public_link_enabled() {
        eprintln!("跳过：需要 SS2022_VPS=1 与公网隧道");
        return;
    }
    timeout(Duration::from_secs(CASE_TIMEOUT_SECS), async {
        let target = ss_core::target::TargetAddr::V4([127, 0, 0, 1], 22);
        let mut session = open_session(Transport::LocalXray, &target).await;
        // SSH 服务端主动先发 banner；参考 SS2022 服务端收到上游数据时才写响应
        // 固定头（`serverConn.writeResponse`），所以这里**不需要**先发载荷。
        session.read_response_header().await;
        let mut banner = session.first_payload.clone();
        while banner.len() < 8 {
            match session.reader.read_payload(&mut session.stream).await {
                Ok(Some(chunk)) => banner.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(error) => panic!("读取 SSH banner 失败：{error:?}"),
            }
        }
        let text = String::from_utf8_lossy(&banner).to_string();
        println!("经公网隧道读到的 SSH banner: {}", text.trim_end());
        assert!(
            banner.starts_with(b"SSH-"),
            "公网隧道后必须读到真实 SSH banner"
        );
    })
    .await
    .expect("SSH banner 取证总超时");
}
