//! 域名 / IPv6 目标地址族的参考对拍（Xray `v26.3.27` `d2758a02`，`#[ignore]`）。
//!
//! 卡点（W4 核验卡实测，2026-10-24）：既有 `xray_tcp` / `xray_udp` 互通全部
//! 只发 IPv4 目标（`xray_tcp/mod.rs` 的 `socket_addr` 遇非 V4 直接 panic），
//! 域名与 IPv6 两族从未与参考实跑过。本 target 补上四个方向：本仓客户端把
//! 域名 / IPv6 目标写进首段明文（TCP）或地址段（UDP），参考服务端解出后经
//! freedom 出站连到本仓回环 echo，回程逐字节核对。
//!
//! 仅回环、假口令、临时端口；日志不输出密钥与明文。
//! ⚠️ `scripts/` 为本卡禁区：本 target 需基建卡在 `reference_manifest.json`
//! 登记（target `xray_addr_families`，expected_passed=4）后方可进官方门禁，
//! 已在核验报告与 `docs/shadowsocks-status.md` 点名。

#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;

use std::net::Ipv4Addr;
use std::time::Duration;

use lengsuo_shadowsocks::udp::UdpCodec;
use lengsuo_shadowsocks::{CipherSuite, TargetAddr, TcpReader, TcpWriter};
use serde_json::json;
use support::{free_port, launch, WAIT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

/// 测试假口令，与任何生产凭据无关。
const PASSWORD: &str = "ss-addr-family-interop-password";
/// 单个测试的总超时。
const OVERALL: Duration = Duration::from_secs(60);

fn suite() -> CipherSuite {
    CipherSuite::from_name("aes-128-gcm").expect("套件名应可解析")
}

fn ss_inbound_config(port: u16, network: &str) -> serde_json::Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "shadowsocks",
            "settings": {"method": "aes-128-gcm", "password": PASSWORD, "network": network}}],
        "outbounds": [{"protocol": "freedom"}]
    })
}

/// 回环 echo（TCP）：与 `xray_tcp/mod.rs` 的 `serve_echo` 同构——读满一行
/// （`\n` 结尾）即回写。**不能**等客户端 EOF 才回：参考 `server.go` 在请求
/// 方向结束时 `task.Close(link.Writer)` 直接关上游连接，「半关闭后再等上游
/// 回包」在参考语义下不可达（本卡实测踩坑，见核验报告）。
async fn spawn_echo(listener: TcpListener) -> std::net::SocketAddr {
    let addr = listener.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.expect("echo accept");
        let mut request = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = conn.read(&mut buf).await.expect("echo 读失败");
            assert!(n > 0, "echo 在读满一行前看到 EOF");
            request.extend_from_slice(&buf[..n]);
            if request.last() == Some(&b'\n') {
                break;
            }
        }
        conn.write_all(&request).await.expect("echo 回写失败");
        conn.shutdown().await.expect("echo 关写半失败");
    });
    addr
}

/// 本仓客户端 → 参考 SS 服务端：写地址 + 载荷，半关闭后读回程到干净 EOF。
async fn tcp_roundtrip(
    xray_port: u16,
    target: &TargetAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, xray_port))
        .await
        .map_err(|e| format!("连接参考服务：{e}"))?;
    let (mut read_half, mut write_half) = stream.into_split();
    let mut request: Vec<u8> = Vec::new();
    target.encode_checked(&mut request).expect("目标可编码");
    request.extend_from_slice(payload);
    let mut writer = TcpWriter::new(&mut write_half, suite(), PASSWORD.as_bytes(), WAIT)
        .map_err(|e| format!("构造写端：{e}"))?;
    timeout(WAIT, writer.send(&request))
        .await
        .map_err(|_| "send 超时".to_string())?
        .map_err(|e| format!("send 失败：{e}"))?;
    timeout(WAIT, writer.shutdown())
        .await
        .map_err(|_| "shutdown 超时".to_string())?
        .map_err(|e| format!("shutdown 失败：{e}"))?;
    drop(writer);

    let mut reader = TcpReader::new(&mut read_half, suite(), PASSWORD.as_bytes(), WAIT)
        .map_err(|e| format!("构造读端：{e}"))?;
    let mut got = Vec::new();
    loop {
        match timeout(WAIT, reader.recv()).await {
            Err(_) => return Err("读回程超时".into()),
            Ok(Err(e)) => return Err(format!("读回程失败：{e}")),
            Ok(Ok(None)) => break,
            Ok(Ok(Some(chunk))) => got.extend_from_slice(&chunk),
        }
    }
    Ok(got)
}

/// IPv6 回环可连性探测（bind 成功不代表 connect 可达，显式验证不冒充通过）。
async fn ipv6_loopback_reachable() -> bool {
    let Ok(probe) = TcpListener::bind("[::1]:0").await else {
        return false;
    };
    let addr = probe.local_addr().expect("探测地址");
    let ok = tokio::select! {
        connect = TcpStream::connect(addr) => connect.is_ok(),
        _ = tokio::time::sleep(Duration::from_secs(2)) => false,
    };
    drop(probe);
    ok
}

#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 提供固定版本参考实现"]
async fn xray_server_relays_domain_target() {
    timeout(OVERALL, async {
        let echo = spawn_echo(TcpListener::bind("127.0.0.1:0").await.expect("bind echo")).await;
        let port = free_port();
        let _reference = launch(ss_inbound_config(port, "tcp"), port).await;
        // 参考 freedom 出站把 "localhost" 交给系统解析（/etc/hosts 首条为 v4 回环）。
        let target = TargetAddr::Domain("localhost".into(), echo.port());
        let payload = b"domain-target-xray-payload\n".to_vec();
        let got = match tcp_roundtrip(port, &target, &payload).await {
            Ok(got) => got,
            Err(err) => {
                let log_path = std::env::temp_dir()
                    .join(format!("lengsuo-vless-{}-{port}", std::process::id()));
                let log = std::fs::read_to_string(log_path.join("xray.log")).unwrap_or_default();
                panic!("域名目标互通失败：{err}\n--- xray.log ---\n{log}");
            }
        };
        assert_eq!(got, payload, "域名目标经参考中继的回程应逐字节一致");
    })
    .await
    .expect("域名目标互通总超时");
}

#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 提供固定版本参考实现"]
async fn xray_server_relays_ipv6_target() {
    timeout(OVERALL, async {
        if !ipv6_loopback_reachable().await {
            println!("skip xray_server_relays_ipv6_target：IPv6 回环不可连接");
            return;
        }
        let echo = spawn_echo(TcpListener::bind("[::1]:0").await.expect("bind echo6")).await;
        let port = free_port();
        let _reference = launch(ss_inbound_config(port, "tcp"), port).await;
        let target = TargetAddr::V6(std::net::Ipv6Addr::LOCALHOST.octets(), echo.port());
        let payload = b"ipv6-target-xray-payload\n".to_vec();
        let got = tcp_roundtrip(port, &target, &payload)
            .await
            .expect("IPv6 目标互通");
        assert_eq!(got, payload, "IPv6 目标经参考中继的回程应逐字节一致");
    })
    .await
    .expect("IPv6 目标互通总超时");
}

/// 本仓客户端 → 参考 SS UDP 服务端：seal(地址 + 载荷)，echo 回包后解封核对。
async fn udp_roundtrip(network_target: TargetAddr, echo_bind: &str) {
    let echo = UdpSocket::bind(echo_bind).await.expect("bind echo");
    let echo_port = echo.local_addr().expect("echo 地址").port();
    let mut target = network_target;
    match &mut target {
        TargetAddr::V4(_, port) => *port = echo_port,
        TargetAddr::V6(_, port) => *port = echo_port,
        TargetAddr::Domain(_, port) => *port = echo_port,
    }
    let payload = b"addr-family-udp-payload".to_vec();
    let echo_payload = payload.clone();
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let (n, peer) = echo.recv_from(&mut buf).await.expect("echo 收包");
        assert_eq!(&buf[..n], &echo_payload[..], "echo 应收到原样载荷");
        echo.send_to(&buf[..n], peer).await.expect("echo 回包");
    });

    let port = free_port();
    let _reference = launch(ss_inbound_config(port, "tcp,udp"), port).await;
    let codec = UdpCodec::new(suite(), PASSWORD.as_bytes()).expect("假口令应可构造编解码器");
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind 客户端");
    socket
        .connect((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("connect 参考服务");
    socket
        .send(&codec.seal(&target, &payload).expect("合法目标应可封装"))
        .await
        .expect("发送数据报");
    let mut buf = [0u8; 4096];
    let n = timeout(WAIT, socket.recv(&mut buf))
        .await
        .expect("等回包超时")
        .expect("读回包失败");
    let (_, got) = codec.open(&buf[..n]).expect("参考回包应可解密");
    assert_eq!(got, payload, "回程载荷应逐字节一致");
    echo_task.await.expect("echo 任务");
}

#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 提供固定版本参考实现"]
async fn xray_server_accepts_udp_domain_target() {
    timeout(OVERALL, async {
        udp_roundtrip(TargetAddr::Domain("localhost".into(), 0), "127.0.0.1:0").await;
    })
    .await
    .expect("UDP 域名目标互通总超时");
}

#[tokio::test]
#[ignore = "需要 LENGSUO_XRAY 提供固定版本参考实现"]
async fn xray_server_accepts_udp_ipv6_target() {
    timeout(OVERALL, async {
        if !ipv6_loopback_reachable().await {
            println!("skip xray_server_accepts_udp_ipv6_target：IPv6 回环不可连接");
            return;
        }
        udp_roundtrip(
            TargetAddr::V6(std::net::Ipv6Addr::LOCALHOST.octets(), 0),
            "[::1]:0",
        )
        .await;
    })
    .await
    .expect("UDP IPv6 目标互通总超时");
}
