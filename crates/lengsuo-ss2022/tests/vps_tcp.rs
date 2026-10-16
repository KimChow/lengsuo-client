//! 公网真实验证：本仓 SS2022 客户端原语 → 47 本机 Xray SS2022 入站
//! → anytls 隧道（伪装层，防路径 DPI）→ 公网 → VPS anytls-server → VPS 本机
//! Xray SS2022 入站 → 目标端口。链路：本仓原语的线上字节全程经公网传输。
#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::crypto::{Key, Method};
use lengsuo_ss2022::tcp::receive::clock_at;
use lengsuo_ss2022::tcp::{Direction, Reader, SessionReplay, Writer};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// 测试架构：
/// 本仓客户端(127.0.0.1:25002 xray 入站) → xray socks 出站(127.0.0.1:31080)
/// → anytls-client(31080) → [anytls TLS 隧道, 公网] → VPS anytls-server(8443)
/// → VPS xray SS2022 入站(127.0.0.1:25001) → 目标。
#[tokio::test]
#[ignore = "需要公网 VPS（SS2022_VPS）与 anytls 隧道（31080 端口）运行"]
async fn rust_client_ss2022_through_public_tunnel() {
    let vps = std::env::var("SS2022_VPS").unwrap_or_else(|_| "43.165.169.48".into());
    let psk = vec![0x11; 16];
    let key = Key::new(Method::Aes128, &psk).unwrap();
    // 打到 VPS 的 SSH banner 端口（隧道目标）。
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", 25002))
        .await
        .expect("连接本机 xray SS2022 入站");
    let mut writer = Writer::random(&key, Direction::Request).unwrap();
    let request_salt = writer.salt().to_vec();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    writer
        .write_request_header(
            &mut client,
            &ss_core::target::TargetAddr::V4([127, 0, 0, 1], 22),
            b"x",
            now,
            8,
        )
        .await
        .expect("请求头");
    writer.write_finish(&mut client).await.expect("EOF 帧");
    let mut reader = Reader::new(key, Direction::Response, Duration::from_secs(15)).unwrap();
    let mut replay = SessionReplay::new(Duration::from_secs(60)).unwrap();
    let now_c = clock_at(now, Instant::now());
    let opened = reader
        .open(
            &mut client,
            &mut replay,
            now_c,
            Some(request_salt.as_slice()),
        )
        .await
        .expect("公网响应头应通过认证");
    let mut banner = opened.payload.clone();
    while banner.len() < 8 {
        match reader.read_payload(&mut client).await.expect("载荷") {
            Some(c) => banner.extend_from_slice(&c),
            None => break,
        }
    }
    println!(
        "经公网隧道读到的 SSH banner: {}",
        String::from_utf8_lossy(&banner[..banner.len().min(40)])
    );
    assert!(
        banner.starts_with(b"SSH-"),
        "公网隧道后必须读到真实 SSH banner"
    );
}
