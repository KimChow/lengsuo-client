//! 公网真实互通：本仓客户端原语 → 公网 VPS 上的 Xray SS2022 → VPS SSH banner。
#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::crypto::{Key, Method};
use lengsuo_ss2022::tcp::receive::clock_at;
use lengsuo_ss2022::tcp::{Direction, Opening, Reader, SessionReplay, Writer};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

#[tokio::test]
#[ignore = "需要公网 VPS 服务端（SS2022_VPS=43.165.169.48）"]
async fn rust_client_to_vps_xray_ssh_banner() {
    let vps = std::env::var("SS2022_VPS").unwrap_or_else(|_| "43.165.169.48".into());
    let psk = vec![0x11; 16];
    let key = Key::new(Method::Aes128, &psk).unwrap();
    let mut client = tokio::net::TcpStream::connect((&vps[..], 25001))
        .await
        .expect("连接 VPS");
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
    let mut reader = Reader::new(key, Direction::Response, Duration::from_secs(10)).unwrap();
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
        .unwrap_or_else(|e| panic!("响应头失败: {e:?}"));
    let mut banner = opened.payload.clone();
    while banner.len() < 8 {
        let chunk = reader.read_payload(&mut client).await.expect("载荷可读");
        match chunk {
            Some(c) => banner.extend_from_slice(&c),
            None => break,
        }
    }
    println!(
        "VPS SSH banner: {}",
        String::from_utf8_lossy(&banner[..banner.len().min(40)])
    );
    assert!(
        banner.starts_with(b"SSH-"),
        "应透过公网隧道读到 VPS 的 SSH banner"
    );
}
