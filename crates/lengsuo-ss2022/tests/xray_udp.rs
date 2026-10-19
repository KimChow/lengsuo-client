//! 回环 UDP 参考互通；收包经过认证后会话与重放过滤。
//!
//! 覆盖 SIP022 §3.2 的两种 UDP 布局：
//! - AES 系列：16 字节 separate header（块加密）+ 12 字节 AEAD nonce；
//! - `2022-blake3-chacha20-poly1305`：24 字节明文 nonce（XChaCha20-Poly1305）。
#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::{
    crypto::{Key, Method},
    packet::Sender,
    receiver::{Clock, Receiver},
    Error,
};
use serde_json::json;
use ss_core::target::TargetAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use support::*;
use tokio::{net::UdpSocket, time::timeout};
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn clock() -> Clock {
    Clock {
        unix_seconds: now(),
        monotonic: Instant::now(),
    }
}
/// 三种方法都要双向实跑：AES-128 / AES-256 作对照，ChaCha 是本卡主体。
fn methods() -> [(Method, &'static str); 3] {
    [
        (Method::Aes128, "2022-blake3-aes-128-gcm"),
        (Method::Aes256, "2022-blake3-aes-256-gcm"),
        (Method::ChaCha20, "2022-blake3-chacha20-poly1305"),
    ]
}

/// 1 B / 1500 B / 8000 B 三档载荷：1 B 覆盖最小体，1500 B 覆盖典型 MTU 级，
/// 8000 B 覆盖较大分片。
///
/// **参考实现的数据报上限**：Xray v26.3.27 走的 sing `buf.Size = 8192`，
/// 单个 UDP 数据报（含 SS2022 头 + AEAD tag）超过 8192 字节会被静默丢弃。
/// 实测：载荷 8000 B（总长 8050 B）双向通过；载荷 8192 B（总长 8242 B）
/// 目标侧完全收不到，AES-128 对照同样失败——与本卡改动无关，故上限定为 8000 B。
/// 真要做 64 KiB 级别需分片，那属于 SIP022 之外的传输层设计，本卡不实现。
const PAYLOADS: [usize; 3] = [1, 1500, 8000];

#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn rust_client_to_xray_server() {
    timeout(WAIT, async {
        for (method, name) in methods() {
            let psk = vec![0x11; method.key_len()];
            let key = Key::new(method, &psk).unwrap();
            let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target_port = target.local_addr().unwrap().port();
            let port = free_port();
            let reference = launch(
                json!({"log":{"loglevel":"warning"},"inbounds":[{
                "listen":"127.0.0.1","port":port,"protocol":"shadowsocks",
                "settings":{"method":name,"password":STANDARD.encode(&psk),"network":"tcp,udp"}}],
                "outbounds":[{"protocol":"freedom"}]}),
                port,
            )
            .await;
            let echo = tokio::spawn(async move {
                let mut buffer = [0; 16384];
                for length in PAYLOADS {
                    let (received, peer) = target.recv_from(&mut buffer).await.unwrap();
                    assert_eq!(received, length);
                    assert!(buffer[..received].iter().all(|b| *b == 0x42));
                    target.send_to(&buffer[..received], peer).await.unwrap();
                }
            });
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket
                .connect((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap();
            let mut sender = Sender::new(key.clone(), None).unwrap();
            let mut receiver = Receiver::new(
                key.clone(),
                Some(sender.session_id()),
                4,
                Duration::from_secs(60),
            )
            .unwrap();
            let mut buffer = [0; 16384];
            for length in PAYLOADS {
                let packet = sender
                    .seal(
                        &TargetAddr::V4([127, 0, 0, 1], target_port),
                        &vec![0x42; length],
                        now(),
                        0,
                    )
                    .unwrap();
                socket.send(&packet).await.unwrap();
                let received = socket.recv(&mut buffer).await.unwrap();
                let peer = socket.peer_addr().unwrap();
                let decoded = receiver
                    .receive(&buffer[..received], peer, clock())
                    .unwrap();
                assert!(matches!(
                    receiver.receive(&buffer[..received], peer, clock()),
                    Err(Error::Replay)
                ));
                assert_eq!(decoded.payload, vec![0x42; length]);
            }
            echo.await.unwrap();
            drop(reference);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn xray_client_to_rust_server() {
    timeout(WAIT,async {
        for (method,name) in methods() {
            let psk=vec![0x11;method.key_len()];
            let key=Key::new(method,&psk).unwrap();
            let server=UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let rust_port=server.local_addr().unwrap().port();
            let port=free_port();
            let reference=launch(json!({"log":{"loglevel":"warning"},
                "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"dokodemo-door",
                    "settings":{"address":"127.0.0.1","port":18001,"network":"tcp,udp"}}],
                "outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{
                    "address":"127.0.0.1","port":rust_port,"method":name,"password":STANDARD.encode(&psk)}]}}]}),port).await;
            let worker=tokio::spawn(async move {
                let mut buffer=[0;16384];let mut sender=None;
                let mut receiver=Receiver::new(key.clone(),None,4,Duration::from_secs(60)).unwrap();
                for (index,length) in PAYLOADS.into_iter().enumerate() {
                    let (received,peer)=server.recv_from(&mut buffer).await.unwrap();
                    let decoded=receiver.receive(&buffer[..received],peer,clock()).unwrap();
                    assert!(matches!(receiver.receive(&buffer[..received],peer,clock()),Err(Error::Replay)));
                    assert_eq!(decoded.packet_id,index as u64);
                    assert_eq!(decoded.target,TargetAddr::V4([127,0,0,1],18001));
                    assert_eq!(decoded.payload,vec![0x42;length]);
                    let sender=sender.get_or_insert_with(||Sender::new(key.clone(),Some(decoded.session_id)).unwrap());
                    let response=sender.seal(&decoded.target,&decoded.payload,now(),0).unwrap();
                    server.send_to(&response,peer).await.unwrap();
                }
            });
            let socket=UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.connect((std::net::Ipv4Addr::LOCALHOST,port)).await.unwrap();
            let mut buffer=[0;16384];
            for length in PAYLOADS {
                socket.send(&vec![0x42;length]).await.unwrap();
                let received=socket.recv(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..received],vec![0x42;length]);
            }
            worker.await.unwrap();drop(reference);
        }
    }).await.unwrap();
}
