//! 仅回环 UDP 对拍；会话表和防重放尚未完成。
#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::{
    crypto::{Key, Method},
    packet::Sender,
};
use serde_json::json;
use ss_core::target::TargetAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use support::*;
use tokio::{net::UdpSocket, time::timeout};
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn methods() -> [(Method, &'static str); 2] {
    [
        (Method::Aes128, "2022-blake3-aes-128-gcm"),
        (Method::Aes256, "2022-blake3-aes-256-gcm"),
    ]
}

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
                let mut buffer = [0; 2048];
                for length in [1, 512, 1200] {
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
            let mut buffer = [0; 4096];
            for length in [1, 512, 1200] {
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
                let decoded = key
                    .open_server(&buffer[..received], now(), sender.session_id())
                    .unwrap();
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
                let mut buffer=[0;4096];let mut sender=None;
                for (index,length) in [1,512,1200].into_iter().enumerate() {
                    let (received,peer)=server.recv_from(&mut buffer).await.unwrap();
                    let decoded=key.open_client(&buffer[..received],now()).unwrap();
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
            let mut buffer=[0;2048];
            for length in [1,512,1200] {
                socket.send(&vec![0x42;length]).await.unwrap();
                let received=socket.recv(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..received],vec![0x42;length]);
            }
            worker.await.unwrap();drop(reference);
        }
    }).await.unwrap();
}
