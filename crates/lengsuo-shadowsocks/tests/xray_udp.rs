//! 四种传统 AEAD 的 UDP 双向参考对拍，仅回环假口令。
#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;
use lengsuo_shadowsocks::{CipherSuite, TargetAddr, UdpCodec};
use serde_json::json;
use support::*;
use tokio::{net::UdpSocket, time::timeout};
const PASSWORD: &str = "ss-udp-reference-test-password";
fn methods() -> [&'static str; 4] {
    [
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
    ]
}
fn codec(name: &str) -> UdpCodec {
    UdpCodec::new(CipherSuite::from_name(name).unwrap(), PASSWORD.as_bytes()).unwrap()
}

#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn rust_client_to_xray_server() {
    timeout(WAIT, async {
        for name in methods() {
            let codec = codec(name);
            let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target_port = target.local_addr().unwrap().port();
            let port = free_port();
            let reference = launch(
                json!({
                    "log": {"loglevel": "warning"},
                    "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "shadowsocks",
                        "settings": {"method": name, "password": PASSWORD, "network": "tcp,udp"}}],
                    "outbounds": [{"protocol": "freedom"}]
                }),
                port,
            )
            .await;
            let echo = tokio::spawn(async move {
                let mut buffer = [0; 2048];
                for length in [1, 512, 1200] {
                    let (received, peer) = target.recv_from(&mut buffer).await.unwrap();
                    assert_eq!(&buffer[..received], vec![0x42; length]);
                    target.send_to(&buffer[..received], peer).await.unwrap();
                }
            });
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket
                .connect((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap();
            let target = TargetAddr::V4([127, 0, 0, 1], target_port);
            let mut buffer = [0; 4096];
            for length in [1, 512, 1200] {
                socket
                    .send(&codec.seal(&target, &vec![0x42; length]).unwrap())
                    .await
                    .unwrap();
                let received = socket.recv(&mut buffer).await.unwrap();
                let (address, payload) = codec.open(&buffer[..received]).unwrap();
                assert_eq!(address, target);
                assert_eq!(payload, vec![0x42; length]);
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
    timeout(WAIT, async {
        for name in methods() {
            let codec = codec(name);
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let rust_port = server.local_addr().unwrap().port();
            let port = free_port();
            let reference = launch(json!({
                "log": {"loglevel": "warning"},
                "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "dokodemo-door",
                    "settings": {"address": "127.0.0.1", "port": 18001, "network": "tcp,udp"}}],
                "outbounds": [{"protocol": "shadowsocks", "settings": {"servers": [{
                    "address": "127.0.0.1", "port": rust_port, "method": name, "password": PASSWORD}]}}]
            }), port).await;
            let worker = tokio::spawn(async move {
                let mut buffer = [0; 4096];
                for length in [1, 512, 1200] {
                    let (received, peer) = server.recv_from(&mut buffer).await.unwrap();
                    let (target, payload) = codec.open(&buffer[..received]).unwrap();
                    assert_eq!(target, TargetAddr::V4([127, 0, 0, 1], 18001));
                    assert_eq!(payload, vec![0x42; length]);
                    server.send_to(&codec.seal(&target, &payload).unwrap(), peer).await.unwrap();
                }
            });
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.connect((std::net::Ipv4Addr::LOCALHOST, port)).await.unwrap();
            let mut buffer = [0; 2048];
            for length in [1, 512, 1200] {
                socket.send(&vec![0x42; length]).await.unwrap();
                let received = socket.recv(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..received], vec![0x42; length]);
            }
            worker.await.unwrap();
            drop(reference);
        }
    }).await.unwrap();
}
