//! 基础 VLESS UDP over TCP 双向参考互通；仅回环明文协议层。
mod support;
use lengsuo_vless::{
    header::{Command, Request},
    stream::*,
};
use serde_json::json;
use ss_core::target::TargetAddr;
use support::*;
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

fn packets() -> Vec<Vec<u8>> {
    vec![vec![0xff], vec![0x42; 512], vec![0x19; 1200]]
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_client_to_xray_server_udp() {
    rust_to_xray(false).await;
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_xudp_client_to_xray_server() {
    rust_to_xray(true).await;
}

async fn rust_to_xray(xudp: bool) {
    timeout(WAIT, async {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let port = free_port();
        let reference = launch(
            json!({
                "log":{"loglevel":"warning"},
                "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vless",
                    "settings":{"clients":[{"id":ID}],"decryption":"none"}}],
                "outbounds":[{"protocol":"freedom"}]
            }),
            port,
        )
        .await;
        let echo = tokio::spawn(async move {
            let mut buffer = [0; 2048];
            for expected in packets() {
                let (length, peer) = target.recv_from(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..length], expected);
                target.send_to(&buffer[..length], peer).await.unwrap();
            }
        });
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let request = Request {
            command: Command::Udp,
            target: TargetAddr::V4([127, 0, 0, 1], target_port),
        };
        let request = if xudp {
            Request {
                command: Command::Mux,
                target: TargetAddr::Domain("v1.mux.cool".into(), 0),
            }
        } else {
            request
        };
        let mut session =
            lengsuo_vless::xudp::Session::client(TargetAddr::V4([127, 0, 0, 1], target_port));
        send_request(&mut stream, &request, &KEY, WAIT)
            .await
            .unwrap();
        let mut response_header = false;
        for packet in packets() {
            if xudp {
                session.send(&mut stream, &packet, WAIT).await.unwrap();
            } else {
                send_datagram(&mut stream, &packet, WAIT).await.unwrap();
            }
            if !response_header {
                receive_response(&mut stream, WAIT).await.unwrap();
                response_header = true;
            }
            let received = if xudp {
                session.receive(&mut stream, 2048, WAIT).await.unwrap().1
            } else {
                receive_datagram(&mut stream, 2048, WAIT).await.unwrap()
            };
            assert_eq!(received, packet);
        }
        echo.await.unwrap();
        drop(reference);
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_client_to_rust_server_udp() {
    timeout(WAIT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rust_port = listener.local_addr().unwrap().port();
        let port = free_port();
        let reference = launch(json!({
            "log":{"loglevel":"warning"},
            "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"dokodemo-door",
                "settings":{"address":"127.0.0.1","port":18001,"network":"tcp,udp"}}],
            "outbounds":[{"protocol":"vless","settings":{"vnext":[{
                "address":"127.0.0.1","port":rust_port,"users":[{"id":ID,"encryption":"none"}]}]}}]
        }),port).await;
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = match receive_request(&mut stream, &KEY, WAIT).await {
                    Ok(request) => request,
                    Err(Error::Io(_)) => continue,
                    Err(error) => panic!("协议头失败：{error}"),
                };
                if request.command == Command::Tcp {
                    continue;
                }
                assert_eq!(request.command, Command::Mux, "默认 Xray 应选择 XUDP");
                let mut session = lengsuo_vless::xudp::Session::server();
                send_response(&mut stream, WAIT).await.unwrap();
                for expected in packets() {
                    let (target, packet) = session.receive(&mut stream, 2048, WAIT).await.unwrap();
                    assert_eq!(target, TargetAddr::V4([127, 0, 0, 1], 18001));
                    assert_eq!(packet, expected);
                    session.send(&mut stream, &packet, WAIT).await.unwrap();
                }
                break;
            }
        });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut buffer = [0; 2048];
        for packet in packets() {
            client.send(&packet).await.unwrap();
            let length = client.recv(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], packet);
        }
        server.await.unwrap();
        drop(reference);
    })
    .await
    .unwrap();
}
