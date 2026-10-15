//! 在认证 TLS 上验证 Trojan UDP 双向参考互通，仅使用回环假凭据。
mod support;
use lengsuo_tls::{PrivatePkcs8KeyDer, TlsClient, TlsServer};
use lengsuo_trojan::{stream::*, Command, Credential, Request, TargetAddr};
use serde_json::{json, Value};
use support::*;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, UdpSocket},
    time::timeout,
};
const PASSWORD: &str = "trojan-udp-reference-test-password";
fn sizes() -> [usize; 3] {
    [1, 512, 1200]
}

struct Identity {
    cert: rcgen::CertifiedKey,
}
impl Identity {
    fn new() -> Self {
        Self {
            cert: rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap(),
        }
    }
    fn client(&self) -> TlsClient {
        TlsClient::new("localhost", [self.cert.cert.der().clone()], WAIT).unwrap()
    }
    fn server(&self) -> TlsServer {
        TlsServer::new(
            vec![self.cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(self.cert.key_pair.serialize_der()).into(),
            WAIT,
        )
        .unwrap()
    }
    fn server_settings(&self) -> Value {
        json!({"security":"tls","tlsSettings":{"certificates":[{
        "certificate":self.cert.cert.pem().lines().collect::<Vec<_>>(),
        "key":self.cert.key_pair.serialize_pem().lines().collect::<Vec<_>>() }]}})
    }
    fn client_settings(&self) -> Value {
        json!({"security":"tls","tlsSettings":{"serverName":"localhost",
        "disableSystemRoot":true,"certificates":[{"usage":"verify",
        "certificate":self.cert.cert.pem().lines().collect::<Vec<_>>()}]}})
    }
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_udp_client_to_xray_server_over_tls() {
    timeout(WAIT,async {
        let identity=Identity::new();
        let target=UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port=target.local_addr().unwrap().port();
        let port=free_port();
        let reference=launch(json!({"log":{"loglevel":"warning"},
            "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"trojan",
                "settings":{"clients":[{"password":PASSWORD}]},"streamSettings":identity.server_settings()}],
            "outbounds":[{"protocol":"freedom"}]}),port).await;
        let echo=tokio::spawn(async move {
            let mut buffer=[0;2048];
            for length in sizes() {
                let(received,peer)=target.recv_from(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..received],vec![0x42;length]);
                target.send_to(&buffer[..received],peer).await.unwrap();
            }
        });
        let mut stream=identity.client().connect(([127,0,0,1],port).into()).await.unwrap();
        let request=Request{command:Command::Udp,target:TargetAddr::V4([0;4],0)};
        send_request(&mut stream,&request,&Credential::new(PASSWORD),WAIT).await.unwrap();
        let target=TargetAddr::V4([127,0,0,1],target_port);
        for length in sizes() {
            send_datagram(&mut stream,&target,&vec![0x42;length],WAIT).await.unwrap();
            let(address,packet)=receive_datagram(&mut stream,2048,WAIT).await.unwrap();
            assert_eq!(address,target);
            assert_eq!(packet,vec![0x42;length]);
        }
        stream.shutdown().await.unwrap();echo.await.unwrap();drop(reference);
    }).await.unwrap();
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_udp_client_to_rust_server_over_tls() {
    timeout(WAIT, async {
        let identity = Identity::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rust_port = listener.local_addr().unwrap().port();
        let port = free_port();
        let reference = launch(
            json!({"log":{"loglevel":"warning"},
            "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"dokodemo-door",
                "settings":{"address":"127.0.0.1","port":18001,"network":"tcp,udp"}}],
            "outbounds":[{"protocol":"trojan","settings":{"servers":[{
                "address":"127.0.0.1","port":rust_port,"password":PASSWORD}]},
                "streamSettings":identity.client_settings()}]}),
            port,
        )
        .await;
        let server = identity.server();
        let worker = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let mut stream = server.accept(socket).await.unwrap();
                let request =
                    match receive_request(&mut stream, &Credential::new(PASSWORD), WAIT).await {
                        Ok(request) => request,
                        Err(Error::Io(_)) => continue,
                        Err(error) => panic!("请求失败 {error}"),
                    };
                if request.command == Command::Tcp {
                    continue;
                }
                for length in sizes() {
                    let (target, packet) = receive_datagram(&mut stream, 2048, WAIT).await.unwrap();
                    assert_eq!(target, TargetAddr::V4([127, 0, 0, 1], 18001));
                    assert_eq!(packet, vec![0x42; length]);
                    send_datagram(&mut stream, &target, &packet, WAIT)
                        .await
                        .unwrap();
                }
                stream.shutdown().await.unwrap();
                break;
            }
        });
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut buffer = [0; 2048];
        for length in sizes() {
            socket.send(&vec![0x42; length]).await.unwrap();
            let received = socket.recv(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..received], vec![0x42; length]);
        }
        worker.await.unwrap();
        drop(reference);
    })
    .await
    .unwrap();
}
