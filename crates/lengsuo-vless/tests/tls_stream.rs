//! Rust 客户端和服务端在认证 TLS 上运行真实 VLESS 数据交换。
use lengsuo_tls::{PrivatePkcs8KeyDer, TlsClient, TlsServer};
use lengsuo_vless::{
    header::{Command, Request},
    stream::*,
};
use ss_core::target::TargetAddr;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

#[tokio::test]
async fn authenticated_tls_vless_exchange_and_eof() {
    let wait = Duration::from_secs(3);
    timeout(wait, async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let server = TlsServer::new(vec![der.clone()], key.into(), wait).unwrap();
        let client = TlsClient::new("localhost", [der], wait).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = server.accept(socket).await.unwrap();
            let request = receive_request(&mut stream, &[7; 16], wait).await.unwrap();
            assert_eq!(request.command, Command::Tcp);
            assert_eq!(
                request.target,
                TargetAddr::Domain("test.invalid".into(), 443)
            );
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.unwrap();
            assert_eq!(payload, b"request payload");
            send_response(&mut stream, wait).await.unwrap();
            stream.write_all(b"response after EOF").await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut stream = client.connect(address).await.unwrap();
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::Domain("test.invalid".into(), 443),
        };
        send_request(&mut stream, &request, &[7; 16], wait)
            .await
            .unwrap();
        stream.write_all(b"request payload").await.unwrap();
        stream.shutdown().await.unwrap();
        receive_response(&mut stream, wait).await.unwrap();
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"response after EOF");
        task.await.unwrap();
    })
    .await
    .unwrap();
}
