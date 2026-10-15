//! 固定基线双向 Trojan/TLS 互通，测试证书运行时生成，不跳过验证。
mod support;
use lengsuo_tls::{PrivatePkcs8KeyDer, TlsClient, TlsServer};
use lengsuo_trojan::{Command, Credential, Request};
use serde_json::json;
use ss_core::target::TargetAddr;
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
const PASSWORD: &str = "trojan-reference-test-password";
const PAYLOAD: &[u8] = b"authenticated reference TLS payload\0\xff";

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_tls_client_to_xray_server() {
    timeout(WAIT, async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = listener.local_addr().unwrap().port();
        let port = free_port();
        let reference = launch(
            json!({
                "log":{"loglevel":"warning"},
                "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"trojan",
                    "settings":{"clients":[{"password":PASSWORD}]},
                    "streamSettings":{"security":"tls","tlsSettings":{"certificates":[{
                        "certificate":cert.cert.pem().lines().collect::<Vec<_>>(),
                        "key":cert.key_pair.serialize_pem().lines().collect::<Vec<_>>() }]}}}],
                "outbounds":[{"protocol":"freedom"}]
            }),
            port,
        )
        .await;
        let endpoint = ([127, 0, 0, 1], port).into();
        let wrong = TlsClient::new("wrong.invalid", [cert.cert.der().clone()], WAIT).unwrap();
        assert!(wrong.connect(endpoint).await.is_err(), "错误名称必须失败");
        let unknown = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let wrong = TlsClient::new("localhost", [unknown.cert.der().clone()], WAIT).unwrap();
        assert!(
            wrong.connect(endpoint).await.is_err(),
            "不信任的证书必须失败"
        );
        let echo = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut payload = vec![0; PAYLOAD.len()];
            socket.read_exact(&mut payload).await.unwrap();
            assert_eq!(payload, PAYLOAD);
            socket.write_all(&payload).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let client = TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap();
        let mut stream = client.connect(endpoint).await.unwrap();
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], target_port),
        };
        send_request(&mut stream, &request, &Credential::new(PASSWORD), WAIT)
            .await
            .unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.flush().await.unwrap();
        let mut received = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, PAYLOAD);
        stream.shutdown().await.unwrap();
        echo.await.unwrap();
        drop(reference);
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_tls_client_to_rust_server() {
    timeout(WAIT, async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server = TlsServer::new(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            WAIT,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rust_port = listener.local_addr().unwrap().port();
        let port = free_port();
        let reference = launch(
            json!({
                "log":{"loglevel":"warning"},
                "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"dokodemo-door",
                    "settings":{"address":"127.0.0.1","port":18001,"network":"tcp"}}],
                "outbounds":[{"protocol":"trojan","settings":{"servers":[{
                    "address":"127.0.0.1","port":rust_port,"password":PASSWORD}]},
                    "streamSettings":{"security":"tls","tlsSettings":{"serverName":"localhost",
                        "disableSystemRoot":true,"certificates":[{"usage":"verify",
                            "certificate":cert.cert.pem().lines().collect::<Vec<_>>()}]}}}]
            }),
            port,
        )
        .await;
        let worker = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let mut stream = server.accept(socket).await.unwrap();
                let request =
                    match receive_request(&mut stream, &Credential::new(PASSWORD), WAIT).await {
                        Ok(request) => request,
                        Err(_) => continue,
                    };
                assert_eq!(
                    request,
                    Request {
                        command: Command::Tcp,
                        target: TargetAddr::V4([127, 0, 0, 1], 18001)
                    }
                );
                let mut payload = vec![0; PAYLOAD.len()];
                if stream.read_exact(&mut payload).await.is_err() {
                    continue;
                }
                assert_eq!(payload, PAYLOAD);
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
                break;
            }
        });
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        let mut payload = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, PAYLOAD);
        stream.shutdown().await.unwrap();
        worker.await.unwrap();
        drop(reference);
    })
    .await
    .unwrap();
}

async fn send_request<W: tokio::io::AsyncWrite + Unpin>(
    stream: &mut W,
    request: &Request,
    credential: &Credential,
    wait: std::time::Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = lengsuo_trojan::encode(request, credential)?;
    timeout(wait, async {
        stream.write_all(&bytes).await?;
        stream.flush().await
    })
    .await??;
    Ok(())
}
async fn receive_request<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
    credential: &Credential,
    wait: std::time::Duration,
) -> Result<Request, Box<dyn std::error::Error + Send + Sync>> {
    timeout(wait, async {
        let mut bytes = Vec::new();
        loop {
            match lengsuo_trojan::decode(&bytes, credential) {
                Ok((request, _)) => return Ok(request),
                Err(lengsuo_trojan::codec::Error::Truncated { .. }) => {
                    bytes.push(stream.read_u8().await?)
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await?
}
