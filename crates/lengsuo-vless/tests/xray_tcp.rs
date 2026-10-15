//! 显式执行：LENGSUO_XRAY=/绝对路径/xray cargo test -p lengsuo-vless --test xray_tcp -- --ignored --nocapture
//! 仅回环明文协议层对拍，不代表安全传输、UDP、Vision 或 Windows 验收。
use lengsuo_vless::{
    header::{Command, Request},
    stream::*,
};
use serde_json::json;
use ss_core::target::TargetAddr;
use std::time::Duration;
mod support;
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const PAYLOAD: &[u8] = b"VLESS independent reference payload\0with binary\xff";

async fn echo(listener: TcpListener) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut received = vec![0; PAYLOAD.len()];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received, PAYLOAD);
    stream.write_all(&received).await.unwrap();
    stream.shutdown().await.unwrap();
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_client_to_xray_server_tcp() {
    timeout(WAIT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().port();
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
        let task = tokio::spawn(echo(listener));
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], target),
        };
        send_request(&mut stream, &request, &KEY, WAIT)
            .await
            .unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();
        receive_response(&mut stream, WAIT).await.unwrap();
        let mut response = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, PAYLOAD);
        stream.shutdown().await.unwrap();
        task.await.unwrap();
        let denied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let denied_port = denied.local_addr().unwrap().port();
        let mut invalid = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let bad = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], denied_port),
        };
        send_request(&mut invalid, &bad, &[0x22; 16], WAIT)
            .await
            .unwrap();
        assert!(matches!(
            receive_response(&mut invalid, WAIT).await,
            Err(Error::Io(_))
        ));
        assert!(
            timeout(Duration::from_millis(100), denied.accept())
                .await
                .is_err(),
            "错误凭据不得连接目标"
        );
        drop(reference);
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_client_to_rust_server_tcp() {
    timeout(WAIT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rust_port = listener.local_addr().unwrap().port();
        let port = free_port();
        let reference = launch(json!({
            "log":{"loglevel":"warning"},
            "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"dokodemo-door",
                "settings":{"address":"127.0.0.1","port":18001,"network":"tcp"}}],
            "outbounds":[{"protocol":"vless","settings":{"vnext":[{
                "address":"127.0.0.1","port":rust_port,"users":[{"id":ID,"encryption":"none"}]}]}}]
        }), port).await;
        let server = tokio::spawn(async move {
            // 启动探测可能让参考客户端提前建立一条无载荷连接。
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = match receive_request(&mut stream, &KEY, WAIT).await {
                    Ok(request) => request,
                    Err(Error::Io(_)) => continue,
                    Err(error) => panic!("握手失败 {error}"),
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
                send_response(&mut stream, WAIT).await.unwrap();
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
                break;
            }
        });
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        let mut response = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, PAYLOAD);
        stream.shutdown().await.unwrap();
        server.await.unwrap();
        drop(reference);
    })
    .await
    .unwrap();
}
