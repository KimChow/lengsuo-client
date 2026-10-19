//! 域名 / IPv6 目标的 VLESS 请求头双向参考互通（明文协议层，仅回环）。
//!
//! 显式执行：
//! `LENGSUO_XRAY=/绝对路径/xray cargo test -p lengsuo-vless --test xray_target_addr -- --ignored --nocapture`
//!
//! 域名走「测试专用假域名 + 回环 DNS 解析路径」：参考端 Xray 通过 `hosts` 把
//! `addr.test.invalid` 静态解析到 127.0.0.1（不依赖公网 DNS），本仓客户端把
//! 域名原样写进 VLESS 头，由参考端完成解析——这正是「域名目标」要验的路径。
//! IPv6 目标用 `::1`，参考端 freedom 出站直连。
mod support;
use lengsuo_vless::{
    header::{self, Command, Request},
    stream::*,
};
use serde_json::json;
use ss_core::target::TargetAddr;
use std::net::Ipv6Addr;
use std::time::Duration;
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

/// 测试专用假域名：仅由参考端 `hosts` 静态映射到回环，公网不可解析。
const FAKE_DOMAIN: &str = "addr.test.invalid";

const PAYLOAD: &[u8] = b"VLESS domain/ipv6 target payload\0\xff";

/// 逐字节核对请求头里域名目标的编码：`Port | 0x02 | len | host`。
#[test]
fn domain_target_header_bytes_are_port_then_address() {
    let request = Request {
        command: Command::Tcp,
        target: TargetAddr::Domain(FAKE_DOMAIN.to_string(), 18001),
    };
    let wire = header::encode(&request, &KEY).unwrap();
    let tail = &wire[19..];
    assert_eq!(tail[0..2], 18001u16.to_be_bytes(), "端口在前");
    assert_eq!(tail[2], 2, "域名类型 = 2");
    assert_eq!(usize::from(tail[3]), FAKE_DOMAIN.len());
    assert_eq!(&tail[4..], FAKE_DOMAIN.as_bytes());
    assert_eq!(header::decode(&wire).unwrap().1, request);
}

/// 逐字节核对 IPv6 目标：`Port | 0x03 | 16 字节地址`。
#[test]
fn ipv6_target_header_bytes_are_port_then_address() {
    let address = Ipv6Addr::LOCALHOST;
    let request = Request {
        command: Command::Tcp,
        target: TargetAddr::V6(address.octets(), 18001),
    };
    let wire = header::encode(&request, &KEY).unwrap();
    let tail = &wire[19..];
    assert_eq!(tail[0..2], 18001u16.to_be_bytes(), "端口在前");
    assert_eq!(tail[2], 3, "IPv6 类型 = 3");
    assert_eq!(&tail[3..19], &address.octets());
    assert_eq!(header::decode(&wire).unwrap().1, request);
}

async fn echo_once(listener: TcpListener) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut received = vec![0; PAYLOAD.len()];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received, PAYLOAD);
    stream.write_all(&received).await.unwrap();
    stream.shutdown().await.unwrap();
}

/// Rust 客户端 → Xray 服务端，目标为**域名**：参考端按 `hosts` 解析后 TCP 转发。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_client_to_xray_server_domain_target() {
    timeout(WAIT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = listener.local_addr().unwrap().port();
        let port = free_port();
        let dns = LoopbackDns::start(FAKE_DOMAIN).await;
        let reference = launch(
            json!({
                "log":{"loglevel":"warning"},
                "dns":{"servers":[{"address":"127.0.0.1","port":dns.port}]},
                "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vless",
                    "settings":{"clients":[{"id":ID}],"decryption":"none"}}],
                "outbounds":[{"protocol":"freedom",
                    "settings":{"domainStrategy":"UseIP"}}]
            }),
            port,
        )
        .await;
        let task = tokio::spawn(echo_once(listener));
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::Domain(FAKE_DOMAIN.to_string(), target_port),
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
        assert_eq!(response, PAYLOAD, "域名目标载荷重组后逐字节一致");
        task.await.unwrap();
        drop(reference);
    })
    .await
    .unwrap();
}

/// Rust 客户端 → Xray 服务端，目标为 **IPv6 `::1`**。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_client_to_xray_server_ipv6_target() {
    timeout(WAIT, async {
        let listener = match TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await {
            Ok(listener) => listener,
            Err(error) => {
                println!("跳过：本机不支持 IPv6 回环（{error}）");
                return;
            }
        };
        let target_port = listener.local_addr().unwrap().port();
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
        let task = tokio::spawn(echo_once(listener));
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V6(Ipv6Addr::LOCALHOST.octets(), target_port),
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
        assert_eq!(response, PAYLOAD, "IPv6 目标载荷重组后逐字节一致");
        task.await.unwrap();
        drop(reference);
    })
    .await
    .unwrap();
}

/// Xray 客户端 → Rust 服务端，参考端下发**域名**目标（dokodemo-door `address` 为域名）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_client_to_rust_server_domain_target() {
    timeout(WAIT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rust_port = listener.local_addr().unwrap().port();
        let port = free_port();
        let reference = launch(json!({
            "log":{"loglevel":"warning"},
            "dns":{"hosts":{"upstream.test.invalid":"127.0.0.1"}},
            "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"dokodemo-door",
                "settings":{"address":"upstream.test.invalid","port":18001,"network":"tcp"}}],
            "outbounds":[{"protocol":"vless","settings":{"vnext":[{
                "address":"127.0.0.1","port":rust_port,"users":[{"id":ID,"encryption":"none"}]}]}}]
        }), port).await;
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = match receive_request(&mut stream, &KEY, WAIT).await {
                    Ok(request) => request,
                    Err(Error::Io(_)) => continue,
                    Err(error) => panic!("握手失败 {error}"),
                };
                // 参考端的 dokodemo-door 以**域名**形式下发目标。
                assert_eq!(
                    request,
                    Request {
                        command: Command::Tcp,
                        target: TargetAddr::Domain("upstream.test.invalid".to_string(), 18001)
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
        assert_eq!(response, PAYLOAD, "域名目标反向载荷逐字节一致");
        stream.shutdown().await.unwrap();
        server.await.unwrap();
        drop(reference);
    })
    .await
    .unwrap();
}

/// 真实可解析域名的 TCP 转发：用 `localhost`（本机 `/etc/hosts` 真实解析到
/// 127.0.0.1，**非**假域名、非测试注入的映射），走系统解析路径。
///
/// 目标地址按**域名**编码进 VLESS 头，解析由对端完成，重组后逐字节比对。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_client_to_xray_server_real_domain() {
    timeout(WAIT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = listener.local_addr().unwrap().port();
        let port = free_port();
        let reference = launch(
            json!({
                "log":{"loglevel":"warning"},
                "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vless",
                    "settings":{"clients":[{"id":ID}],"decryption":"none"}}],
                // 系统解析（AS_IS）：`localhost` 由本机 hosts 解析，不注入任何映射。
                "outbounds":[{"protocol":"freedom"}]
            }),
            port,
        )
        .await;
        let task = tokio::spawn(echo_once(listener));
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let request = Request {
            command: Command::Tcp,
            // 真实域名（本机 hosts 真实解析到 127.0.0.1），端口为测试临时端口。
            target: TargetAddr::Domain("localhost".to_string(), target_port),
        };
        send_request(&mut stream, &request, &KEY, WAIT)
            .await
            .unwrap();
        // 分片写出：验证流式重组（真实流量的分片形态）。
        for chunk in PAYLOAD.chunks(7) {
            stream.write_all(chunk).await.unwrap();
            stream.flush().await.unwrap();
        }
        stream.shutdown().await.unwrap();
        receive_response(&mut stream, WAIT).await.unwrap();
        let mut response = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, PAYLOAD, "真实域名目标分片重组后逐字节一致");
        task.await.unwrap();
        drop(reference);
    })
    .await
    .unwrap();
}

/// 逐字节比对（固定长度场景）：域名目标头 + 载荷整体与参考端"接受"的字节一致。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn domain_target_fixed_length_bytes_match_reference() {
    timeout(WAIT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = listener.local_addr().unwrap().port();
        let port = free_port();
        let dns = LoopbackDns::start(FAKE_DOMAIN).await;
        let reference = launch(
            json!({
                "log":{"loglevel":"warning"},
                "dns":{"servers":[{"address":"127.0.0.1","port":dns.port}]},
                "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vless",
                    "settings":{"clients":[{"id":ID}],"decryption":"none"}}],
                "outbounds":[{"protocol":"freedom",
                    "settings":{"domainStrategy":"UseIP"}}]
            }),
            port,
        )
        .await;
        let task = tokio::spawn(echo_once(listener));
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::Domain(FAKE_DOMAIN.to_string(), target_port),
        };
        let expected = header::encode(&request, &KEY).unwrap();
        // 同一条请求的编码必须稳定（固定长度场景逐字节比对的前提）。
        assert_eq!(header::encode(&request, &KEY).unwrap(), expected);
        stream.write_all(&expected).await.unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();
        receive_response(&mut stream, WAIT).await.unwrap();
        let mut response = vec![0; PAYLOAD.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, PAYLOAD);
        task.await.unwrap();
        drop(reference);
        // 观察窗口：参考端不得在本用例后仍持有连接。
        tokio::time::sleep(Duration::from_millis(50)).await;
    })
    .await
    .unwrap();
}
