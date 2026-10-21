//! **固定基线参考**（Xray v26.3.27，commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）
//! 的重放行为**独立复核**。
//!
//! 本文件不照抄审计结论，而是用实跑证据回答三个问题：
//!
//! 1. **参考的请求头里有没有一次性字段**（nonce / 时间戳 / 会话标识 / 序号）？
//!    做法：让参考客户端连到**头部捕获端**（被动观察者，只按 Trojan 头部格式
//!    记录字节，不参与认证/路由），开**两次独立会话**，断言两段头部**逐字节
//!    相同**；再断言头部前缀 == 独立实现的 SHA-224(口令) ⇒ 前缀是**口令的函数**。
//!    两者合起来 ⇒ 头部里没有任何一次性字段。
//! 2. **参考会不会因为重放而拒绝**？
//!    做法：让参考**服务端**接收一次合法请求，把同一段头部在新连接上重放，
//!    断言它**被当作新请求接受**（业务目标 accept 计数从 1 涨到 2）。
//! 3. **参考客户端重放自己的头会怎样**？
//!    做法：让参考客户端连参考服务端两次，断言第二次同样被接受。
//!
//! 判定纪律：拒绝必须有独立观测面（业务目标 accept 计数），**不把「我方读
//! 超时」当拒绝**；每条用例都带正常对照组，对照组必须真的走通。
//!
//! 这些用例默认忽略；必须用 `--ignored` 实跑并贴退出码。

use super::harness::*;
use super::sha224::hex_sha224;
use super::support;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 捕获端读到一段头部后可能还要等业务目标回程，给足预算。
pub const CAPTURE_BOUND: Duration = Duration::from_secs(15);

/// 最小 SOCKS5 TCP CONNECT（no-auth + IPv4 目标），返回建好的隧道。
pub async fn socks5_tcp_connect(proxy_port: u16, target_port: u16) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(std::io::Error::other("socks 协商失败"));
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&[127, 0, 0, 1]);
    request.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "socks CONNECT 失败",
        ));
    }
    let extra = match head[3] {
        1 => 4 + 2,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            usize::from(length[0]) + 2
        }
        4 => 16 + 2,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "非法 bind ATYP",
            ))
        }
    };
    let mut tail = vec![0u8; extra];
    stream.read_exact(&mut tail).await?;
    Ok(stream)
}

/// 参考客户端配置：本地 socks5 入站 + 指向指定服务端地址的 trojan 出站。
///
/// `server_port` 可以是参考服务端的端口（纯 trojan，无 TLS），也可以是
/// 头部捕获端的端口（观察参考客户端写出的原始字节）。
pub fn reference_client_config(socks_port: u16, server_port: u16, password: &str) -> Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":socks_port,"protocol":"socks",
            "settings":{"auth":"noauth"}}],
        "outbounds":[{"protocol":"trojan","settings":{"servers":[{
            "address":"127.0.0.1","port":server_port,"password":password}]}}]})
}

/// 参考服务端配置：trojan 入站（纯协议，无 TLS）+ freedom 出口。
pub fn reference_server_config(port: u16, password: &str) -> Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"trojan",
            "settings":{"clients":[{"password":password}]}}],
        "outbounds":[{"protocol":"freedom"}]})
}

/// 参考服务端配置（带 TLS），供本仓客户端对接的对照组使用。
pub fn reference_server_tls_config(port: u16, password: &str, identity: &Identity) -> Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"trojan",
            "settings":{"clients":[{"password":password}]},
            "streamSettings":{"security":"tls","tlsSettings":{"certificates":[{
                "certificate":identity.cert.cert.pem().lines().collect::<Vec<_>>(),
                "key":identity.cert.key_pair.serialize_pem().lines().collect::<Vec<_>>()}]}}}],
        "outbounds":[{"protocol":"freedom"}]})
}

/// 参考客户端的 trojan 出站加 TLS（对照：参考客户端 → 本仓 TLS 服务端）。
pub fn reference_client_tls_config(
    socks_port: u16,
    server_port: u16,
    password: &str,
    identity: &Identity,
) -> Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":socks_port,"protocol":"socks",
            "settings":{"auth":"noauth"}}],
        "outbounds":[{"protocol":"trojan","settings":{"servers":[{
            "address":"127.0.0.1","port":server_port,"password":password}]},
            "streamSettings":identity.client_settings()}]})
}

/// 参考客户端在一条 socks 隧道上完成一次 CONNECT + 载荷往返。
pub async fn reference_round_trip(socks_port: u16, target_port: u16) {
    let mut tunnel = socks5_tcp_connect(socks_port, target_port)
        .await
        .expect("socks CONNECT 应成功");
    timeout(WAIT, tunnel.write_all(PAYLOAD))
        .await
        .expect("写入请求超时")
        .expect("写入请求失败");
    timeout(WAIT, tunnel.flush())
        .await
        .expect("flush 超时")
        .expect("flush 失败");
    let mut reply = vec![0u8; PAYLOAD.len()];
    timeout(WAIT, tunnel.read_exact(&mut reply))
        .await
        .expect("回程超时")
        .expect("回程读失败");
    assert_eq!(reply, PAYLOAD, "参考客户端的回程必须逐字节一致");
}

/// ① 参考请求头里**没有一次性字段**：两次独立会话的头部逐字节相同，
///    且前缀 == 独立实现的 SHA-224(口令)。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn reference_header_has_no_one_time_field() {
    timeout(TOTAL, async {
        // 捕获端后面挂一个业务目标：参考客户端会把它当目标。
        let target = EchoTarget::spawn(PAYLOAD.len()).await;
        // 上游是普通回显目标 ⇒ 头部不转发（否则目标会把头部字节当载荷回显）。
        let capture = CaptureServer::spawn(target.port, false).await;

        // 两次**独立**会话（两次独立启动的参考客户端进程）。
        let mut session_headers: Vec<Vec<u8>> = Vec::new();
        for index in 0..2 {
            let before = capture.headers().len();
            let socks = support::free_port();
            let reference = support::launch(
                reference_client_config(socks, capture.port, PASSWORD),
                socks,
            )
            .await;
            reference_round_trip(socks, target.port).await;
            drop(reference);
            // 等捕获端把这一段头部记下来。
            let deadline = tokio::time::Instant::now() + CAPTURE_BOUND;
            loop {
                let seen = capture.headers();
                if seen.len() > before {
                    assert_eq!(seen.len() - before, 1, "第 {index} 次会话只应产生一个头部");
                    session_headers.push(seen[before].clone());
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "捕获端未在预算内看到参考客户端写出的头部"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        // 两次会话的头部必须逐字节相同。
        assert_eq!(session_headers.len(), 2, "必须捕获到两段会话的头部");
        assert_eq!(
            session_headers[0], session_headers[1],
            "两次独立会话的头部必须逐字节相同（头部不得含 nonce/时间戳/会话标识）"
        );

        // 前缀是口令的函数（与独立实现的 SHA-224 一致），不是会话随机数。
        let header = &session_headers[0];
        assert_eq!(
            &header[..56],
            hex_sha224(PASSWORD).as_bytes(),
            "参考头部前缀必须是口令的 SHA-224 小写 hex"
        );
        assert_eq!(&header[56..58], b"\r\n", "哈希后必须是 CRLF");
        assert_eq!(header[58], 1, "命令字节必须是 TCP=1");
        assert_eq!(&header[59..60], &[0x01], "ATYP 必须是 IPv4");
        assert_eq!(&header[66..68], b"\r\n", "尾部必须是 CRLF");

        capture.stop().await;
    })
    .await
    .unwrap();
}

/// ② 参考**服务端**不因重放而拒绝：同一段头部在新连接上重放被当作新请求接受。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn reference_server_accepts_replayed_header() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let target = EchoTarget::spawn(PAYLOAD.len()).await;

        // 捕获端：拿到参考客户端写出的头部，同时把它转发给业务目标。
        // 这里捕获端放在**客户端与参考服务端之间**：参考客户端 → 捕获端 → 参考服务端。
        // 捕获端对参考服务端而言是普通 TCP 客户端，所以它发出去的头就是参考客户端的头。
        let server_port = support::free_port();
        let reference =
            support::launch(reference_server_config(server_port, PASSWORD), server_port).await;
        let capture = CaptureServer::spawn(server_port, true).await;

        // 第一次：参考客户端 → 捕获端 → 参考服务端 → 业务目标。
        let socks = support::free_port();
        let client = support::launch(
            reference_client_config(socks, capture.port, PASSWORD),
            socks,
        )
        .await;
        reference_round_trip(socks, target.port).await;
        drop(client);

        // 等捕获端记下第一段头部。
        let deadline = tokio::time::Instant::now() + CAPTURE_BOUND;
        loop {
            if !capture.headers().is_empty() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "捕获端未在预算内看到参考客户端写出的头部"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let header = capture.headers().remove(0);
        assert_eq!(header.len(), 68, "IPv4 目标的 trojan 头部长度应为 68 字节");
        assert_eq!(
            target.accepted(),
            1,
            "对照组：第一次请求必须抵达业务目标一次"
        );

        // 第二次：把**同一段**头部原样发给参考服务端（新连接）。
        // 头部是纯明文协议（参考服务端此处未开 TLS），所以可以直接重放。
        let mut replay = TcpStream::connect(("127.0.0.1", server_port))
            .await
            .unwrap();
        replay.write_all(&header).await.unwrap();
        replay.write_all(PAYLOAD).await.unwrap();
        replay.flush().await.unwrap();
        let mut reply = vec![0u8; PAYLOAD.len()];
        timeout(WAIT, replay.read_exact(&mut reply))
            .await
            .expect("重放的回程超时")
            .expect("重放的回程读失败");
        assert_eq!(
            reply, PAYLOAD,
            "重放的请求必须被参考服务端正常处理（不被拒绝）"
        );
        replay.shutdown().await.unwrap();

        // 独立观测面：业务目标被连接了两次 ⇒ 参考服务端确实把重放当成新请求。
        assert_eq!(
            target.accepted(),
            2,
            "参考服务端必须把重放当作新请求（业务目标被连接两次）"
        );

        capture.stop().await;
        drop(reference);
        let _ = identity;
    })
    .await
    .unwrap();
}
