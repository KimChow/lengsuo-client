//! 回环 TCP 参考互通：本仓 SIP022 TCP 会话原语 ↔ Xray shadowsocks 入站。
//! 默认 `#[ignore]`（`LENGSUO_XRAY` 指向锁定基线二进制）；只绑 127.0.0.1、
//! 假 PSK base64、随机端口，参考进程由 support 守卫回收。
#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::crypto::{Key, Method};
use lengsuo_ss2022::tcp::receive::clock_at;
use lengsuo_ss2022::tcp::{Direction, Reader, SessionReplay, Writer};
use serde_json::json;
use ss_core::target::TargetAddr;
use std::time::{Duration, Instant};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn clock() -> lengsuo_ss2022::receiver::Clock {
    clock_at(now_secs(), Instant::now())
}

fn methods() -> [(Method, &'static str); 2] {
    [
        (Method::Aes128, "2022-blake3-aes-128-gcm"),
        (Method::Aes256, "2022-blake3-aes-256-gcm"),
    ]
}

async fn echo_server() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.expect("echo 监听")
}

/// Rust 客户端原语 → Xray SS2022 入站 → 本仓 echo：目标连通 + 回程数据一致。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn rust_client_to_xray_server_tcp() {
    timeout(WAIT, async {
        for (method, name) in methods() {
            let psk = vec![0x11; method.key_len()];
            let key = Key::new(method, &psk).unwrap();
            let target = echo_server().await;
            let target_port = target.local_addr().unwrap().port();
            let port = free_port();
            let _reference = launch(
                json!({"log":{"loglevel":"warning"},"inbounds":[{
                "listen":"127.0.0.1","port":port,"protocol":"shadowsocks",
                "settings":{"method":name,"password":STANDARD.encode(&psk),"network":"tcp"}}],
                "outbounds":[{"protocol":"freedom"}]}),
                port,
            )
            .await;

            // echo 任务：把收到的字节原样回发（一次读一个规格）。
            tokio::spawn(async move {
                let (mut socket, _) = target.accept().await.expect("echo 接受");
                let mut buffer = [0u8; 2048];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if socket.write_all(&buffer[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });

            // 客户端方向：salt 随机（Opening::random）、时间戳取当前。
            let mut client = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .expect("连接 Xray");
            let mut writer = Writer::random(&key, Direction::Request).expect("可构造");
            let target_addr = TargetAddr::V4([127, 0, 0, 1], target_port);
            writer
                .write_request_header(&mut client, &target_addr, b"first", now_secs(), 0)
                .await
                .expect("请求头可写");
            writer
                .write_payload(&mut client, b"second-payload")
                .await
                .expect("载荷可写");
            writer.write_finish(&mut client).await.expect("EOF 帧可写");

            // 读回程：Xray → echo → 回程。服务端方向响应头 + 载荷帧。
            let mut reader = Reader::new(key.clone(), Direction::Response, Duration::from_secs(5))
                .expect("可构造");
            let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
            // 请求的 session id 需要回填给响应绑定：Writer::random 的 id 取出来。
            let request_salt = writer.salt().to_vec();
            let opened = reader
                .open(
                    &mut client,
                    &mut replay,
                    clock(),
                    Some(request_salt.as_slice()),
                )
                .await
                .expect("响应开场应通过校验");
            assert!(
                matches!(
                    opened.association,
                    lengsuo_ss2022::tcp::receive::Association::Response(ref salt)
                        if salt == request_salt.as_slice()
                ),
                "响应回指 salt 必须等于请求 salt"
            );
            let mut got = Vec::new();
            got.extend_from_slice(&opened.payload);
            // Xray 回程不携带 EOF 帧（连接保持）；数据齐即视为完成，不再等 EOF。
            let want = b"firstsecond-payload";
            if got.len() < want.len() {
                while let Some(chunk) = reader.read_payload(&mut client).await.expect("载荷可读")
                {
                    got.extend_from_slice(&chunk);
                    if got.len() >= want.len() {
                        break;
                    }
                }
            }
            assert_eq!(&got[..want.len()], want, "{name:?} 回程载荷逐字节一致");
        }
    })
    .await
    .expect("SS2022 TCP 互通总超时");
}
