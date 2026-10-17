//! 回环 TCP 参考互通：本仓 SIP022 TCP 会话原语 ↔ Xray shadowsocks 入站。
//! 默认 `#[ignore]`（`LENGSUO_XRAY` 指向锁定基线二进制）；只绑 127.0.0.1、
//! 假 PSK base64、随机端口，参考进程由 support 守卫回收。
//!
//! 变长头按 SIP022 §3.1.3 与 sing-shadowsocks v0.2.7 `writeRequest` 逐字节对齐：
//! `ATYP+地址+port(u16be) | padding length(u16be) | padding | 首批载荷`。
//! 因此这里必须带**非零 padding** 跑互通：若 padding 字段位置或固定头 length
//! 声明与参考实现不一致，Xray 会把 padding 字节当载荷转发到目标端，
//! 下面的“目标端实收字节”断言会立刻失败。
#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::crypto::{Key, Method};
use lengsuo_ss2022::tcp::receive::clock_at;
use lengsuo_ss2022::tcp::{Association, Direction, Reader, SessionReplay, Writer};
use serde_json::json;
use ss_core::target::TargetAddr;
use std::sync::{Arc, Mutex};
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

/// 变长头 padding 用例：非零 padding 为主，并覆盖首批载荷为空（只有 padding）
/// 与 padding 上限 900，逐字节核对 Xray 转发到目标端的实收内容。
fn padding_cases() -> Vec<(&'static str, &'static [u8], u16)> {
    vec![
        ("pad8", &b"first"[..], 8),
        ("pad1", &b"first"[..], 1),
        ("pad17", &b"first"[..], 17),
        ("pad900", &b"first"[..], 900),
        ("pad8-no-initial-payload", &b""[..], 8),
        ("pad900-no-initial-payload", &b""[..], 900),
    ]
}

/// Rust 客户端原语 → Xray SS2022 入站 → 本仓 echo：目标连通 + 两向数据一致。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn rust_client_to_xray_server_tcp() {
    timeout(WAIT, async {
        for (method, name) in methods() {
            for (case, initial, padding) in padding_cases() {
                let psk = vec![0x11; method.key_len()];
                let key = Key::new(method, &psk).unwrap();
                // Xray 解出变长头后转发给目标端的实际字节（padding 不得出现在这里）。
                let upstream: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
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

                // echo 任务：记录实收字节并把它们原样回发（一次读一个规格）。
                let record = Arc::clone(&upstream);
                tokio::spawn(async move {
                    let (mut socket, _) = target.accept().await.expect("echo 接受");
                    let mut buffer = [0u8; 4096];
                    loop {
                        match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                record.lock().unwrap().extend_from_slice(&buffer[..n]);
                                if socket.write_all(&buffer[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });

                // 客户端方向：salt 随机（Opening::random）、时间戳取当前、非零 padding。
                let mut client =
                    tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                        .await
                        .expect("连接 Xray");
                let mut writer = Writer::random(&key, Direction::Request).expect("可构造");
                let target_addr = TargetAddr::V4([127, 0, 0, 1], target_port);
                writer
                    .write_request_header(&mut client, &target_addr, initial, now_secs(), padding)
                    .await
                    .unwrap_or_else(|error| panic!("{name} {case} 请求头可写：{error:?}"));
                writer
                    .write_payload(&mut client, b"second-payload")
                    .await
                    .expect("载荷可写");
                writer.write_finish(&mut client).await.expect("EOF 帧可写");

                // 读回程：Xray → echo → 回程。服务端方向响应头 + 载荷帧。
                let mut reader =
                    Reader::new(key.clone(), Direction::Response, Duration::from_secs(5))
                        .expect("可构造");
                let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
                let request_salt = writer.salt().to_vec();
                let opened = reader
                    .open(&mut client, &mut replay, clock(), Some(&request_salt))
                    .await
                    .unwrap_or_else(|error| panic!("{name} {case} 响应开场校验：{error:?}"));
                assert!(
                    matches!(&opened.association, Association::Response(salt)
                        if salt == &request_salt),
                    "{name} {case} 响应回指 salt 必须等于请求 salt"
                );
                let want = [initial, b"second-payload"].concat();
                let mut got = opened.payload.clone();
                // Xray 回程不携带 EOF 帧（连接保持）；数据齐即视为完成，不再等 EOF。
                while got.len() < want.len() {
                    match reader.read_payload(&mut client).await.expect("载荷可读") {
                        Some(chunk) => got.extend_from_slice(&chunk),
                        None => break,
                    }
                }
                assert_eq!(got, want, "{name} {case} 回程载荷逐字节一致");
                // 互通关键断言：目标端只应看到载荷；padding 被 Xray 正确吃掉。
                let deadline = Instant::now() + Duration::from_secs(2);
                while Instant::now() < deadline {
                    if upstream.lock().unwrap().len() >= want.len() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                assert_eq!(
                    *upstream.lock().unwrap(),
                    want,
                    "{name} {case} padding={padding} Xray 转发到目标端的字节必须恰为载荷，\
                     多出/错位的字节说明变长头 padding 布局与参考实现不一致"
                );
            }
        }
    })
    .await
    .expect("SS2022 TCP 互通总超时");
}
