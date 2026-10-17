//! 回环 TCP 反向真实互通：Xray shadowsocks 客户端出站 ↔ 本仓 SIP022 TCP **服务端视角**。
//!
//! `tests/xray_tcp.rs` 只覆盖 Rust 客户端 → Xray 服务端；本文件补齐反方向：
//! Xray（v26.3.27 / `d2758a0…`，由 `LENGSUO_XRAY` 显式提供）socks 入站接收本端
//! SOCKS5 请求，shadowsocks 出站连到本端随机回环监听端口；本端用
//! [`Reader`]（`Direction::Request`）解出 salt + 固定头 + 变长头（目标地址、随机
//! padding、首批载荷）与后续载荷帧，中继到本仓 spawn 的 echo 目标，再用
//! [`Writer`]（`Direction::Response`）以 `Opened.request_salt` 回写响应固定头 +
//! 载荷帧。线格式一律由产品 API 产生与解析，测试不自造协议字节。
//!
//! 覆盖 AES-128/AES-256 × 载荷 1/512/1200 字节（Xray 对 <900 字节的载荷必带
//! 1..900 随机 padding，≥900 时 padding 为 0，两条路径都走到）；响应方向先写
//! 半个载荷作为固定头声明的首批载荷，再写余下 chunk，验证 nonce 跨 chunk 连续。
//! 收尾走 TCP 半关闭：本端写完 EOF chunk 后 `shutdown` 写半，再等请求方向 EOF。
//!
//! 所有 I/O 都有有限超时；参考进程由 `support::Reference` 的 `Drop` 回收；只绑
//! 127.0.0.1、假 PSK、随机端口，不监听公网、不读生产配置、不连接任何 VPS。

#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;

use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::crypto::{Key, Method};
use lengsuo_ss2022::tcp::receive::clock_at;
use lengsuo_ss2022::tcp::{
    Association, Direction, Reader, SessionReplay, Writer, MAX_CHUNK_PAYLOAD,
};
use serde_json::json;
use ss_core::target::TargetAddr;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use support::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

mod reverse_support;
use reverse_support::*;

/// Xray 客户端 → Rust 服务端：AES-128/256 × 1/512/1200 字节，含半关闭收尾。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn xray_client_to_rust_server_tcp() {
    timeout(OVERALL, async {
        for (method, name) in methods() {
            let psk = vec![0x11; method.key_len()];
            let key = Key::new(method, &psk).expect("假 PSK 应可用");
            let echo = TcpListener::bind(BIND).await.expect("echo 应可监听");
            let echo_port = echo.local_addr().expect("echo 应有地址").port();
            // 本仓“服务端”只监听随机回环端口，密钥与 Xray 出站完全一致。
            let server = TcpListener::bind(BIND).await.expect("本端应可监听");
            let rust_port = server.local_addr().expect("本端应有地址").port();
            let specs = sizes();
            let echo_task = tokio::spawn(serve_echo(echo, specs.len()));
            let served_task = tokio::spawn(rust_server(server, key.clone(), specs.len()));
            let port = free_port();
            let reference = launch(
                json!({
                    "log": {"loglevel": "warning"},
                    "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                        "settings": {"auth": "noauth", "udp": false}}],
                    "outbounds": [{"protocol": "shadowsocks", "settings": {"servers": [{
                        "address": "127.0.0.1", "port": rust_port,
                        "method": name, "password": STANDARD.encode(&psk)}]}}]
                }),
                port,
            )
            .await;
            let target = TargetAddr::V4(LOOPBACK, echo_port);
            for size in specs {
                let want = line(size);
                let mut stream = socks5_connect(port, &target).await;
                timeout(WAIT, stream.write_all(&want))
                    .await
                    .expect("SOCKS 写载荷超时")
                    .expect("SOCKS 写载荷失败");
                let mut reply = read_line(&mut stream, ECHO_LIMIT).await;
                // 回程跨 chunk：首批载荷在响应固定头里，其后按载荷帧补齐。
                while reply.len() < want.len() {
                    reply.extend_from_slice(&read_line(&mut stream, ECHO_LIMIT).await);
                }
                assert_eq!(reply, want, "{name} / {size} 字节端到端载荷不符");
                // 收齐之后才关写半，避免参考实现提前收尾丢掉回程数据。
                timeout(WAIT, stream.shutdown())
                    .await
                    .expect("本端关闭写半超时")
                    .expect("本端应可半关闭");
                drop(stream);
            }
            let served = served_task.await.expect("本端服务任务");
            assert_eq!(served.len(), specs.len(), "本端应处理每条互通连接");
            for (index, one) in served.iter().enumerate() {
                let size = specs[index];
                assert_eq!(
                    one.target,
                    Some(target.clone()),
                    "{name} / {size} 解出的目标地址不符"
                );
                assert_eq!(one.request, line(size), "{name} / {size} 请求方向载荷不符");
                assert!(
                    one.chunk_lens
                        .iter()
                        .all(|&len| len > 0 && len <= MAX_CHUNK_PAYLOAD),
                    "{name} / {size} 请求 chunk 规格不符：{:?}",
                    one.chunk_lens
                );
                assert!(
                    one.peer_closed,
                    "{name} / {size} 请求方向应在半关闭后收到 EOF"
                );
            }
            drop(reference);
            timeout(WAIT, echo_task)
                .await
                .expect("echo 服务任务超时")
                .expect("echo 服务任务失败");
        }
    })
    .await
    .expect("Xray 客户端 → Rust 服务端 TCP 反向互通超时")
}
