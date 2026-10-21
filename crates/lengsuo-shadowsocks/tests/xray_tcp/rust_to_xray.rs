//! 方向一：本端作客户端，Xray 作服务端。
//!
//! 本端 `TcpWriter` 写 salt + `TargetAddr::encode_checked` 的目标地址 + 载荷，
//! Xray 的 shadowsocks 入站解出地址并经 freedom 出站连到本仓 spawn 的 echo
//! 服务，回程由 `TcpReader` 读取，逐字节核对等于 echo 内容。

use std::net::Ipv4Addr;

use lengsuo_shadowsocks::{TargetAddr, MAX_SEGMENT_PAYLOAD};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use super::{line, methods, rust_client_roundtrip, serve_echo, sizes, suite_of};
use super::{BIND, LOOPBACK, OVERALL, PASSWORD};
use crate::support::{free_port, launch, WAIT};

#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn rust_client_to_xray_server_tcp() {
    timeout(OVERALL, async {
        for name in methods() {
            let suite = suite_of(name);
            let echo = TcpListener::bind(BIND).await.expect("echo 应可监听");
            let echo_port = echo.local_addr().expect("echo 应有地址").port();
            let specs = sizes();
            let echo_task = tokio::spawn(serve_echo(echo, specs.len()));
            let port = free_port();
            let reference = launch(
                json!({
                    "log": {"loglevel": "warning"},
                    "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "shadowsocks",
                        "settings": {"method": name, "password": PASSWORD, "network": "tcp"}}],
                    "outbounds": [{"protocol": "freedom"}]
                }),
                port,
            )
            .await;
            let target = TargetAddr::V4(LOOPBACK, echo_port);
            for size in specs {
                let payload = line(size);
                let stream = timeout(WAIT, TcpStream::connect((Ipv4Addr::LOCALHOST, port)))
                    .await
                    .expect("连接参考服务超时")
                    .expect("应可连接参考服务");
                let (reply, chunk_lens) = timeout(
                    WAIT,
                    rust_client_roundtrip(stream, suite, &target, &payload),
                )
                .await
                .expect("请求与回程往返超时");
                assert_eq!(reply.len(), size, "{name} / {size} 字节回程长度不符");
                assert_eq!(
                    reply, payload,
                    "{name} / {size} 字节回程内容不等于 echo 内容"
                );
                assert!(
                    chunk_lens
                        .iter()
                        .all(|&len| len > 0 && len <= MAX_SEGMENT_PAYLOAD),
                    "{name} / {size} 回程 chunk 规格不符：{chunk_lens:?}"
                );
                if size > MAX_SEGMENT_PAYLOAD {
                    assert!(
                        chunk_lens.len() >= 2,
                        "{name} / {size} 超上限载荷应由参考实现分块，实际 {chunk_lens:?}"
                    );
                }
            }
            drop(reference);
            echo_task.await.expect("echo 服务任务");
        }
    })
    .await
    .expect("Rust 客户端 → Xray 服务端 TCP 互通超时")
}
