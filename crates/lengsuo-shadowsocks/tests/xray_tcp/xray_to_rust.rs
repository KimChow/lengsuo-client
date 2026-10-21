//! 方向二：Xray 作客户端，本端作服务端。
//!
//! Xray 的 socks 入站接收本端 SOCKS5 请求，shadowsocks 出站连到本端监听器；
//! 本端用 `TcpReader`（服务端视角）解请求方向、中继到 echo 目标，再用
//! `TcpWriter` 写回程，核对端到端载荷。

use lengsuo_shadowsocks::{TargetAddr, MAX_SEGMENT_PAYLOAD};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

use super::{line, methods, rust_server, serve_echo, sizes, socks5_connect, suite_of};
use super::{BIND, LOOPBACK, OVERALL, PASSWORD};
use crate::support::{free_port, launch, WAIT};

#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn xray_client_to_rust_server_tcp() {
    timeout(OVERALL, async {
        for name in methods() {
            let suite = suite_of(name);
            let server = TcpListener::bind(BIND).await.expect("本端应可监听");
            let rust_port = server.local_addr().expect("本端应有地址").port();
            let echo = TcpListener::bind(BIND).await.expect("echo 应可监听");
            let echo_port = echo.local_addr().expect("echo 应有地址").port();
            let specs = sizes();
            let echo_task = tokio::spawn(serve_echo(echo, specs.len()));
            let served_task = tokio::spawn(rust_server(server, suite, specs.len()));
            let port = free_port();
            let reference = launch(
                json!({
                    "log": {"loglevel": "warning"},
                    "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                        "settings": {"auth": "noauth", "udp": false}}],
                    "outbounds": [{"protocol": "shadowsocks", "settings": {"servers": [{
                        "address": "127.0.0.1", "port": rust_port, "method": name, "password": PASSWORD}]}}]
                }),
                port,
            )
            .await;
            let target = TargetAddr::V4(LOOPBACK, echo_port);
            for size in specs {
                let payload = line(size);
                let mut stream = socks5_connect(port, &target).await;
                timeout(WAIT, stream.write_all(&payload))
                    .await
                    .expect("SOCKS 写载荷超时")
                    .expect("SOCKS 写载荷失败");
                let mut reply = vec![0u8; size];
                timeout(WAIT, stream.read_exact(&mut reply))
                    .await
                    .expect("SOCKS 读回包超时")
                    .expect("SOCKS 读回包失败");
                assert_eq!(reply, payload, "{name} / {size} 字节端到端载荷不符");
                drop(stream);
            }
            let served = served_task.await.expect("本端服务任务");
            assert_eq!(served.len(), specs.len(), "本端应处理每条互通连接");
            for (index, one) in served.iter().enumerate() {
                let size = specs[index];
                assert_eq!(one.target, target, "{name} / {size} 解出的目标地址不符");
                assert_eq!(one.request, line(size), "{name} / {size} 请求方向载荷不符");
                if size > MAX_SEGMENT_PAYLOAD {
                    assert!(
                        one.chunk_lens.len() >= 2,
                        "{name} / {size} 超上限载荷应由参考实现分块，实际 {:?}",
                        one.chunk_lens
                    );
                }
            }
            drop(reference);
            echo_task.await.expect("echo 服务任务");
        }
    })
    .await
    .expect("Xray 客户端 → Rust 服务端 TCP 互通超时")
}
