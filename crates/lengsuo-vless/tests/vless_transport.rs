//! VLESS 外层传输（WS / HTTPUpgrade）真实互通与本地双工。
//!
//! 参考对端用例默认 `#[ignore]`，必须显式 `--ignored` 实跑：
//! `LENGSUO_XRAY=/path/to/xray cargo test -p lengsuo-vless --test vless_transport -- --ignored`
//!
//! 方向与断言口径照搬 `crates/lengsuo-trojan/tests/xray_transport.rs`：
//! 固定基线 Xray（`d2758a0` / v26.3.27）作服务端或客户端，回程与请求逐字节一致，
//! 回显后端 accept 计数证明 VLESS 头部与载荷确实穿过外层传输抵达业务目标。
//! 非 ignore 用例只用本仓客户端 ↔ 本仓服务端，验证帧/升级语义，**不冒充**参考互通。

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_vless::header::{Command, Request};
use lengsuo_vless::stream::{receive_request, receive_response, send_request, send_response};
use lengsuo_vless::transport::{httpupgrade, server, ws, Error as TransportError};
use serde_json::{json, Value};
use ss_core::target::TargetAddr;
use support::{free_port, launch, ID, KEY, WAIT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const PAYLOAD: &[u8] = b"vless-over-outer-transport-payload";
const PATH: &str = "/lengsuo-vless";
const TOTAL: Duration = Duration::from_secs(90);

/// 回显后端：读满 `len` 字节后原样回写并关写端；返回端口、accept 计数与句柄。
async fn spawn_echo(len: usize) -> (u16, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; len];
                if socket.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let _ = socket.write_all(&buf).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, accepted, task)
}

/// Xray 服务端配置：VLESS 入站套 `network`（ws/httpupgrade），freedom 出站。
fn server_config(port: u16, network: &str) -> Value {
    let mut stream = json!({"network": network});
    let mut settings = json!({"path": PATH});
    if network == "ws" {
        settings["host"] = json!("localhost");
    }
    stream["wsSettings"] = settings.clone();
    stream["httpupgradeSettings"] = settings;
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vless",
            "settings":{"clients":[{"id":ID}],"decryption":"none"},
            "streamSettings":stream}],
        "outbounds":[{"protocol":"freedom"}]})
}

/// 本仓客户端一次 VLESS/TCP 回环：升级 → 请求头 → 载荷 → 响应头 → 回程。
async fn client_roundtrip<S>(conn: &mut S, echo_port: u16)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = Request {
        command: Command::Tcp,
        target: TargetAddr::V4([127, 0, 0, 1], echo_port),
    };
    send_request(conn, &request, &KEY, WAIT)
        .await
        .expect("请求头写出失败");
    conn.write_all(PAYLOAD).await.unwrap();
    conn.flush().await.unwrap();
    receive_response(conn, WAIT).await.expect("响应头读取失败");
    let mut reply = vec![0u8; PAYLOAD.len()];
    timeout(WAIT, conn.read_exact(&mut reply))
        .await
        .expect("回程超时")
        .expect("回程读失败");
    assert_eq!(reply, PAYLOAD, "回程必须与请求逐字节一致");
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_vless_client_over_ws_to_xray_server() {
    timeout(TOTAL, async {
        let (echo_port, accepted, echo_task) = spawn_echo(PAYLOAD.len()).await;
        let port = free_port();
        let reference = launch(server_config(port, "ws"), port).await;

        let stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut conn = ws::Client::new(PATH, "localhost", "localhost")
            .upgrade(stream, WAIT)
            .await
            .expect("WS 升级应成功");
        client_roundtrip(&mut conn, echo_port).await;

        assert_eq!(accepted.load(Ordering::SeqCst), 1, "必须抵达回显后端一次");
        drop(reference);
        echo_task.abort();
        let _ = timeout(WAIT, echo_task).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_vless_client_over_httpupgrade_to_xray_server() {
    timeout(TOTAL, async {
        let (echo_port, accepted, echo_task) = spawn_echo(PAYLOAD.len()).await;
        let port = free_port();
        let reference = launch(server_config(port, "httpupgrade"), port).await;

        let stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut conn = httpupgrade::Client::new(PATH, "localhost", "localhost")
            .upgrade(stream, WAIT)
            .await
            .expect("HTTPUpgrade 应成功");
        client_roundtrip(&mut conn, echo_port).await;

        assert_eq!(accepted.load(Ordering::SeqCst), 1, "必须抵达回显后端一次");
        drop(reference);
        echo_task.abort();
        let _ = timeout(WAIT, echo_task).await;
    })
    .await
    .unwrap();
}

/// 参考 Xray 作客户端（vless outbound 套 `network: ws`）连本仓 VLESS 服务端。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_client_to_rust_vless_server_over_ws() {
    timeout(TOTAL, async {
        let (echo_port, accepted, echo_task) = spawn_echo(PAYLOAD.len()).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rust_port = listener.local_addr().unwrap().port();
        let port = free_port();
        let reference = launch(
            json!({
                "log":{"loglevel":"warning"},
                "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"dokodemo-door",
                    "settings":{"address":"127.0.0.1","port":echo_port,"network":"tcp"}}],
                "outbounds":[{"protocol":"vless","settings":{"vnext":[{
                    "address":"127.0.0.1","port":rust_port,
                    "users":[{"id":ID,"encryption":"none"}]}]},
                    "streamSettings":{"network":"ws",
                        "wsSettings":{"path":PATH,"headers":{"Host":"localhost"}}}}]
            }),
            port,
        )
        .await;

        let config = server::Config::new(PATH, "");
        let server = tokio::spawn(async move {
            // 启动探测可能让参考客户端提前建立一条无载荷连接。
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let Ok(mut conn) = server::accept_ws(stream, &config, WAIT).await else {
                    continue;
                };
                let Ok(request) = receive_request(&mut conn, &KEY, WAIT).await else {
                    continue;
                };
                assert_eq!(
                    request.target,
                    TargetAddr::V4([127, 0, 0, 1], echo_port),
                    "目标地址必须由 VLESS 头部解出"
                );
                // 按 VLESS 头里的目标连回显后端，证明目标地址确实被采用。
                let mut target = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, echo_port))
                    .await
                    .unwrap();
                send_response(&mut conn, WAIT).await.unwrap();
                let mut buf = vec![0u8; PAYLOAD.len()];
                if conn.read_exact(&mut buf).await.is_err() {
                    continue;
                }
                target.write_all(&buf).await.unwrap();
                let mut reply = vec![0u8; PAYLOAD.len()];
                target.read_exact(&mut reply).await.unwrap();
                conn.write_all(&reply).await.unwrap();
                conn.flush().await.unwrap();
                return;
            }
        });

        // 驱动参考端：经 dokodemo 入站 → vless outbound（ws）→ 本仓服务端 → 回显。
        let mut app = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        app.write_all(PAYLOAD).await.unwrap();
        app.flush().await.unwrap();
        let mut reply = vec![0u8; PAYLOAD.len()];
        timeout(WAIT, app.read_exact(&mut reply))
            .await
            .expect("参考客户端回程超时")
            .expect("参考客户端回程读失败");
        assert_eq!(reply, PAYLOAD, "回程必须与请求逐字节一致");
        drop(app);

        timeout(WAIT, server)
            .await
            .expect("Rust 服务端超时")
            .unwrap();
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "必须抵达回显后端一次");
        drop(reference);
        echo_task.abort();
        let _ = timeout(WAIT, echo_task).await;
    })
    .await
    .unwrap();
}

/// 错误路径：Xray 的 ws 入站只接受配置的 path，错误 path 应被拒（非 101）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn ws_wrong_path_is_rejected_by_xray() {
    timeout(TOTAL, async {
        let (_echo_port, accepted, echo_task) = spawn_echo(PAYLOAD.len()).await;
        let port = free_port();
        let reference = launch(server_config(port, "ws"), port).await;

        let stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        match ws::Client::new("/wrong-path", "localhost", "localhost")
            .upgrade(stream, WAIT)
            .await
        {
            Err(TransportError::UpgradeRejected(_)) => {}
            other => panic!("错误 path 必须被拒：{:?}", other.err()),
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "错误 path 不得抵达业务目标"
        );
        drop(reference);
        echo_task.abort();
        let _ = timeout(WAIT, echo_task).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn local_ws_client_server_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn = server::accept_ws(stream, &server::Config::new(PATH, ""), WAIT)
            .await
            .expect("服务端应接受 WS 升级");
        let request = receive_request(&mut conn, &KEY, WAIT).await.unwrap();
        assert_eq!(request.target, TargetAddr::V4([127, 0, 0, 1], 7));
        send_response(&mut conn, WAIT).await.unwrap();
        let mut buf = vec![0u8; PAYLOAD.len()];
        conn.read_exact(&mut buf).await.unwrap();
        conn.write_all(&buf).await.unwrap();
        conn.flush().await.unwrap();
    });
    let stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let mut conn = ws::Client::new(PATH, "localhost", "localhost")
        .upgrade(stream, WAIT)
        .await
        .unwrap();
    client_roundtrip(&mut conn, 7).await;
    server.await.unwrap();
}

#[tokio::test]
async fn local_httpupgrade_client_server_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn = server::accept_httpupgrade(stream, &server::Config::new(PATH, ""), WAIT)
            .await
            .expect("服务端应接受 HTTPUpgrade");
        let request = receive_request(&mut conn, &KEY, WAIT).await.unwrap();
        assert_eq!(request.target, TargetAddr::V4([127, 0, 0, 1], 7));
        send_response(&mut conn, WAIT).await.unwrap();
        let mut buf = vec![0u8; PAYLOAD.len()];
        conn.read_exact(&mut buf).await.unwrap();
        conn.write_all(&buf).await.unwrap();
        conn.flush().await.unwrap();
    });
    let stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let mut conn = httpupgrade::Client::new(PATH, "localhost", "localhost")
        .upgrade(stream, WAIT)
        .await
        .unwrap();
    client_roundtrip(&mut conn, 7).await;
    server.await.unwrap();
}
