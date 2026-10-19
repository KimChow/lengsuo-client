//! 固定基线 Xray 服务端的**外层传输**真实互通（默认忽略，必须 `--ignored` 实跑）。
//!
//! 方向：本仓 Rust 客户端（TLS → WS/HTTPUpgrade → trojan）→ 官方 Xray 服务端
//! （trojan 入站套 `streamSettings.network = ws | httpupgrade`），目标由 Xray
//! `freedom` 出站抵达独立回环回显后端。**这不是自家 roundtrip**：对端是固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0` 的官方二进制。
//!
//! 断言口径：回程与请求**逐字节一致**，且回显后端 accept 计数 `== 1`
//! （证明 trojan 头部与载荷确实穿过外层传输抵达业务目标）。
//! 另补两条失败路径：错误路径（Xray 侧应 404/拒绝升级）与错误密码（穿过传输
//! 后仍被认证拒绝，accept 计数不增长）。

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_tls::TlsClient;
use lengsuo_trojan::stream::send_request;
use lengsuo_trojan::transport::{httpupgrade, ws};
use lengsuo_trojan::{Command, Credential, Request, TargetAddr};
use serde_json::{json, Value};
use support::{free_port, launch, WAIT};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

const PASSWORD: &str = "interop-trojan-transport-password";
const BAD_PASSWORD: &str = "interop-trojan-transport-wrong";
const PAYLOAD: &[u8] = b"trojan-over-outer-transport-payload";
const PATH: &str = "/lengsuo-trojan";
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

/// 生成测试证书（叶子 `localhost`，运行时自签），返回 DER 与配置片段。
fn identity() -> (rcgen::CertifiedKey, Value) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let settings = json!({"security":"tls","tlsSettings":{"certificates":[{
        "certificate":cert.cert.pem().lines().collect::<Vec<_>>(),
        "key":cert.key_pair.serialize_pem().lines().collect::<Vec<_>>() }]}});
    (cert, settings)
}

/// Xray 服务端配置：trojan 入站套 `network`（ws/httpupgrade），freedom 出站。
fn server_config(port: u16, tls: Value, network: &str) -> Value {
    let mut stream = tls;
    stream["network"] = json!(network);
    stream["security"] = json!("tls");
    let mut ws_settings = json!({"path": PATH});
    if network == "ws" {
        ws_settings["host"] = json!("localhost");
    }
    stream["wsSettings"] = ws_settings.clone();
    stream["httpupgradeSettings"] = ws_settings;
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"trojan",
            "settings":{"clients":[{"password":PASSWORD}]},
            "streamSettings":stream}],
        "outbounds":[{"protocol":"freedom"}]})
}

/// 本仓客户端一次 trojan/TCP 回环：TLS → 外层传输升级 → 请求头 → 载荷 → 回程。
async fn client_roundtrip<S>(conn: &mut S, echo_port: u16)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = Request {
        command: Command::Tcp,
        target: TargetAddr::V4([127, 0, 0, 1], echo_port),
    };
    send_request(conn, &request, &Credential::new(PASSWORD), WAIT)
        .await
        .expect("请求头写出失败");
    conn.write_all(PAYLOAD).await.unwrap();
    conn.flush().await.unwrap();
    // trojan 无成功响应头；写半关闭在 WS 下会发 Close 帧——服务端已收到载荷，
    // 这里直接读回程（参考 trojan 读到就转发，不等我方 FIN）。
    let mut reply = vec![0u8; PAYLOAD.len()];
    timeout(WAIT, conn.read_exact(&mut reply))
        .await
        .expect("回程超时")
        .expect("回程读失败");
    assert_eq!(reply, PAYLOAD, "回程必须与请求逐字节一致");
}

#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn rust_trojan_client_over_ws_to_xray_server() {
    timeout(TOTAL, async {
        let (cert, tls) = identity();
        let (echo_port, accepted, echo_task) = spawn_echo(PAYLOAD.len()).await;
        let port = free_port();
        let reference = launch(server_config(port, tls, "ws"), port).await;

        let client = TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap();
        let tls_stream = client.connect(([127, 0, 0, 1], port).into()).await.unwrap();
        let ws_client = ws::Client::new(PATH, "localhost", "localhost");
        let mut conn = ws_client
            .upgrade(tls_stream, WAIT)
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
async fn rust_trojan_client_over_httpupgrade_to_xray_server() {
    timeout(TOTAL, async {
        let (cert, tls) = identity();
        let (echo_port, accepted, echo_task) = spawn_echo(PAYLOAD.len()).await;
        let port = free_port();
        let reference = launch(server_config(port, tls, "httpupgrade"), port).await;

        let client = TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap();
        let tls_stream = client.connect(([127, 0, 0, 1], port).into()).await.unwrap();
        let up_client = httpupgrade::Client::new(PATH, "localhost", "localhost");
        let mut conn = up_client
            .upgrade(tls_stream, WAIT)
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

/// 错误路径：Xray 的 ws 入站只接受配置的 path，错误 path 应被拒（非 101）。
/// 证明“升级成功”不是无条件成立——观测面有效。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn ws_wrong_path_is_rejected_by_xray() {
    timeout(TOTAL, async {
        let (cert, tls) = identity();
        let (_echo_port, accepted, echo_task) = spawn_echo(PAYLOAD.len()).await;
        let port = free_port();
        let reference = launch(server_config(port, tls, "ws"), port).await;

        let client = TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap();
        let tls_stream = client.connect(([127, 0, 0, 1], port).into()).await.unwrap();
        let ws_client = ws::Client::new("/wrong-path", "localhost", "localhost");
        match ws_client.upgrade(tls_stream, WAIT).await {
            Err(lengsuo_trojan::transport::Error::UpgradeRejected(_)) => {}
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

/// 错误密码：穿过 WS 外层传输后仍必须在 trojan 认证层被拒，业务目标 accept 不增长。
/// 先跑正确密码对照组证明观测面有效。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn ws_wrong_password_never_reaches_target() {
    timeout(TOTAL, async {
        let (cert, tls) = identity();
        let (echo_port, accepted, echo_task) = spawn_echo(PAYLOAD.len()).await;
        let port = free_port();
        let reference = launch(server_config(port, tls, "ws"), port).await;

        // 对照组：正确密码走通。
        let client = TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap();
        let tls_stream = client.connect(([127, 0, 0, 1], port).into()).await.unwrap();
        let mut good = ws::Client::new(PATH, "localhost", "localhost")
            .upgrade(tls_stream, WAIT)
            .await
            .unwrap();
        client_roundtrip(&mut good, echo_port).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "对照组必须抵达业务目标");

        // 错误密码：写头 + 载荷，读侧应被主动断开（或在观察上限内无回程）。
        let before = accepted.load(Ordering::SeqCst);
        let client = TlsClient::new("localhost", [cert.cert.der().clone()], WAIT).unwrap();
        let tls_stream = client.connect(([127, 0, 0, 1], port).into()).await.unwrap();
        let mut bad = ws::Client::new(PATH, "localhost", "localhost")
            .upgrade(tls_stream, WAIT)
            .await
            .unwrap();
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], echo_port),
        };
        let _ = send_request(&mut bad, &request, &Credential::new(BAD_PASSWORD), WAIT).await;
        let _ = bad.write_all(PAYLOAD).await;
        let _ = bad.flush().await;
        // 读到结束（Ok(0)）或错误；读到数据即失败（不该有回程）。
        let mut buf = [0u8; 64];
        match timeout(Duration::from_secs(8), bad.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("错误密码不得有回程，读到 {n} 字节"),
            Err(_) => {} // Xray 静默保持连接也可能；下面用计数判定。
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            before,
            "错误密码不得建立通往业务目标的连接"
        );
        drop(reference);
        echo_task.abort();
        let _ = timeout(WAIT, echo_task).await;
    })
    .await
    .unwrap();
}
