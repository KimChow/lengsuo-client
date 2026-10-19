//! 回环端到端 dry-run：本仓协议服务端 ↔ lengsuo-node 出站分发。
//!
//! 夹具写法照抄 `lengsuo-trojan/tests/xray_tls.rs`（rcgen 运行时生成自签证书 +
//! `lengsuo-tls` 服务端，证书链与名称校验全程开启，不跳过验证）；trojan 对端
//! 直接复用 `lengsuo-trojan::server::Server` 产品入口，anytls 对端用
//! `auth::Credential::verify` + `frame` 原语手拼最小服务端（认证 → ServerSettings）。
//! 全部用例带总超时；错密码判据对齐参考行为：服务端拒绝的唯一表达是关闭连接。

use std::time::Duration;

use lengsuo_node::config::NodeConfig;
use lengsuo_node::dryrun::dry_run;
use lengsuo_tls::PrivatePkcs8KeyDer;
use serde_json::json;
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener;
use tokio::time::timeout;

use lengsuo_anytls::auth::Credential as AnyTlsCredential;
use lengsuo_anytls::frame::{Command as AnyTlsCommand, Frame};
use lengsuo_tls::TlsServer;
use lengsuo_trojan::server::{
    Inbound as TrojanInbound, Server as TrojanServer, Timeouts, Validator,
};

/// 单步等待（对齐 trojan 互通夹具量级）。
const WAIT: Duration = Duration::from_secs(5);
/// trojan 认证拒绝观察窗。
const OBSERVE: Duration = Duration::from_millis(300);
/// 单用例总超时。
const TOTAL: Duration = Duration::from_secs(30);
const PASSWORD: &str = "node-loopback-password";

/// 挂住的 TCP 目标：接受连接后静默保持——trojan dry-run 的 probe_target，
/// 让“认证成功”路径的服务端中继得以建立，观察窗内连接安静即判 ok。
async fn parked_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut scratch = [0u8; 1024];
                let _ = socket.read(&mut scratch).await;
            });
        }
    });
    port
}

/// 本仓 trojan 产品服务端（TLS + 多用户校验 + CONNECT 中继）。
/// 返回（端口，CA PEM）。认证失败按参考语义直接关闭连接。
async fn trojan_server(password: &'static str) -> (u16, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut validator = Validator::new();
    validator
        .add("user@example.com", password)
        .expect("注册用户");
    let inbound = TrojanInbound::new(
        vec![cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        WAIT,
    )
    .expect("TLS 接入配置");
    let server = TrojanServer::with_tls(
        validator,
        Timeouts::new(WAIT, WAIT).expect("超时配置"),
        inbound,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = server.accept_loop(listener).await;
    });
    (port, cert.cert.pem())
}

/// 最小 anytls 服务端：TLS → verify（32 字节摘要 + padding）→ ServerSettings(v=2)。
/// 认证失败按参考语义断连；成功后保持连接直到对端关闭。
async fn anytls_server(password: &'static str) -> (u16, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server = TlsServer::new(
        vec![cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        WAIT,
    )
    .expect("TLS 服务端配置");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let server = server.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = server.accept(socket).await else {
                    return;
                };
                let credential = AnyTlsCredential::new(password.as_bytes());
                if credential.verify(&mut tls, u16::MAX, WAIT).await.is_err() {
                    return; // 认证失败：关闭连接，不回任何帧。
                }
                let _ = Frame {
                    command: AnyTlsCommand::ServerSettings,
                    stream_id: 0,
                    data: b"v=2".to_vec(),
                }
                .write(&mut tls, WAIT)
                .await;
                let mut scratch = [0u8; 1024];
                let _ = tls.read(&mut scratch).await;
            });
        }
    });
    (port, cert.cert.pem())
}

fn node(protocol: &str, port: u16, ca_pem: &str, password: &str, probe: Option<u16>) -> NodeConfig {
    let mut value = json!({
        "name": format!("{protocol}-loopback"),
        "protocol": protocol,
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": { "server_name": "localhost", "ca_pem": ca_pem },
        "auth": { "password": password }
    });
    if let Some(probe_port) = probe {
        value["probe_target"] = json!({ "host": "127.0.0.1", "port": probe_port });
    }
    let nodes: Vec<NodeConfig> = serde_json::from_value(json!([value])).expect("节点配置");
    nodes.into_iter().next().expect("恰好一个节点")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_dryrun_ok_and_wrong_password_rejected() {
    timeout(TOTAL, async {
        let probe_port = parked_target().await;
        let (port, ca_pem) = trojan_server(PASSWORD).await;

        // 正确密码：TLS + 请求头 + 服务端中继建立，观察窗内连接安静 → ok。
        let good = node("trojan", port, &ca_pem, PASSWORD, Some(probe_port));
        let reports = dry_run(&[good], WAIT, OBSERVE).await;
        assert!(reports[0].ok(), "正确密码应通过：{:?}", reports[0].reason);

        // 错密码：参考服务端认证失败即关闭连接，观察窗内 EOF → fail。
        let bad = node(
            "trojan",
            port,
            &ca_pem,
            "definitely-wrong-password",
            Some(probe_port),
        );
        let reports = dry_run(&[bad], WAIT, OBSERVE).await;
        let reason = reports[0].reason.as_deref().expect("错密码必须失败");
        assert!(
            !reason.contains(PASSWORD) && !reason.contains("definitely-wrong"),
            "失败原因不得包含任何密码：{reason}"
        );
    })
    .await
    .expect("总超时");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anytls_dryrun_ok_and_wrong_password_rejected() {
    timeout(TOTAL, async {
        let (port, ca_pem) = anytls_server(PASSWORD).await;

        // 正确密码：认证块 → 客户端 Settings → 收到 ServerSettings(v=2) → ok。
        let good = node("anytls", port, &ca_pem, PASSWORD, None);
        let reports = dry_run(&[good], WAIT, OBSERVE).await;
        assert!(reports[0].ok(), "正确密码应通过：{:?}", reports[0].reason);

        // 错密码：服务端 verify 失败断连，等 ServerSettings 时读到 Io → fail。
        let bad = node("anytls", port, &ca_pem, "definitely-wrong-password", None);
        let reports = dry_run(&[bad], WAIT, OBSERVE).await;
        let reason = reports[0].reason.as_deref().expect("错密码必须失败");
        assert!(
            !reason.contains(PASSWORD) && !reason.contains("definitely-wrong"),
            "失败原因不得包含任何密码：{reason}"
        );
    })
    .await
    .expect("总超时");
}

/// 拒连场景：端口不可达时 dry-run 报失败原因（而不是挂死），全部受截止约束。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreachable_endpoint_fails_fast() {
    timeout(TOTAL, async {
        let dead = node(
            "trojan",
            1,
            "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n",
            PASSWORD,
            None,
        );
        let reports = dry_run(&[dead], WAIT, OBSERVE).await;
        assert!(!reports[0].ok(), "不可达/坏证书必须失败");
    })
    .await
    .expect("总超时");
}
