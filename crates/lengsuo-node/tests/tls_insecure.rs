//! `tls.insecure` 回归：显式跳过证书/主机名校验，但 TLS 握手仍完整执行。
//!
//! 覆盖四条判据（见卡 `node-tls-insecure`）：
//! 1. `insecure = true` 的最小配置 ⇒ [`tls_client`] 返回 `Ok`（改动前这里是
//!    「尚未实现」错误）。
//! 2. [`NoCertificateVerification`] 单测：伪造证书调 `verify_server_cert` 返回
//!    `Ok` 且 `supported_verify_schemes` 非空。
//! 3. `insecure = true` 连一个「accept 后回垃圾字节」的监听器 ⇒ **握手仍失败**
//!    （`Err`），⛔ 不得判成功、更不得回落明文。
//! 4. 回归：`insecure = false` 且 `ca_pem` 为空 ⇒ 仍 `Err`。

use std::time::Duration;

use lengsuo_node::config::NodeConfig;
use lengsuo_node::outbound::{tls_client, NoCertificateVerification};
use lengsuo_tls::{PrivatePkcs8KeyDer, TlsServer};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::json;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);
const TOTAL: Duration = Duration::from_secs(30);

/// 由 JSON 构造最小节点配置（端点固定回环；`tls.ca_pem` 缺省）。
fn node(insecure: bool) -> NodeConfig {
    let value = json!([{
        "name": "tls-insecure-test",
        "protocol": "trojan",
        "endpoint": { "host": "127.0.0.1", "port": 8443 },
        "tls": { "insecure": insecure },
        "auth": { "password": "fake-password" }
    }]);
    let nodes: Vec<NodeConfig> = serde_json::from_value(value).expect("配置应可反序列化");
    nodes.into_iter().next().expect("恰好一个节点")
}

/// 1. `insecure = true` ⇒ 构造客户端成功（改动前是「尚未实现」错误）。
#[test]
fn insecure_config_builds_client() {
    let _client = tls_client(&node(true), WAIT).expect("insecure=true 应可构造 TLS 客户端");
    // 能拿到客户端即说明配置路径成立；连接行为由握手用例覆盖。
}

/// 2. 验证器单测：伪造证书也判 `Ok`，且支持的签名方案非空。
#[test]
fn no_certificate_verification_accepts_anything() {
    let verifier = NoCertificateVerification;
    let forged = CertificateDer::from(b"not-a-cert".to_vec());
    let name = ServerName::try_from("localhost").expect("测试名称合法");
    let now = UnixTime::since_unix_epoch(Duration::from_secs(0));

    // 调用成功本身即断言：insecure 验证器必须接受伪造证书。
    let _verified = verifier
        .verify_server_cert(&forged, &[], &name, &[], now)
        .expect("insecure 验证器必须接受伪造证书");
    assert!(
        !verifier.supported_verify_schemes().is_empty(),
        "支持的签名方案不得为空"
    );
}

/// 3. 握手仍然发生：对端 accept 后回垃圾字节 ⇒ 必须 `Err`（不是成功、不是明文）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn insecure_still_performs_tls_handshake() {
    timeout(TOTAL, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // 明确不是 TLS：先回一段纯文本垃圾。
            let _ = socket.write_all(b"this-is-not-a-tls-server\r\n").await;
            let _ = socket.shutdown().await;
        });

        let client = tls_client(&node(true), WAIT).expect("insecure=true 应可构造客户端");
        let result = client.connect(addr).await;
        assert!(
            result.is_err(),
            "对端非 TLS 时握手必须失败，绝不能判成功或回落明文"
        );
        let _ = timeout(Duration::from_secs(5), server).await;
    })
    .await
    .expect("用例总超时");
}

/// 3b. 正向证据：证书 SAN 与请求 SNI **不匹配**时，`insecure = true` 仍能
/// 完成完整 TLS 握手（校验开启时这一步必然失败）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn insecure_handshake_ignores_name_mismatch() {
    timeout(TOTAL, async {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server = TlsServer::new(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            WAIT,
        )
        .expect("TLS 服务端配置");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = server.accept(socket).await;
        });

        // 证书 SAN 是 localhost，请求名却是 127.0.0.1：校验开启时必然失败。
        let mut config = node(true);
        config.tls.as_mut().expect("节点带 tls 段").server_name = Some("127.0.0.1".to_owned());
        let client = tls_client(&config, WAIT).expect("insecure=true 应可构造客户端");
        client
            .connect(addr)
            .await
            .expect("insecure 应跳过名称校验并完成握手");
        let _ = timeout(Duration::from_secs(5), server_task).await;
    })
    .await
    .expect("用例总超时");
}

/// 4. 回归：`insecure = false` 且 `ca_pem` 为空 ⇒ 仍 `Err`（零行为变化）。
#[test]
fn verified_without_trust_anchor_still_fails() {
    let result = tls_client(&node(false), WAIT);
    assert!(result.is_err(), "缺 ca_pem 必须拒绝");
    let error = result.err().expect("已断言为 Err");
    assert!(
        error.to_string().contains("ca_pem"),
        "报错应点名 ca_pem：{error}"
    );
}
