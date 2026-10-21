//! anytls 出口拆分为独立模块后的 **node 级回归**（纯重构，行为必须不变）。
//!
//! 拆分前 anytls 的握手逻辑内联在 `outbound.rs`；拆分后搬到
//! `outbound_anytls.rs`。本文件用**回环 anytls 服务端**证明三条判据未变：
//!
//! 1. **认证成功路径**：服务端完成认证后下发 ServerSettings ⇒ node 侧
//!    `dial_anytls` 返回 `Ok`（收到 ServerSettings 即认证完成的正向证据，
//!    对齐 anytls-go `session.go` 客户端分支；该判据在拆分前的
//!    `outbound.rs` 模块注释里已写明，本卡只搬移、未改判据）。
//! 2. **认证被拒路径**：服务端回 Alert 或直接断连 ⇒ node 侧必须判为**拒绝**
//!    （`DialError::Rejected` / 协议错误），**不得**静默成功。
//! 3. **padding 常量不变**：`ANYTLS_DEFAULT_SCHEME_MD5` / `ANYTLS_AUTH_PADDING`
//!    与 `lengsuo-anytls/tests/interop_client/session.rs` 同源同值。
//!
//! 夹具写法照抄 `crates/lengsuo-node/tests/dryrun_loopback.rs`：rcgen 运行时
//! 生成自签证书 + `lengsuo-tls` 服务端，证书链与名称校验全程开启。全部用例
//! 带总超时；只用回环地址、临时端口与假凭据；日志不输出任何凭据。

use std::time::Duration;

use lengsuo_anytls::auth::Credential as AnyTlsCredential;
use lengsuo_anytls::frame::{Command as AnyTlsCommand, Frame};
use lengsuo_node::config::NodeConfig;
use lengsuo_node::outbound::{dial_anytls, DialError};
use lengsuo_node::outbound_anytls::{
    AnyTlsError, ANYTLS_AUTH_PADDING, ANYTLS_CLIENT_IDENT, ANYTLS_DEFAULT_SCHEME_MD5,
    ANYTLS_MAX_STREAMS,
};
use lengsuo_tls::{PrivatePkcs8KeyDer, TlsServer};
use serde_json::json;
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener;
use tokio::time::timeout;

/// 单步等待（对齐 `dryrun_loopback.rs` 量级）。
const WAIT: Duration = Duration::from_secs(5);
/// 单用例总超时。
const TOTAL: Duration = Duration::from_secs(30);
/// 假凭据（回环夹具专用，非任何真实口令）。
const PASSWORD: &str = "node-anytls-outbound-fake-password";

/// 服务端在认证之后的动作。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServerBehavior {
    /// 认证通过后下发 ServerSettings(v=2)（参考 anytls-go 服务端分支）。
    ServerSettings,
    /// 认证通过后回 Alert 帧（参考里服务端拒绝的显式表达之一）。
    Alert,
    /// 认证通过后直接断连（不写任何帧）。
    Disconnect,
}

/// 最小 anytls 服务端：TLS → verify（32 字节摘要 + padding）→ 按 `behavior` 收尾。
///
/// 认证失败按参考语义断连（不回任何帧）；成功后按 `behavior` 走三种分支之一。
/// 返回（端口，CA PEM）。
async fn anytls_server(password: &'static str, behavior: ServerBehavior) -> (u16, String) {
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
                match behavior {
                    ServerBehavior::ServerSettings => {
                        let _ = Frame {
                            command: AnyTlsCommand::ServerSettings,
                            stream_id: 0,
                            data: b"v=2".to_vec(),
                        }
                        .write(&mut tls, WAIT)
                        .await;
                        // 保持连接直到对端关闭，避免客户端读到 EOF 造成歧义。
                        let mut scratch = [0u8; 1024];
                        let _ = tls.read(&mut scratch).await;
                    }
                    ServerBehavior::Alert => {
                        let _ = Frame {
                            command: AnyTlsCommand::Alert,
                            stream_id: 0,
                            data: b"auth failed".to_vec(),
                        }
                        .write(&mut tls, WAIT)
                        .await;
                        let mut scratch = [0u8; 1024];
                        let _ = tls.read(&mut scratch).await;
                    }
                    ServerBehavior::Disconnect => {
                        // 直接断连：关闭 socket 即可。
                    }
                }
            });
        }
    });
    (port, cert.cert.pem())
}

/// 回环 anytls 节点配置。
fn node(port: u16, ca_pem: &str, password: &str) -> NodeConfig {
    let value = json!({
        "name": "anytls-outbound-loopback",
        "protocol": "anytls",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": { "server_name": "localhost", "ca_pem": ca_pem },
        "auth": { "password": password }
    });
    let nodes: Vec<NodeConfig> = serde_json::from_value(json!([value])).expect("节点配置");
    nodes.into_iter().next().expect("恰好一个节点")
}

/// 回归 1：认证成功 ⇒ 收到 ServerSettings 即返回 `Ok`（认证完成的正向证据）。
///
/// 该判据是拆分前后**逐字相同**的语义（见 `outbound_anytls` 模块注释）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anytls_dial_succeeds_on_server_settings() {
    timeout(TOTAL, async {
        let (port, ca_pem) = anytls_server(PASSWORD, ServerBehavior::ServerSettings).await;
        let good = node(port, &ca_pem, PASSWORD);

        let outbound = dial_anytls(&good, WAIT)
            .await
            .expect("收到 ServerSettings 即认证完成，应返回 Ok");
        // 会话状态机必须已采纳服务端设置（v=2 协商生效）。
        assert_eq!(outbound.state.peer_version(), 2, "应协商出 v2");
        assert!(
            outbound.state.settings_sent(),
            "客户端 Settings 应已标记写出"
        );
        assert!(!outbound.state.is_poisoned(), "会话不应被毒化");
    })
    .await
    .expect("总超时");
}

/// 回归 2a：服务端回 Alert ⇒ node 侧判为**拒绝**（不是静默成功）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anytls_dial_rejects_on_server_alert() {
    timeout(TOTAL, async {
        let (port, ca_pem) = anytls_server(PASSWORD, ServerBehavior::Alert).await;
        let good = node(port, &ca_pem, PASSWORD);

        let err = dial_anytls(&good, WAIT)
            .await
            .err()
            .expect("服务端 Alert 必须判为拒绝");
        assert!(
            matches!(err, DialError::Rejected(ref msg) if msg.contains("Alert")),
            "应为 Rejected(服务端 Alert)，实际：{err}"
        );
    })
    .await
    .expect("总超时");
}

/// 回归 2b：服务端直接断连 ⇒ node 侧判为**失败**（fail-closed，不得静默成功）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anytls_dial_fails_on_disconnect() {
    timeout(TOTAL, async {
        let (port, ca_pem) = anytls_server(PASSWORD, ServerBehavior::Disconnect).await;
        let good = node(port, &ca_pem, PASSWORD);

        let err = dial_anytls(&good, WAIT)
            .await
            .err()
            .expect("对端断连必须判为失败");
        // 断连在帧层表现为 IO 错误（写端 RST 或读端 EOF），经 `DialError::AnyTls`
        // 承载；**不得**退化成超时（`DialError::Timeout`）——那会让失败原因失真。
        assert!(
            matches!(
                err,
                DialError::AnyTls(AnyTlsError::Protocol(lengsuo_anytls::Error::Io(_)))
            ),
            "应为 AnyTls 协议 IO 错误，实际：{err}"
        );
    })
    .await
    .expect("总超时");
}

/// 回归 2c：错密码 ⇒ 服务端断连 ⇒ node 侧判为**失败**，且失败原因不含口令。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anytls_dial_fails_on_wrong_password() {
    timeout(TOTAL, async {
        let (port, ca_pem) = anytls_server(PASSWORD, ServerBehavior::ServerSettings).await;
        let bad = node(port, &ca_pem, "definitely-wrong-password");

        let err = dial_anytls(&bad, WAIT).await.err().expect("错密码必须失败");
        assert!(
            matches!(
                err,
                DialError::AnyTls(AnyTlsError::Protocol(lengsuo_anytls::Error::Io(_)))
            ),
            "错密码应表现为对端断连（IO 错误），实际：{err}"
        );
        let reason = err.to_string();
        assert!(
            !reason.contains(PASSWORD) && !reason.contains("definitely-wrong"),
            "失败原因不得包含任何口令：{reason}"
        );
    })
    .await
    .expect("总超时");
}

/// 回归 1b：分发路径 `outbound::dial` → `Outbound::AnyTls` 仍然成立。
///
/// 拆分只搬走了 anytls 的实现，`outbound.rs` 的分发分支与 `Outbound` 枚举
/// 变体未改；本用例证明「分发 → 认证完成」在拆分后仍然闭环。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anytls_dispatch_yields_anytls_outbound() {
    timeout(TOTAL, async {
        let (port, ca_pem) = anytls_server(PASSWORD, ServerBehavior::ServerSettings).await;
        let good = node(port, &ca_pem, PASSWORD);

        let outbound = lengsuo_node::outbound::dial(&good, WAIT, WAIT)
            .await
            .expect("分发到 anytls 应成功");
        match outbound {
            lengsuo_node::outbound::Outbound::AnyTls(mut session) => {
                assert_eq!(session.state.peer_version(), 2, "应协商出 v2");
                // 干净收尾：TLS close_notify。
                use tokio::io::AsyncWriteExt as _;
                let _ = session.stream.shutdown().await;
            }
            _ => panic!("分发结果应为 Outbound::AnyTls"),
        }
    })
    .await
    .expect("总超时");
}

/// 回归 3：padding 常量不变。
///
/// `ANYTLS_DEFAULT_SCHEME_MD5` 与 `lengsuo-anytls/tests/interop_client/session.rs`
/// 的 `DEFAULT_SCHEME_MD5` 同源同值（亦即 `lengsuo_anytls::padding::DEFAULT_PADDING_MD5`）；
/// `ANYTLS_AUTH_PADDING` 与该文件的 `AUTH_PADDING` 同源同值（默认方案 `0=30-30`
/// 的 0 号记录恒 30 字节零值）。同时校验活跃流上限与客户端标识未变。
#[test]
fn anytls_padding_constants_match_interop_source() {
    assert_eq!(
        ANYTLS_DEFAULT_SCHEME_MD5, "75cff2ad89aadf5e257059ee571ebe11",
        "默认 padding 方案 md5 不得漂移"
    );
    assert_eq!(
        ANYTLS_DEFAULT_SCHEME_MD5,
        lengsuo_anytls::padding::DEFAULT_PADDING_MD5,
        "与 lengsuo_anytls::padding::DEFAULT_PADDING_MD5 必须同源同值"
    );
    assert_eq!(
        ANYTLS_AUTH_PADDING, [0u8; 30],
        "认证块 padding 必须是 30 字节零值（默认方案 0=30-30）"
    );
    assert_eq!(ANYTLS_AUTH_PADDING.len(), 30, "认证块 padding 长度不得漂移");
    assert_eq!(ANYTLS_MAX_STREAMS, 16, "单会话活跃流上限不得漂移");
    assert_eq!(ANYTLS_CLIENT_IDENT, "lengsuo-node", "客户端标识不得漂移");
}

/// 回归 4：错误文案逐字不变（拆分前 `DialError` 的两个 anytls 变体）。
///
/// 拆分前：
/// - `#[error("anytls 协议错误：{0}")] AnyTls(#[from] lengsuo_anytls::Error)`
/// - `#[error("anytls 客户端状态机拒绝：{0}")] AnyTlsState(String)`
///
/// 拆分后这两个变体随实现迁到 `outbound_anytls::AnyTlsError`，`DialError::AnyTls`
/// 改以 `#[error(transparent)]` 承载 ⇒ **对外 `Display` 必须逐字相同**。
/// 本用例把该不变量钉死（dry-run 的失败原因直接来自 `DialError` 的 `Display`）。
#[test]
fn anytls_error_text_unchanged_after_split() {
    let protocol = DialError::from(lengsuo_anytls::Error::Authentication);
    assert_eq!(
        protocol.to_string(),
        "anytls 协议错误：认证失败",
        "协议错误文案不得漂移"
    );

    let state = DialError::from(AnyTlsError::State("会话已终止".to_owned()));
    assert_eq!(
        state.to_string(),
        "anytls 客户端状态机拒绝：会话已终止",
        "状态机拒绝文案不得漂移"
    );
}
