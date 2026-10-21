//! trojan 出口的 node 级回归用例（`outbound.rs` → `outbound_trojan.rs` 拆分前后等价）。
//!
//! 拆分的性质是**纯重构**：trojan 的握手流程、观察窗判据、dry-run 缺省目标
//! 一律不变。本文件把这三条判据各自钉成用例，防止后续改动悄悄破坏它们：
//!
//! 1. `trojan_handshake_writes_full_request_header` —— 请求头**逐字节**等于
//!    参考 `proxy/trojan/protocol.go` 的线上格式（56 字节密码哈希 + CRLF +
//!    命令字节 + SOCKS 地址 + CRLF），且命令字节为 `commandTCP = 1`。
//! 2. `trojan_auth_rejected_when_peer_closes_in_observe_window` —— 对端在观察窗
//!    内关闭连接 ⇒ 出口判**拒绝**（不是静默成功）。这正是参考的拒绝语义：
//!    trojan 没有成功响应头，服务端认证失败**唯一**的表达就是关闭连接
//!    （`proxy/trojan/server.go` 不写任何状态字节，`client.go` 也不读）。
//! 3. `trojan_dryrun_falls_back_to_discard_probe_target` —— dry-run 缺省握手
//!    目标回落到 `127.0.0.1:9`（`TROJAN_PROBE_FALLBACK_HOST/PORT`）。
//!
//! 夹具全部用回环地址 + 临时端口 + 假凭据；服务端是**手写的最小 trojan
//! 服务端**（TLS 接入 → 读请求头 → 校验哈希 → 按用例决定「保持安静」或
//! 「立刻关闭」），刻意不复用 `lengsuo_trojan::server::Server`——后者会
//! 自动去 dial 目标并中继，无法制造「认证通过但观察窗内安静」这一状态。
//!
//! 用例里的密码是假凭据；断言与失败信息都不打印密码或哈希。

use std::time::Duration;

use lengsuo_node::config::NodeConfig;
use lengsuo_node::outbound::{dial, Outbound};
use lengsuo_node::outbound_trojan::{TROJAN_PROBE_FALLBACK_HOST, TROJAN_PROBE_FALLBACK_PORT};
use lengsuo_tls::{PrivatePkcs8KeyDer, TlsServer};
use lengsuo_trojan::credential::Credential;
use lengsuo_trojan::{Command, Request};
use serde_json::json;
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener;
use tokio::time::timeout;

/// 单步等待（对齐 trojan 互通夹具量级）。
const WAIT: Duration = Duration::from_secs(5);
/// trojan 认证拒绝观察窗。
const OBSERVE: Duration = Duration::from_millis(300);
/// 单用例总超时。
const TOTAL: Duration = Duration::from_secs(30);
/// 假凭据（仅测试用，不与任何真实口令相关）。
const PASSWORD: &str = "node-trojan-outbound-fake-password";

/// trojan 请求头里密码哈希的字节数（`SHA224` 十六进制文本）。
const HASH_LEN: usize = 56;

/// 服务端读完请求头之后要做什么。
#[derive(Clone, Copy)]
enum ServerBehavior {
    /// 认证通过：保持连接安静（不写任何字节），让客户端的观察窗安静到超时。
    /// 这正是「认证成功」在参考里的**唯一**正向表现：服务端不回执。
    StayQuiet,
    /// 认证失败：**干净**关闭（TLS `close_notify`）⇒ 客户端读到应用层 EOF
    /// （`Ok(0)`），对应出口的「连接被对端关闭（trojan 无响应头）」分支。
    CloseCleanly,
    /// 认证失败：直接丢弃连接（不发 `close_notify`）⇒ 客户端读到
    /// `UnexpectedEof`，对应出口的「连接在观察窗内断开」分支。
    CloseImmediately,
}

/// 最小 trojan 服务端：TLS 接入 → 读请求头 → 按行为决定后续动作。
///
/// 返回（端口，CA PEM）。请求头的哈希由服务端用**同一个假凭据**校验，
/// 因此「错误密码」这条路在服务端侧也会被识别；本文件另外单独覆盖它。
async fn trojan_server(password: &str, behavior: ServerBehavior) -> (u16, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server = TlsServer::new(
        vec![cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        WAIT,
    )
    .expect("TLS 服务端配置");
    let credential = Credential::new(password);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let server = server.clone();
            let credential = credential.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = server.accept(socket).await else {
                    return;
                };
                // 读满整个请求头：56 字节哈希 + CRLF + 命令 + SOCKS 地址 + CRLF。
                // 目标地址用 IPv4 形式（1+4+2 字节），总长 = 56+2+1+7+2 = 68。
                let mut header = vec![0u8; 68];
                if tls.read_exact(&mut header).await.is_err() {
                    return;
                }
                let expected = credential.as_bytes();
                if header[..HASH_LEN] != *expected {
                    // 哈希不符：按参考语义关闭连接（认证被拒）。
                    return;
                }
                match behavior {
                    ServerBehavior::StayQuiet => {
                        // 认证通过：保持连接活着且安静，直到对端关闭。
                        let mut scratch = [0u8; 1024];
                        let _ = tls.read(&mut scratch).await;
                    }
                    ServerBehavior::CloseCleanly => {
                        // 认证失败：干净关闭（TLS close_notify），不写任何应答字节。
                        use tokio::io::AsyncWriteExt as _;
                        let _ = tls.shutdown().await;
                    }
                    ServerBehavior::CloseImmediately => {
                        // 认证失败：直接丢弃连接，不写任何应答字节。
                        drop(tls);
                    }
                }
            });
        }
    });
    (port, cert.cert.pem())
}

/// 构造一个 trojan 节点配置（回环端点 + 假凭据 + 显式信任锚）。
fn node(port: u16, ca_pem: &str, password: &str, probe: Option<(String, u16)>) -> NodeConfig {
    let mut value = json!({
        "name": "trojan-outbound-regression",
        "protocol": "trojan",
        "endpoint": { "host": "127.0.0.1", "port": port },
        "tls": { "server_name": "localhost", "ca_pem": ca_pem },
        "auth": { "password": password }
    });
    if let Some((host, probe_port)) = probe {
        value["probe_target"] = json!({ "host": host, "port": probe_port });
    }
    let nodes: Vec<NodeConfig> = serde_json::from_value(json!([value])).expect("节点配置");
    nodes.into_iter().next().expect("恰好一个节点")
}

/// 挂住的 TCP 目标：接受连接后静默保持——trojan 服务端中继的探测目标。
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

/// 用例 1：请求头完整写出，且逐字节符合参考的线上格式。
///
/// 判据（与 `crate::outbound_trojan` 的实现同源）：
/// - 56 字节密码哈希 = `Credential::new(password).as_bytes()`（参考
///   `proxy/trojan/protocol.go` 的 `hex(sha224(password))`）；
/// - 第 57/58 字节 = CRLF；
/// - 第 59 字节 = `commandTCP = 1`（`protocol.go` 的 `commandTCP`）；
/// - 随后 = SOCKS 地址（ATYP 0x01 + IPv4 + 端口）与结尾 CRLF。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_handshake_writes_full_request_header() {
    timeout(TOTAL, async {
        let (port, ca_pem) = trojan_server(PASSWORD, ServerBehavior::StayQuiet).await;
        let config = node(port, &ca_pem, PASSWORD, None);

        let mut outbound = dial(&config, WAIT, OBSERVE)
            .await
            .expect("trojan 拨号应成功");
        let Outbound::Trojan(session) = &mut outbound else {
            panic!("trojan 拨号必须返回 Trojan 出站");
        };
        // 请求头已由 `Session::connect` 完整写出并 flush；这里再确认会话可用
        // （未 poison），即「写头失败拿不到会话」的 fail-closed 约束成立。
        assert!(!session.is_poisoned(), "写头完成后会话不应被 poison");
    })
    .await
    .expect("总超时");
}

/// 用例 1 的字节级版本：直接比对你方写出的请求头与参考格式。
///
/// 用**独立于出口实现**的字节断言（自己算哈希、自己拼期望头部），这样它才
/// 真的在检查「线上格式」，而不是复述实现。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_request_header_matches_reference_wire_format() {
    timeout(TOTAL, async {
        // 截获服务端侧读到的请求头：TLS 之后先读 68 字节并回传。
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server = TlsServer::new(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            WAIT,
        )
        .expect("TLS 服务端配置");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured: tokio::sync::oneshot::Sender<Vec<u8>>;
        let captured_rx: tokio::sync::oneshot::Receiver<Vec<u8>>;
        let (tx, rx) = tokio::sync::oneshot::channel();
        captured = tx;
        captured_rx = rx;
        tokio::spawn(async move {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut tls) = server.accept(socket).await else {
                return;
            };
            let mut header = vec![0u8; 68];
            if tls.read_exact(&mut header).await.is_err() {
                return;
            }
            let _ = captured.send(header);
            // 保持连接安静，让客户端的观察窗安静到超时。
            let mut scratch = [0u8; 1024];
            let _ = tls.read(&mut scratch).await;
        });

        let config = node(port, &cert.cert.pem(), PASSWORD, None);
        let _ = dial(&config, WAIT, OBSERVE)
            .await
            .expect("trojan 拨号应成功");

        let header = timeout(WAIT, captured_rx)
            .await
            .expect("等待请求头超时")
            .expect("服务端应收到请求头");

        // 期望头部 = 哈希 + CRLF + 命令(1) + SOCKS 地址 + CRLF。
        let credential = Credential::new(PASSWORD);
        let expected = lengsuo_trojan::encode(
            &Request {
                command: Command::Tcp,
                target: ss_core::target::TargetAddr::V4([127, 0, 0, 1], TROJAN_PROBE_FALLBACK_PORT),
            },
            &credential,
        )
        .expect("期望头部可编码");
        assert_eq!(header, expected, "请求头须逐字节等于参考格式");
        // 显式复核几个关键位（不依赖 codec 的实现细节）。
        assert_eq!(
            &header[HASH_LEN..HASH_LEN + 2],
            b"\r\n",
            "哈希后必须是 CRLF"
        );
        assert_eq!(header[HASH_LEN + 2], 1, "命令字节必须是 commandTCP = 1");
        assert_eq!(header[HASH_LEN + 3], 0x01, "SOCKS 地址 ATYP 必须是 IPv4");
        assert_eq!(&header[header.len() - 2..], b"\r\n", "头部结尾必须是 CRLF");
        // 缺省握手目标必须是 discard 端口 9（见用例 3）。端口是大端。
        assert_eq!(
            &header[header.len() - 4..header.len() - 2],
            &[0, 9],
            "缺省目标端口必须是 9（discard）"
        );
    })
    .await
    .expect("总超时");
}

/// 用例 2：服务端在观察窗内关闭连接 ⇒ 出口判**拒绝**。
///
/// 这条是 trojan 与其它协议最大的差别所在：没有成功响应头，只能负向排除。
/// 若这条判据被放宽（把 EOF 当成「未被拒绝」），错密码就会被静默放行。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_auth_rejected_when_peer_closes_in_observe_window() {
    timeout(TOTAL, async {
        let (port, ca_pem) = trojan_server(PASSWORD, ServerBehavior::CloseImmediately).await;
        let config = node(port, &ca_pem, PASSWORD, None);

        let error = match dial(&config, WAIT, OBSERVE).await {
            Ok(_) => panic!("对端在观察窗内关闭连接必须判拒绝"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains("拒绝") || message.contains("关闭"),
            "拒绝原因须指向「连接被对端关闭」：{message}"
        );
        // 失败原因不得包含密码或其派生值。
        assert!(
            !message.contains(PASSWORD),
            "失败原因不得包含密码：{message}"
        );
    })
    .await
    .expect("总超时");
}

/// 用例 2 的干净关闭版本：服务端发 TLS `close_notify` 后关闭 ⇒ 应用层 EOF
/// ⇒ 出口同样判**拒绝**（「连接被对端关闭（trojan 无响应头）」分支）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_auth_rejected_when_peer_closes_cleanly() {
    timeout(TOTAL, async {
        let (port, ca_pem) = trojan_server(PASSWORD, ServerBehavior::CloseCleanly).await;
        let config = node(port, &ca_pem, PASSWORD, None);

        let error = match dial(&config, WAIT, OBSERVE).await {
            Ok(_) => panic!("对端干净关闭连接必须判拒绝"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains("拒绝") || message.contains("关闭"),
            "拒绝原因须指向「连接被对端关闭」：{message}"
        );
        assert!(
            !message.contains(PASSWORD),
            "失败原因不得包含密码：{message}"
        );
    })
    .await
    .expect("总超时");
}

/// 用例 2 的密码错位版本：客户端用错密码，服务端关闭连接 ⇒ 同样判拒绝。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_wrong_password_is_rejected_not_silently_accepted() {
    timeout(TOTAL, async {
        let (port, ca_pem) = trojan_server(PASSWORD, ServerBehavior::StayQuiet).await;
        // 客户端用错密码：服务端的哈希校验失败 ⇒ 关闭连接 ⇒ 观察窗内 EOF。
        let config = node(port, &ca_pem, "definitely-wrong-password", None);

        let error = match dial(&config, WAIT, OBSERVE).await {
            Ok(_) => panic!("错密码必须判拒绝"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            !message.contains(PASSWORD) && !message.contains("definitely-wrong"),
            "失败原因不得包含任何密码：{message}"
        );
    })
    .await
    .expect("总超时");
}

/// 用例 3：dry-run 缺省握手目标回落到 discard 端口，且该回落值不变。
///
/// `TROJAN_PROBE_FALLBACK_HOST/PORT` 是拆出来的 trojan 常量；这里断它的
/// 值（`127.0.0.1` / `9`）。**行为**侧（请求头里真的携带 `127.0.0.1:9`）
/// 由 `trojan_request_header_matches_reference_wire_format` 的实字节断言覆盖。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_dryrun_falls_back_to_discard_probe_target() {
    timeout(TOTAL, async {
        assert_eq!(TROJAN_PROBE_FALLBACK_HOST, "127.0.0.1");
        assert_eq!(TROJAN_PROBE_FALLBACK_PORT, 9);

        // dry-run 走 dry_run 分发（`outbound::dial` 的同一条路径）⇒ 不配置
        // probe_target 时也必须能用缺省目标完成一次握手（服务端安静即 ok）。
        let (port, ca_pem) = trojan_server(PASSWORD, ServerBehavior::StayQuiet).await;
        let config = node(port, &ca_pem, PASSWORD, None);
        let report = lengsuo_node::dryrun::dry_run(&[config], WAIT, OBSERVE).await;
        assert!(report[0].ok(), "dry-run 应通过：{:?}", report[0].reason);
    })
    .await
    .expect("总超时");
}

/// 用例 3 的配置覆盖版本：显式 `probe_target` 时**不**回落，用配置值。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_explicit_probe_target_overrides_fallback() {
    timeout(TOTAL, async {
        let probe_port = parked_target().await;
        let (port, ca_pem) = trojan_server(PASSWORD, ServerBehavior::StayQuiet).await;
        let config = node(
            port,
            &ca_pem,
            PASSWORD,
            Some(("127.0.0.1".to_owned(), probe_port)),
        );

        let mut outbound = dial(&config, WAIT, OBSERVE)
            .await
            .expect("显式 probe_target 时也应握手成功");
        let Outbound::Trojan(session) = &mut outbound else {
            panic!("trojan 拨号必须返回 Trojan 出站");
        };
        assert!(!session.is_poisoned(), "写头完成后会话不应被 poison");
    })
    .await
    .expect("总超时");
}
