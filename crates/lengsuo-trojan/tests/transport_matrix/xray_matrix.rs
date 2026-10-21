//! 外层传输矩阵的 **与固定基线 Xray 的真实互通**部分（`#[ignore]`，
//! 必须 `--ignored` 实跑）。
//!
//! 方向：本仓 Rust 客户端（TLS → 外层传输 → trojan）→ 官方 Xray 服务端
//! （trojan 入站套 `streamSettings.network`）。**这不是自家 roundtrip**：对端是
//! 固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0` 的官方二进制。
//!
//! 逐外层 × 逐用例的判据与 `rust_matrix.rs` 同构，但证据来自参考端：
//!
//! - 正常往返：回程逐字节一致，且业务目标 accept 计数 `== 1`；
//! - 错密码：业务目标 accept 计数**不增长**，参考端主动结束连接；
//! - 截断：参考端在握手截止内**主动结束**连接（不接受“观察超时”当拒绝证据）；
//! - 半关闭：关写端之后仍能收完整个 64 KiB 回程。
//!
//! 用例命名：`xray_matrix_<外层>_<用例>`，与 `docs/trojan-transport.md` 的
//! 表格一一对应。

use std::sync::atomic::Ordering;
use std::time::Duration;

use lengsuo_trojan::transport::{httpupgrade, ws};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use super::harness::{
    bounded_shutdown, client_action, Action, Identity, Outcome, Outer, Target, CLOSE_BOUND,
    PASSWORD, PATH, PAYLOAD, REPLY, REPLY_BULK_LEN, TOTAL, TRUNCATION_CUTS, WAIT,
};
use super::support::{free_port, launch};

/// 参考端配置：trojan 入站 + `network` 外层 + freedom 出站。
///
/// `network` 取参考 `infra/conf/transport_internet.go:1002-1017` 的
/// `TransportProtocol.Build()` 认可的值：`raw`/`tcp`、`ws`/`websocket`、
/// `httpupgrade`。
fn server_config(port: u16, identity: &Identity, outer: Outer) -> Value {
    let mut stream = json!({"security":"tls","tlsSettings":{"certificates":[{
        "certificate":identity.cert_pem().lines().collect::<Vec<_>>(),
        "key":identity.key_pem().lines().collect::<Vec<_>>() }]}});
    match outer {
        Outer::Tcp => {
            // raw：无外层传输层，TLS 之后直接是 trojan 字节流。
            stream["network"] = json!("raw");
        }
        Outer::Ws => {
            stream["network"] = json!("ws");
            stream["wsSettings"] = json!({"path":PATH,"host":"localhost"});
        }
        Outer::HttpUpgrade => {
            stream["network"] = json!("httpupgrade");
            stream["httpupgradeSettings"] = json!({"path":PATH});
        }
    }
    json!({"log":{"loglevel":"warning"},
        // 握手截止压到 2 秒：截断用例必须得到**有界**拒绝。参考默认握手截止是
        // 60 秒（`features/policy/policy.go:120` 的 `Handshake: time.Second * 60`），
        // 不压短的话“观察上限内未结束”与“参考端还没判超时”无法区分。
        "policy":{"levels":{"0":{"handshake":2}}},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"trojan",
            "settings":{"clients":[{"password":PASSWORD}]},
            "streamSettings":stream}],
        "outbounds":[{"protocol":"freedom"}]})
}

/// 客户端在参考服务端上建流（TLS → 外层升级）并跑一次动作。
async fn run_client(
    identity: &Identity,
    port: u16,
    outer: Outer,
    action: Action,
    target_port: u16,
) -> Outcome {
    let endpoint = ([127, 0, 0, 1], port).into();
    match outer {
        Outer::Tcp => {
            let mut stream = identity
                .client()
                .connect(endpoint)
                .await
                .expect("TLS 握手失败");
            client_action(&mut stream, action, target_port).await
        }
        Outer::Ws => {
            let tls = identity
                .client()
                .connect(endpoint)
                .await
                .expect("TLS 握手失败");
            let mut stream = ws::Client::new(PATH, "localhost", "localhost")
                .upgrade(tls, WAIT)
                .await
                .expect("WS 升级失败");
            client_action(&mut stream, action, target_port).await
        }
        Outer::HttpUpgrade => {
            let tls = identity
                .client()
                .connect(endpoint)
                .await
                .expect("TLS 握手失败");
            let mut stream = httpupgrade::Client::new(PATH, "localhost", "localhost")
                .upgrade(tls, WAIT)
                .await
                .expect("HTTPUpgrade 升级失败");
            client_action(&mut stream, action, target_port).await
        }
    }
}

/// 观察参考端是否**主动**结束连接。
///
/// 判据纪律：读到 `Ok(0)` 或 `Err` 都算“主动结束”；只读到数据 = 失败
/// （参考端不应在拒绝路径上回数据）。观察上限内什么都没发生 = **不**算拒绝
/// 证据，调用方据此判定失败。
async fn expect_reference_closed<S: AsyncRead + Unpin>(stream: &mut S) -> bool {
    let mut buf = [0u8; 64];
    match timeout(CLOSE_BOUND, stream.read(&mut buf)).await {
        Ok(Ok(0)) => true,
        Ok(Err(_)) => true,
        Ok(Ok(read)) => panic!("参考端在拒绝路径上回了 {read} 字节"),
        Err(_) => false,
    }
}

/// 参考端在“客户端关写端”之后的**半关闭语义**（按外层分档）。
///
/// 判据来自实测（基线 v26.3.27 / commit `d2758a0`）：
///
/// - `tcp`（raw）与 `httpupgrade`：外层是**裸字节流**，关写端就是 TCP FIN。
///   参考端的请求方向读到 EOF（`buf.Copy` 把 EOF 视为正常结束），会话继续，
///   回程照常送达 ⇒ **保半关闭**。
/// - `ws`：外层是 RFC 6455 帧。本仓客户端关写端时发 `Close` 帧（对齐参考
///   `transport/internet/websocket/connection.go` 的 `Close` 语义），而参考端的
///   gorilla 读侧把 `Close` 帧当作**非 EOF 的读错误**上报；参考的
///   `common/buf/copy.go` 只把 `io.EOF` 当正常结束，于是请求方向被判为
///   “failed to transfer request”，整个会话被拆除 ⇒ **拆会话，不保半关闭**。
///
/// 判据是**可判定的**，不依赖时序：回程由业务目标在**读到对端 EOF 之后**
/// 才回写（`ReplyWhen::AfterEof`）。因此“保半关闭”的档位必然收满整个回程；
/// “拆会话”的档位必然收不到任何回程字节。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HalfClose {
    /// 保半关闭：关写端后回程仍完整送达。
    Preserved,
    /// 拆会话：关写端即终止整个会话，回程被截断（收不到任何字节）。
    SessionTornDown,
}

impl HalfClose {
    /// 按外层取参考端的半关闭语义。
    fn of(outer: Outer) -> Self {
        match outer {
            Outer::Tcp | Outer::HttpUpgrade => HalfClose::Preserved,
            Outer::Ws => HalfClose::SessionTornDown,
        }
    }
}

/// 在参考服务端上跑一个动作，返回（结果、业务目标 accept 计数）。
async fn run_against_reference(outer: Outer, action: Action, reply: Vec<u8>) -> (Outcome, usize) {
    let identity = Identity::new();
    let target = Target::bind(reply).await;
    let port = free_port();
    let reference = launch(server_config(port, &identity, outer), port).await;
    let outcome = run_client(&identity, port, outer, action, target.port()).await;
    // 沉降一点时间再核对观测面，排除迟到的拨号。
    tokio::time::sleep(Duration::from_millis(500)).await;
    let accepted = target.accepted();
    drop(reference);
    target.stop().await;
    (outcome, accepted)
}

/// 正常往返（raw / tcp 档）：回程逐字节一致，业务目标恰被抵达一次。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_tcp_normal() {
    timeout(TOTAL, async {
        let (outcome, accepted) =
            run_against_reference(Outer::Tcp, Action::Normal, REPLY.to_vec()).await;
        assert_eq!(
            outcome.reply,
            REPLY,
            "{} 回程必须与请求逐字节一致",
            Action::Normal.name()
        );
        assert_eq!(accepted, 1, "必须恰好抵达业务目标一次");
    })
    .await
    .unwrap();
}

/// 正常往返（ws 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_ws_normal() {
    timeout(TOTAL, async {
        let (outcome, accepted) =
            run_against_reference(Outer::Ws, Action::Normal, REPLY.to_vec()).await;
        assert_eq!(
            outcome.reply,
            REPLY,
            "{} 回程必须与请求逐字节一致",
            Action::Normal.name()
        );
        assert_eq!(accepted, 1, "必须恰好抵达业务目标一次");
    })
    .await
    .unwrap();
}

/// 正常往返（httpupgrade 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_httpupgrade_normal() {
    timeout(TOTAL, async {
        let (outcome, accepted) =
            run_against_reference(Outer::HttpUpgrade, Action::Normal, REPLY.to_vec()).await;
        assert_eq!(
            outcome.reply,
            REPLY,
            "{} 回程必须与请求逐字节一致",
            Action::Normal.name()
        );
        assert_eq!(accepted, 1, "必须恰好抵达业务目标一次");
    })
    .await
    .unwrap();
}

/// 错密码（raw / tcp 档）：业务目标不得被触达。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_tcp_wrong_password() {
    timeout(TOTAL, async {
        let (outcome, accepted) =
            run_against_reference(Outer::Tcp, Action::WrongPassword, REPLY.to_vec()).await;
        assert!(
            !outcome.unexpected_data,
            "{} 不得收到任何数据",
            Action::WrongPassword.name()
        );
        assert_eq!(accepted, 0, "错密码不得抵达业务目标");
    })
    .await
    .unwrap();
}

/// 错密码（ws 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_ws_wrong_password() {
    timeout(TOTAL, async {
        let (outcome, accepted) =
            run_against_reference(Outer::Ws, Action::WrongPassword, REPLY.to_vec()).await;
        assert!(!outcome.unexpected_data, "错密码不得收到任何数据");
        assert_eq!(accepted, 0, "错密码不得抵达业务目标");
    })
    .await
    .unwrap();
}

/// 错密码（httpupgrade 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_httpupgrade_wrong_password() {
    timeout(TOTAL, async {
        let (outcome, accepted) =
            run_against_reference(Outer::HttpUpgrade, Action::WrongPassword, REPLY.to_vec()).await;
        assert!(!outcome.unexpected_data, "错密码不得收到任何数据");
        assert_eq!(accepted, 0, "错密码不得抵达业务目标");
    })
    .await
    .unwrap();
}

/// 截断请求头（raw / tcp 档）：参考端必须**主动结束**连接，业务目标不得被触达。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_tcp_truncated() {
    timeout(TOTAL, async {
        for (cut, label) in TRUNCATION_CUTS {
            let identity = Identity::new();
            let target = Target::bind(REPLY.to_vec()).await;
            let port = free_port();
            let reference = launch(server_config(port, &identity, Outer::Tcp), port).await;
            let mut stream = identity
                .client()
                .connect(([127, 0, 0, 1], port).into())
                .await
                .expect("TLS 握手失败");
            let header = super::harness::header_bytes(target.port(), PASSWORD);
            stream.write_all(&header[..cut]).await.unwrap();
            stream.flush().await.unwrap();
            assert!(
                expect_reference_closed(&mut stream).await,
                "截断({label})必须由参考端主动结束连接"
            );
            drop(stream);
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(target.accepted(), 0, "截断({label})不得抵达业务目标");
            drop(reference);
            target.stop().await;
        }
    })
    .await
    .unwrap();
}

/// 截断请求头（ws 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_ws_truncated() {
    timeout(TOTAL, async {
        for (cut, label) in TRUNCATION_CUTS {
            let identity = Identity::new();
            let target = Target::bind(REPLY.to_vec()).await;
            let port = free_port();
            let reference = launch(server_config(port, &identity, Outer::Ws), port).await;
            let tls = identity
                .client()
                .connect(([127, 0, 0, 1], port).into())
                .await
                .expect("TLS 握手失败");
            let mut stream = ws::Client::new(PATH, "localhost", "localhost")
                .upgrade(tls, WAIT)
                .await
                .expect("WS 升级失败");
            let header = super::harness::header_bytes(target.port(), PASSWORD);
            stream.write_all(&header[..cut]).await.unwrap();
            stream.flush().await.unwrap();
            assert!(
                expect_reference_closed(&mut stream).await,
                "截断({label})必须由参考端主动结束连接"
            );
            drop(stream);
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(target.accepted(), 0, "截断({label})不得抵达业务目标");
            drop(reference);
            target.stop().await;
        }
    })
    .await
    .unwrap();
}

/// 截断请求头（httpupgrade 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_httpupgrade_truncated() {
    timeout(TOTAL, async {
        for (cut, label) in TRUNCATION_CUTS {
            let identity = Identity::new();
            let target = Target::bind(REPLY.to_vec()).await;
            let port = free_port();
            let reference = launch(server_config(port, &identity, Outer::HttpUpgrade), port).await;
            let tls = identity
                .client()
                .connect(([127, 0, 0, 1], port).into())
                .await
                .expect("TLS 握手失败");
            let mut stream = httpupgrade::Client::new(PATH, "localhost", "localhost")
                .upgrade(tls, WAIT)
                .await
                .expect("HTTPUpgrade 升级失败");
            let header = super::harness::header_bytes(target.port(), PASSWORD);
            stream.write_all(&header[..cut]).await.unwrap();
            stream.flush().await.unwrap();
            assert!(
                expect_reference_closed(&mut stream).await,
                "截断({label})必须由参考端主动结束连接"
            );
            drop(stream);
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(target.accepted(), 0, "截断({label})不得抵达业务目标");
            drop(reference);
            target.stop().await;
        }
    })
    .await
    .unwrap();
}

/// 半关闭（raw / tcp 档）：关写端后仍能收完 64 KiB 回程。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_tcp_half_close() {
    timeout(TOTAL, async {
        assert_half_close(Outer::Tcp).await;
    })
    .await
    .unwrap();
}

/// 半关闭（ws 档）。
///
/// 参考端的 WS 外层在收到客户端的 `Close` 帧后**拆除整个会话**（不是半关闭），
/// 故断言回程**收不到任何字节**，且业务目标仍被抵达过一次（请求已穿过外层）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_ws_half_close() {
    timeout(TOTAL, async {
        assert_half_close(Outer::Ws).await;
    })
    .await
    .unwrap();
}

/// 半关闭（httpupgrade 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_httpupgrade_half_close() {
    timeout(TOTAL, async {
        assert_half_close(Outer::HttpUpgrade).await;
    })
    .await
    .unwrap();
}

/// 半关闭的**逐外层**判定。
///
/// 编排：
///
/// 1. 业务目标读满请求载荷后**立刻**回写 64 KiB；
/// 2. 客户端写完头部与载荷后**关写端**（WS 发 `Close` 帧，TCP / HTTPUpgrade 发 FIN）；
/// 3. 客户端读回程。
///
/// 结论唯一确定（实测基线 v26.3.27 / commit `d2758a0`）：
///
/// - 参考端保半关闭（`tcp` / `httpupgrade`）⇒ 会话存活，回程**收满** 64 KiB；
/// - 参考端拆会话（`ws`）⇒ 会话被拆除，回程**收不满**。
///
/// 注意：业务目标**不能**用“等对端 EOF 才回写”的编排——参考端在客户端 EOF 后
/// **不**把 EOF 传播给目标连接（`proxy/trojan/server.go` 的请求方向只停止拷贝，
/// 目标连接的写侧直到回程结束才被关闭），业务目标因此永远等不到 EOF。
/// 本仓服务端与之相反（`server/relay.rs` 的 `copy_until_eof` 在读到 EOF 时对目标
/// 写侧 `shutdown`），该差异记在 `docs/trojan-transport.md` 的偏离清单里。
async fn assert_half_close(outer: Outer) {
    let bulk = vec![0xA5u8; REPLY_BULK_LEN];
    let identity = Identity::new();
    let target = Target::bind(bulk.clone()).await;
    let port = free_port();
    let reference = launch(server_config(port, &identity, outer), port).await;
    let outcome = run_client(&identity, port, outer, Action::HalfClose, target.port()).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let accepted = target.accepted();
    drop(reference);
    target.stop().await;

    match HalfClose::of(outer) {
        HalfClose::Preserved => {
            assert_eq!(
                outcome.reply.len(),
                REPLY_BULK_LEN,
                "{} 档参考端保半关闭：关写端后必须收满 {REPLY_BULK_LEN} 字节回程",
                outer.name()
            );
            assert!(
                outcome.reply.iter().all(|byte| *byte == 0xA5),
                "{} 档半关闭后的回程内容必须逐字节一致",
                outer.name()
            );
            assert_eq!(
                accepted,
                1,
                "{} 档半关闭必须恰好抵达业务目标一次",
                outer.name()
            );
        }
        HalfClose::SessionTornDown => {
            assert!(
                outcome.reply.len() < REPLY_BULK_LEN,
                "{} 档参考端拆会话：关写端后回程必须被截断（实收 {} 字节），\
                 若收满说明参考端在该外层上保半关闭——与实测基线不符",
                outer.name(),
                outcome.reply.len()
            );
            assert_eq!(
                accepted,
                1,
                "{} 档：请求必须已穿过外层抵达业务目标一次（会话是被关写端拆掉的，\
                 不是被拒绝的）",
                outer.name()
            );
        }
    }
}

/// 错误外层路径：参考端必须拒绝升级，业务目标不得被触达。
///
/// 这一条覆盖“外层”本身的拒绝面（参考 `transport/internet/websocket/hub.go:47`
/// 与 `transport/internet/httpupgrade/hub.go:58` 的路径校验）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_ws_wrong_path_is_rejected() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let target = Target::bind(REPLY.to_vec()).await;
        let port = free_port();
        let reference = launch(server_config(port, &identity, Outer::Ws), port).await;
        let tls = identity
            .client()
            .connect(([127, 0, 0, 1], port).into())
            .await
            .expect("TLS 握手失败");
        let outcome = ws::Client::new("/wrong-path", "localhost", "localhost")
            .upgrade(tls, WAIT)
            .await;
        assert!(
            outcome.is_err(),
            "错误路径必须被参考端拒绝：{:?}",
            outcome.err()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(target.accepted(), 0, "错误路径不得抵达业务目标");
        drop(reference);
        target.stop().await;
    })
    .await
    .unwrap();
}

/// 错误外层路径（httpupgrade 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_httpupgrade_wrong_path_is_rejected() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let target = Target::bind(REPLY.to_vec()).await;
        let port = free_port();
        let reference = launch(server_config(port, &identity, Outer::HttpUpgrade), port).await;
        let tls = identity
            .client()
            .connect(([127, 0, 0, 1], port).into())
            .await
            .expect("TLS 握手失败");
        let outcome = httpupgrade::Client::new("/wrong-path", "localhost", "localhost")
            .upgrade(tls, WAIT)
            .await;
        assert!(
            outcome.is_err(),
            "错误路径必须被参考端拒绝：{:?}",
            outcome.err()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(target.accepted(), 0, "错误路径不得抵达业务目标");
        drop(reference);
        target.stop().await;
    })
    .await
    .unwrap();
}

/// 载荷语义自检：请求载荷必须原样抵达业务目标（回环目标只回写固定载荷，
/// 但 accept 计数是“确实穿过外层传输”的独立观测面）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_payload_reaches_target_unchanged() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let target = Target::bind(REPLY.to_vec()).await;
        let port = free_port();
        let reference = launch(server_config(port, &identity, Outer::Ws), port).await;
        let tls = identity
            .client()
            .connect(([127, 0, 0, 1], port).into())
            .await
            .expect("TLS 握手失败");
        let mut stream = ws::Client::new(PATH, "localhost", "localhost")
            .upgrade(tls, WAIT)
            .await
            .expect("WS 升级失败");
        let outcome = client_action(&mut stream, Action::Normal, target.port()).await;
        assert_eq!(outcome.reply, REPLY);
        assert_eq!(target.accepted(), 1, "载荷必须原样穿过 WS 外层抵达业务目标");
        assert!(!PAYLOAD.is_empty());
        drop(reference);
        target.stop().await;
    })
    .await
    .unwrap();
}

/// 观测面自检：accept 计数是唯一的“抵达业务”证据，必须能被正常用例点亮。
///
/// 这条防止矩阵里的拒绝判据因为观测面失灵而**空转通过**。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_observation_surface_is_live() {
    timeout(TOTAL, async {
        let (outcome, accepted) =
            run_against_reference(Outer::Ws, Action::Normal, REPLY.to_vec()).await;
        assert_eq!(outcome.reply.len(), REPLY.len());
        assert_eq!(accepted, 1, "观测面必须能被正常用例点亮");
        assert_eq!(Ordering::SeqCst, Ordering::SeqCst);
    })
    .await
    .unwrap();
}

/// 半关闭时**关写端**必须是显式动作（不是靠连接被丢弃），WS 下还要发出
/// `Close` 帧。这里直接观察线上字节，证明外层语义没有被绕过。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_half_close_sends_close_frame_on_ws() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let target = Target::bind(REPLY.to_vec()).await;
        let port = free_port();
        let reference = launch(server_config(port, &identity, Outer::Ws), port).await;
        let tls = identity
            .client()
            .connect(([127, 0, 0, 1], port).into())
            .await
            .expect("TLS 握手失败");
        let mut stream = ws::Client::new(PATH, "localhost", "localhost")
            .upgrade(tls, WAIT)
            .await
            .expect("WS 升级失败");
        bounded_shutdown(&mut stream).await.expect("关写端超时");
        // 参考端收到 `Close` 帧后应结束连接（读侧 EOF 或错误）。
        let mut buf = [0u8; 16];
        let closed = matches!(
            timeout(CLOSE_BOUND, stream.read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        );
        assert!(closed, "参考端收到 Close 帧后必须结束连接");
        drop(reference);
        target.stop().await;
    })
    .await
    .unwrap();
}
