//! VLESS 出口接 REALITY 的实跑取证（Rust↔Rust）。
//!
//! 对端是**本仓**的 REALITY + TLS 1.3 服务端（`lengsuo_vless::reality::server`
//! 与 `lengsuo_vless::reality::session::server_handshake`，编排见
//! `vless_reality_support/mod.rs`），客户端是 **node 的 VLESS 出口**
//! （`lengsuo_node::outbound_vless::dial_vless`，走新加的 REALITY 配置段）。
//!
//! ```text
//! node 侧：NodeConfig.reality → RealityConfig::from_settings → RealityStream::connect
//!        → stream::send_request（VLESS 头）→ stream::receive_response（[0,0]）
//! 服务端：accept_hello → TLS 1.3 → stream::receive_request → 回环 echo
//!        → stream::send_response → 载荷
//! ```
//!
//! 覆盖四组：
//! 1. **正例**：握手成功 + 收到 `[0, 0]` 成功响应头 + 载荷往返逐字节一致。
//! 2. **负例**：坏 publicKey / 坏 shortId ⇒ 拨号失败，且**没有**退回普通 TLS、
//!    **没有**发出明文。
//! 3. **配置层**：非 vless 协议带 `reality` 段 ⇒ 加载阶段显式报错（fail-closed）。
//! 4. **熵源自检**：REALITY 服务端握手所需的 `rand_core` 在 node 依赖里可达。
//!
//! **本文件只覆盖 Rust↔Rust**，不声称与参考实现互通；参考侧取证见
//! `vless_reality_xray.rs`。
//!
//! 全部回环地址、临时端口、运行时生成的假凭据；每个网络操作都有截止时间。
//! 日志不输出任何密钥材料。

#[path = "vless_reality_support/mod.rs"]
mod support;

use std::sync::Arc;
use std::time::Duration;

use lengsuo_node::config::NodeConfig;
use lengsuo_node::outbound_vless::dial_vless;
use md5::digest::crypto_common::rand_core::{OsRng, RngCore};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use support::{
    accept_only_watcher, reality_node, start_server, Server, DEADLINE, PAYLOAD, SHORT_ID_HEX, UUID,
    WAIT,
};

/// **1. 正例**：node 的 VLESS 出口经 REALITY 连上本仓 REALITY 服务端，
/// 握手成功、收到 `[0, 0]` 成功响应头、载荷往返逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_reality_roundtrip_to_own_server() {
    timeout(DEADLINE, async {
        let server = Arc::new(Server::new());
        let (port, server_task) = start_server(server.clone()).await;

        let node = reality_node(port, &server);
        let mut outbound = dial_vless(&node, WAIT)
            .await
            .expect("REALITY 建流 + VLESS 握手应成功");

        // 判据与普通 TLS 分支完全一致：成功响应头 `[0, 0]` 已被消费
        // （`dial_vless` 内部调 `receive_response`，非 `[0,0]` 一律失败）。
        outbound.stream.write_all(PAYLOAD).await.expect("写载荷");
        let mut received = vec![0u8; PAYLOAD.len()];
        timeout(WAIT, outbound.stream.read_exact(&mut received))
            .await
            .expect("读载荷超时")
            .expect("读载荷");
        assert_eq!(received, PAYLOAD, "回环载荷必须逐字节一致");
        assert_eq!(
            server_task.await.unwrap().expect("服务端"),
            PAYLOAD,
            "服务端读到的载荷必须逐字节一致"
        );
        println!(
            "VLESS+REALITY 主链路贯通：{} 字节逐字节一致",
            received.len()
        );
    })
    .await
    .expect("用例总超时");
}

/// **2. 负例**：坏 publicKey ⇒ 拨号失败。
///
/// 断言三件事：
/// - 拨号返回错误（fail-closed，不回退普通 TLS）；
/// - 错误消息不含公钥原文；
/// - **没有建立任何连接**（坏配置下连 TCP 都不拨 ⇒ 不发出任何明文）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_reality_bad_public_key_fails_closed() {
    timeout(DEADLINE, async {
        let server = Server::new();
        let (port, accepted, watcher) = accept_only_watcher().await;

        let mut node = reality_node(port, &server);
        // 破坏公钥：不是 base64 raw-url。
        node.reality.as_mut().expect("REALITY 段").public_key = "not*base64*at*all".to_owned();

        let error = dial_vless(&node, WAIT)
            .await
            .expect_err("坏 publicKey 必须失败");
        let text = error.to_string();
        assert!(text.contains("REALITY 配置非法"), "必须是配置非法：{text}");
        assert!(
            !text.contains("not*base64*at*all"),
            "错误消息不得含公钥原文：{text}"
        );

        // 截止时间内没有被 accept 到 ⇒ 坏配置下**没有**发出任何字节。
        let outcome = timeout(Duration::from_secs(2), watcher).await;
        assert!(
            outcome.is_err(),
            "坏配置下不该建立连接（已被 accept {} 次）",
            accepted.load(std::sync::atomic::Ordering::SeqCst)
        );
    })
    .await
    .expect("用例总超时");
}

/// **2b. 负例**：短 ID 非十六进制 ⇒ 同样 fail-closed。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_reality_bad_short_id_fails_closed() {
    timeout(DEADLINE, async {
        let server = Server::new();
        let (port, accepted, watcher) = accept_only_watcher().await;

        let mut node = reality_node(port, &server);
        node.reality.as_mut().expect("REALITY 段").short_id = "zz".to_owned();

        let error = dial_vless(&node, WAIT).await.expect_err("坏短 ID 必须失败");
        assert!(
            error.to_string().contains("REALITY 配置非法"),
            "必须是配置非法：{error}"
        );
        let outcome = timeout(Duration::from_secs(2), watcher).await;
        assert!(
            outcome.is_err(),
            "坏配置下不该建立连接（已被 accept {} 次）",
            accepted.load(std::sync::atomic::Ordering::SeqCst)
        );
    })
    .await
    .expect("用例总超时");
}

/// **3. 配置层**：非 vless 协议带 `reality` 段 ⇒ 加载阶段显式报错。
#[test]
fn reality_section_is_rejected_for_non_vless_protocol() {
    let value = json!([{
        "name": "trojan-with-reality",
        "protocol": "trojan",
        "endpoint": { "host": "127.0.0.1", "port": 8443 },
        "tls": { "insecure": true },
        "auth": { "password": "pw" },
        "reality": { "public_key": "AAAA", "short_id": "00" }
    }]);
    let nodes: Vec<NodeConfig> = serde_json::from_value(value).expect("反序列化应成功");
    let error = nodes[0]
        .validate()
        .expect_err("非 vless 带 reality 段必须被拒");
    assert!(
        error.to_string().contains("reality"),
        "报错应点名该配置段：{error}"
    );
}

/// **3b. 配置层**：vless 不带 `reality` 段 ⇒ 既有行为不变（校验通过）。
#[test]
fn reality_section_is_optional_for_vless() {
    let value = json!([{
        "name": "vless-plain",
        "protocol": "vless",
        "endpoint": { "host": "127.0.0.1", "port": 8443 },
        "tls": { "insecure": true },
        "auth": { "password": UUID }
    }]);
    let nodes: Vec<NodeConfig> = serde_json::from_value(value).expect("反序列化应成功");
    assert!(nodes[0].reality.is_none());
    assert!(nodes[0].validate().is_ok(), "既有配置行为不变");
}

/// **3c. 配置层**：Debug 输出不含 REALITY 凭据。
#[test]
fn reality_credentials_are_redacted_in_debug() {
    let server = Server::new();
    let node = reality_node(8443, &server);
    let text = format!("{node:?}");
    assert!(text.contains("<redacted>"), "应有脱敏占位：{text}");
    assert!(
        !text.contains(&server.public_key()),
        "Debug 输出不得含公钥：{text}"
    );
    assert!(
        !text.contains(SHORT_ID_HEX),
        "Debug 输出不得含短 ID：{text}"
    );
}

/// **3d. 配置层**：vless 带 `reality` 段但公钥与口令都空 ⇒ 显式报错。
#[test]
fn reality_section_requires_a_credential() {
    let value = json!([{
        "name": "vless-reality-empty",
        "protocol": "vless",
        "endpoint": { "host": "127.0.0.1", "port": 8443 },
        "tls": { "insecure": true },
        "auth": { "password": UUID },
        "reality": { "short_id": "00" }
    }]);
    let nodes: Vec<NodeConfig> = serde_json::from_value(value).expect("反序列化应成功");
    assert!(nodes[0].validate().is_err(), "公钥与口令都空必须被拒");
}

/// **4. 熵源可达性自检**：REALITY 服务端握手需要一个 `RngCore + CryptoRng`，
/// 本仓的 `md-5` 依赖链把它带进来了（`md5::digest::crypto_common::rand_core`）。
/// 这条断言让「熵源路径将来被裁掉」变成显式失败而不是夹具编译不过。
#[test]
fn entropy_source_is_reachable_from_node_dependencies() {
    let mut rng = OsRng;
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    assert_ne!(bytes, [0u8; 16], "系统熵源不应恒为零");
}
