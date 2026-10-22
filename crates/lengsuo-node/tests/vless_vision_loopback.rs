//! VLESS Vision 接进 node 出站产品路径的**实跑取证**（Rust↔Rust 回环）。
//!
//! 对端是**本仓**的 Vision 服务端（`lengsuo_vless::vision::server::VisionServer`，
//! 编排见 `vless_vision_loopback/support.rs`），客户端是 **node 的 VLESS 出口**
//! （`lengsuo_node::outbound_vless::dial_vless`，走新加的 `vision` 配置段）。
//!
//! ```text
//! node 侧：NodeConfig.vision → VisionStream（流量层）→ VLESS 请求头 + 首块
//!        → 等成功响应头 → 载荷往返
//! 服务端：TLS → 解 VLESS 请求头 → 写响应头 → VisionServer 解上行块 → 回环写下行块
//! ```
//!
//! 覆盖六组：
//! 1. **正例**：握手成功 + 收到成功响应头 + 载荷往返逐字节一致（纯流量层）。
//! 2. **记录层正例**：`encryption` 段开启 ⇒ 上下行走 AEAD 记录层，载荷逐字节一致。
//! 3. **负例**：错 UUID ⇒ 服务端拒绝（不断回成功响应头）⇒ 拨号失败（fail-closed）。
//! 4. **负例**：记录层密钥材料非法 ⇒ 拨号失败，且**一条字节都不发**。
//! 5. **配置层**：未知 `flow` / 未知 `cipher` / 非 vless 协议带该段 ⇒ 显式报错。
//! 6. **脱敏**：Debug 输出不含记录层密钥材料。
//!
//! **本文件只覆盖 Rust↔Rust 回环**，⛔ 不声称与参考实现互通。参考侧（固定版本
//! Xray）在**库层**已有真实对端证据（`crates/lengsuo-vless/tests/xray_vision.rs`）；
//! **node 侧**与参考对端的互通**尚未验证**（见本卡报告偏离清单）。

#[path = "vless_vision_loopback/support.rs"]
mod support;

use std::time::Duration;

use lengsuo_node::config::NodeConfig;
use lengsuo_node::outbound_vless::dial_vless;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use support::{
    accept_only_watcher, record_config, vision_node, vision_server_fixture, DEADLINE, KEY, PAYLOAD,
    RECORD_CTX, RECORD_KEY_HEX, WAIT,
};

/// **1. 正例**：node 的 VLESS 出口经 Vision 流量层连上本仓 Vision 服务端，
/// 握手成功、收到成功响应头、载荷往返逐字节一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_vision_roundtrip_to_own_server() {
    timeout(DEADLINE, async {
        let fixture = vision_server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vision_node(port, &ca_pem, None);
        assert!(node.validate().is_ok(), "配置应通过校验");

        let (client, server) = tokio::join!(
            async {
                let mut outbound = dial_vless(&node, WAIT)
                    .await
                    .expect("Vision 建流 + 握手应成功");
                outbound.stream.write_all(PAYLOAD).await.expect("写载荷");
                let mut received = vec![0u8; PAYLOAD.len()];
                timeout(WAIT, outbound.stream.read_exact(&mut received))
                    .await
                    .expect("读载荷超时")
                    .expect("读载荷");
                received
            },
            support::serve_vision(fixture, KEY, None),
        );
        assert_eq!(client, PAYLOAD, "回环载荷必须逐字节一致");
        assert_eq!(
            server.expect("服务端"),
            PAYLOAD,
            "服务端解出的上行明文必须逐字节一致"
        );
        println!("VLESS+Vision 流量层贯通：{} 字节逐字节一致", client.len());
    })
    .await
    .expect("用例总超时");
}

/// **2. 记录层正例**：`encryption` 段开启 ⇒ 上下行都走 AEAD 记录层。
///
/// 记录层的密钥由配置给出（**偏离**：参考走 ML-KEM 会话握手，本仓没有 ML-KEM）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_vision_with_record_layer_roundtrips() {
    timeout(DEADLINE, async {
        let fixture = vision_server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vision_node(
            port,
            &ca_pem,
            Some(("aes-256-gcm", RECORD_CTX, RECORD_KEY_HEX)),
        );
        assert!(node.validate().is_ok(), "配置应通过校验");

        let server_config = record_config("aes-256-gcm", RECORD_CTX, RECORD_KEY_HEX);
        let (client, server) = tokio::join!(
            async {
                let mut outbound = dial_vless(&node, WAIT)
                    .await
                    .expect("Vision + 记录层建流 + 握手应成功");
                outbound.stream.write_all(PAYLOAD).await.expect("写载荷");
                let mut received = vec![0u8; PAYLOAD.len()];
                timeout(WAIT, outbound.stream.read_exact(&mut received))
                    .await
                    .expect("读载荷超时")
                    .expect("读载荷");
                received
            },
            support::serve_vision(fixture, KEY, Some(server_config)),
        );
        assert_eq!(client, PAYLOAD, "回环载荷必须逐字节一致");
        assert_eq!(
            server.expect("服务端"),
            PAYLOAD,
            "服务端解出的上行明文必须逐字节一致"
        );
        println!("VLESS+Vision+记录层贯通：{} 字节逐字节一致", client.len());
    })
    .await
    .expect("用例总超时");
}

/// **3. 负例**：错 UUID ⇒ 服务端拒绝 ⇒ 拨号失败（fail-closed）。
///
/// 服务端用**另一个** UUID ⇒ 请求头里的 UUID 与服务端不符 ⇒ 服务端断开、
/// **不**回成功响应头 ⇒ node 侧拨号必须失败，且**不得**把没认证的连接交出去。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_vision_wrong_uuid_fails_closed() {
    timeout(DEADLINE, async {
        let fixture = vision_server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vision_node(port, &ca_pem, None);

        let (result, server) = tokio::join!(
            async { dial_vless(&node, WAIT).await.map(|_| ()) },
            support::serve_vision(fixture, [0x77; 16], None),
        );
        let error = result.expect_err("错 UUID 必须失败");
        let text = error.to_string();
        assert!(
            text.contains("vision") || text.contains("响应头"),
            "错误应点名 vision 失败原因：{text}"
        );
        // 服务端侧：因 UUID 不匹配而拒绝。
        assert!(server.is_err(), "服务端必须拒绝");
    })
    .await
    .expect("用例总超时");
}

/// **4. 负例**：记录层的密钥材料非法（奇数长度十六进制）⇒ 拨号失败（fail-closed）。
///
/// 判据：记录层构造失败 ⇒ **一条字节都不发**（连 TCP 都不拨）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_vision_bad_record_key_fails_closed() {
    timeout(DEADLINE, async {
        let (port, accepted, watcher) = accept_only_watcher().await;
        // 奇数长度的十六进制 ⇒ 解码失败。
        let node = vision_node(port, "", Some(("aes-256-gcm", "ctx", "abc")));

        let error = dial_vless(&node, WAIT).await.expect_err("坏 key 必须失败");
        assert!(
            error.to_string().contains("vision"),
            "错误应点名 vision 配置非法：{error}"
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

/// **5. 配置层**：未知 `flow` ⇒ 显式报错（fail-closed，不静默退回无流量层路径）。
#[test]
fn unknown_vision_flow_is_rejected() {
    let value = json!([{
        "name": "vless-vision-bad-flow",
        "protocol": "vless",
        "endpoint": { "host": "127.0.0.1", "port": 8443 },
        "tls": { "insecure": true },
        "auth": { "password": support::UUID },
        "vision": { "flow": "xtls-rprx-direct" }
    }]);
    let nodes: Vec<NodeConfig> = serde_json::from_value(value).expect("反序列化应成功");
    let error = nodes[0].validate().expect_err("未知 flow 必须被拒");
    assert!(
        error.to_string().contains("flow"),
        "报错应点名 flow：{error}"
    );
}

/// **4b. 负例**：未知 `flow` 且**未走** `validate()` ⇒ 拨号仍必须失败，
/// ⛔ 不得静默退回「无流量层」路径；且**一条字节都不发**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_vision_unknown_flow_fails_closed_without_connect() {
    timeout(DEADLINE, async {
        let (port, accepted, watcher) = accept_only_watcher().await;
        let value = json!([{
            "name": "vless-vision-unvalidated-flow",
            "protocol": "vless",
            "endpoint": { "host": "127.0.0.1", "port": port },
            "tls": { "insecure": true },
            "auth": { "password": support::UUID },
            "vision": { "flow": "xtls-rprx-direct" }
        }]);
        let nodes: Vec<NodeConfig> = serde_json::from_value(value).expect("反序列化应成功");
        let node = nodes.into_iter().next().expect("恰好一个节点");

        let error = dial_vless(&node, WAIT)
            .await
            .expect_err("未校验的未知 flow 也必须失败");
        assert!(
            error.to_string().contains("flow"),
            "错误应点名 flow：{error}"
        );
        let outcome = timeout(Duration::from_secs(2), watcher).await;
        assert!(
            outcome.is_err(),
            "未知 flow 下不该建立连接（已被 accept {} 次）",
            accepted.load(std::sync::atomic::Ordering::SeqCst)
        );
    })
    .await
    .expect("用例总超时");
}

/// **5b. 配置层**：未知 `cipher` ⇒ 显式报错（fail-closed，不静默退回明文路径）。
#[test]
fn unknown_encryption_cipher_is_rejected() {
    let value = json!([{
        "name": "vless-vision-bad-cipher",
        "protocol": "vless",
        "endpoint": { "host": "127.0.0.1", "port": 8443 },
        "tls": { "insecure": true },
        "auth": { "password": support::UUID },
        "encryption": { "cipher": "rc4", "ctx": "c", "key": "00" }
    }]);
    let nodes: Vec<NodeConfig> = serde_json::from_value(value).expect("反序列化应成功");
    let error = nodes[0].validate().expect_err("未知 cipher 必须被拒");
    assert!(
        error.to_string().contains("cipher"),
        "报错应点名 cipher：{error}"
    );
}

/// **5c. 配置层**：非 vless 协议带 `vision` 段 ⇒ 显式报错（不静默忽略）。
#[test]
fn vision_section_is_rejected_for_non_vless_protocol() {
    let value = json!([{
        "name": "trojan-with-vision",
        "protocol": "trojan",
        "endpoint": { "host": "127.0.0.1", "port": 8443 },
        "tls": { "insecure": true },
        "auth": { "password": "pw" },
        "vision": { "flow": "xtls-rprx-vision" }
    }]);
    let nodes: Vec<NodeConfig> = serde_json::from_value(value).expect("反序列化应成功");
    let error = nodes[0]
        .validate()
        .expect_err("非 vless 带 vision 段必须被拒");
    assert!(
        error.to_string().contains("vision"),
        "报错应点名该配置段：{error}"
    );
}

/// **5d. 配置层**：vless 不带 `vision` 段 ⇒ 既有行为不变（校验通过）。
#[test]
fn vision_section_is_optional_for_vless() {
    let value = json!([{
        "name": "vless-plain",
        "protocol": "vless",
        "endpoint": { "host": "127.0.0.1", "port": 8443 },
        "tls": { "insecure": true },
        "auth": { "password": support::UUID }
    }]);
    let nodes: Vec<NodeConfig> = serde_json::from_value(value).expect("反序列化应成功");
    assert!(nodes[0].vision.is_none());
    assert!(nodes[0].validate().is_ok(), "既有配置行为不变");
}

/// **6. 脱敏**：Debug 输出不含记录层密钥材料。
#[test]
fn encryption_key_is_redacted_in_debug() {
    let node = vision_node(8443, "", Some(("aes-256-gcm", "ctx", RECORD_KEY_HEX)));
    let text = format!("{node:?}");
    assert!(text.contains("<redacted>"), "应有脱敏占位：{text}");
    assert!(
        !text.contains(RECORD_KEY_HEX),
        "Debug 输出不得含密钥材料：{text}"
    );
}
