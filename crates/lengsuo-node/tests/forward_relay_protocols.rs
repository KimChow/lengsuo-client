//! 转发层的**逐协议可转发性**验收：每个可转发协议两个用例。
//!
//! 每个协议两个用例：
//!
//! 1. **端到端转发**：本地 SOCKS5 CONNECT ⇒ 转发器 ⇒ 协议服务端 ⇒ 目标 echo
//!    ⇒ 回程载荷**逐字节一致**，且断言目标**确实被拨到**（数据真的穿过了
//!    转发器，而不是只握手成功）。
//! 2. **半关闭**：本地侧**只关写侧**（FIN）后，回程仍必须收到**完整**响应。
//!    夹具用「读到 EOF 才回内容」的延迟 echo ⇒ 响应能回来，就证明 FIN 穿过
//!    转发器到达了目标、且回程没有被提前掐断（`join!` 语义的核心）。
//!
//! 覆盖：trojan / shadowsocks（复用既有夹具）+ vless(TLS) / vless(REALITY) /
//! vmess / ss2022 / anytls / hysteria（本文件自建服务端）；外加 wireguard 的
//! **显式失败**反例（结构性不可转发 ⇒ 断开，**不得**静默直连）。
//!
//! 全部只绑回环、临时端口、假凭据；每个用例带总超时。
//!
//! **不声称与参考实现互通**：这里验证的是「本仓服务端 ↔ 本仓转发器」的端到端
//! 转发；与参考实现的互通结论见各协议 crate 的文档与 `docs/node-forward-relay.md`。

#[path = "forward_support/mod.rs"]
mod support;

#[path = "forward_relay_protocols/reality_proxy.rs"]
mod reality;

#[path = "forward_relay_protocols/servers.rs"]
mod servers;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lengsuo_node::config::NodeConfig;
use lengsuo_node::forward::{ForwardConfig, ForwardHandle, Forwarder, NodePool};
use lengsuo_node::route::RouteTable;
use servers::{
    anytls_node, anytls_server, hysteria_node, hysteria_server, ss2022_node, ss2022_server,
    vless_node, vless_tls_server, vmess_node, vmess_server, wireguard_node, ANYTLS_PASSWORD,
    HYSTERIA_PASSWORD, TEST_UUID,
};
use support::*;
use tokio::time::timeout;

/// 单用例总超时。
const TOTAL: Duration = Duration::from_secs(60);

/// 带总超时的用例包装（超时即失败，不允许挂死）。
macro_rules! case {
    ($body:block) => {
        timeout(TOTAL, async $body).await.expect("总超时")
    };
}

/// 转发器配置（测试用短超时）。
fn test_config() -> ForwardConfig {
    ForwardConfig {
        listen: "127.0.0.1:0".to_owned(),
        default_node: None,
        rules: Vec::new(),
        idle_timeout_secs: 5,
        session_timeout_secs: 10,
    }
}

/// 起一个转发器，返回（本地地址, 句柄）。
async fn start_forwarder(nodes: Vec<NodeConfig>) -> (SocketAddr, ForwardHandle) {
    let default_node = nodes
        .first()
        .map(|node| node.name.clone())
        .expect("至少一个节点");
    let routes = RouteTable::new(Vec::new(), Some(default_node)).expect("路由表");
    let forwarder = Forwarder::bind(
        "127.0.0.1:0".parse().unwrap(),
        NodePool::new(nodes),
        routes,
        test_config(),
    )
    .await
    .expect("转发器绑定");
    let addr = forwarder.local_addr().expect("转发器地址");
    let handle = forwarder.start().await.expect("转发器启动");
    (addr, handle)
}

/// 端到端断言：回程载荷逐字节一致，且目标确实被拨到。
fn assert_echoed(
    result: &Socks5Result,
    payload: &[u8],
    counter: &std::sync::atomic::AtomicUsize,
    label: &str,
) {
    match result {
        Socks5Result::Replied { rep, payload: got } => {
            assert_eq!(*rep, 0x00, "{label}：SOCKS5 回复码应为成功");
            assert_eq!(got, payload, "{label}：回程载荷必须逐字节一致");
        }
        Socks5Result::Closed { .. } => panic!("{label}：转发应成功建立会话"),
    }
    assert_eq!(
        hits(counter),
        1,
        "{label}：目标必须被拨到一次（数据真的穿过转发器）"
    );
}

/// 半关闭断言：本地只关写侧后，回程仍收到**完整**响应。
fn assert_half_closed(
    result: &Socks5Result,
    expected: &[u8],
    counter: &std::sync::atomic::AtomicUsize,
    label: &str,
) {
    match result {
        Socks5Result::Replied { rep, payload: got } => {
            assert_eq!(*rep, 0x00, "{label}：SOCKS5 回复码应为成功");
            assert_eq!(got, expected, "{label}：半关闭后回程必须仍是完整响应");
        }
        Socks5Result::Closed { payload: got } => {
            panic!("{label}：半关闭后回程必须仍是完整响应，实得 {got:?}")
        }
    }
    assert_eq!(hits(counter), 1, "{label}：目标必须被拨到一次");
}

// 用例按主题拆到 `tests/forward_relay_protocols/` 下，用 `include!` **文本并入**
// 同一模块（不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。
include!("forward_relay_protocols/cases_basic.rs");
include!("forward_relay_protocols/cases_extra.rs");
