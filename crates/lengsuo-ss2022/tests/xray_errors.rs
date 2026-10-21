//! SS2022 UDP 错误路径与重放的真实 Xray 参考验收（仅回环、测试专用假密钥）。
//!
//! 判据统一为「是否抵达回环目标」：本测试自己实现的那一段中继（Rust 侧认证解密后
//! 才向目标 UDP 套接字转发）就是交付点；错误密钥与篡改必须在交付点之前失败，同一
//! 密文重放不得产生第二次交付。
//!
//! 固定参考：Xray v26.3.27 / d2758a0。`proxy/shadowsocks_2022/inbound.go` 把 UDP
//! 报文交给 sing-shadowsocks `shadowaead_2022` 服务，`proxy/shadowsocks_2022/outbound.go`
//! 是出站方向。本文件不主张 TCP 方向结论，也不把内部窗口测试当作参考互通证据。

#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::{
    crypto::{Key, Method},
    packet::Sender,
    receiver::{Clock, Receiver},
    Error,
};
use serde_json::json;
use ss_core::target::TargetAddr;
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::*;
use tokio::{net::UdpSocket, time::timeout};

/// 判定「不再抵达」的静默窗口：大于参考端正常送达耗时，避免把慢速误判成拒绝。
const SETTLE: Duration = Duration::from_millis(1500);
/// 整体预算：多次 Xray 启动与若干静默窗口的上限。
const BUDGET: Duration = Duration::from_secs(120);
const METHOD: Method = Method::Aes256;
const NAME: &str = "2022-blake3-aes-256-gcm";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn clock() -> Clock {
    Clock {
        unix_seconds: now(),
        monotonic: Instant::now(),
    }
}
/// 测试假密钥：只按填充字节区分，与任何生产密钥无关。
fn psk(byte: u8) -> Vec<u8> {
    vec![byte; METHOD.key_len()]
}
fn key(byte: u8) -> Key {
    Key::new(METHOD, &psk(byte)).expect("假密钥长度应合法")
}
fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)
}

/// `Decoded` 故意不实现 `Debug`（载荷不得进日志），因此不能直接 `expect_err`。
/// 成功即 panic，失败交出错误。
fn rejected(outcome: Result<lengsuo_ss2022::packet::Decoded, Error>, what: &str) -> Error {
    match outcome {
        Ok(_) => panic!("{what}：必须失败却返回了已解密的报文"),
        Err(error) => error,
    }
}

/// 取回 `within` 内抵达目标的全部数据报；窗口到点即停，绝不无限读取。
async fn arrivals(target: &UdpSocket, within: Duration) -> Vec<Vec<u8>> {
    let mut got: Vec<Vec<u8>> = Vec::new();
    let mut buffer = [0u8; 2048];
    while got.len() < 8 {
        match timeout(within, target.recv_from(&mut buffer)).await {
            Ok(Ok((length, _peer))) => got.push(buffer[..length].to_vec()),
            _ => break,
        }
    }
    got
}

/// 已连接参考入站的客户端套接字。
async fn client(port: u16) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(loopback(port)).await.unwrap();
    socket
}

/// Xray SS2022 服务端入站（tcp,udp）+ freedom 出站。
fn server_config(port: u16, byte: u8) -> serde_json::Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"shadowsocks",
            "settings":{"method":NAME,"password":STANDARD.encode(psk(byte)),"network":"tcp,udp"}}],
        "outbounds":[{"protocol":"freedom"}]})
}

/// Xray dokodemo-door(目标) → SS2022 出站 → Rust 监听端口。
fn xray_client_config(port: u16, target_port: u16, rust_port: u16, byte: u8) -> serde_json::Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"dokodemo-door",
            "settings":{"address":"127.0.0.1","port":target_port,"network":"tcp,udp"}}],
        "outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{
            "address":"127.0.0.1","port":rust_port,"method":NAME,
            "password":STANDARD.encode(psk(byte))}]}}]})
}

// 用例按方向拆到 `tests/xray_errors/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致（`mod`
// 方案会把名字变成 `cases::xxx` 等，属于改名）。代价是分文件之间不能重复
// `use`，故所有 `use` 都留在本入口文件。
//
// ⚠️ `mod support;` 及其 `#[path]` **必须留在本入口文件**：`#[path]` 是相对本文件
// 目录解析的，搬到子目录后相对路径要改成 `../../../lengsuo-trojan/...`，属于
// 跨 crate 引用的易错点。留在入口文件则路径一字不改。
include!("xray_errors/cases.rs");
