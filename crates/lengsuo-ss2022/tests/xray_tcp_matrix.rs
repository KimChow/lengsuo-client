//! SS2022 TCP 三算法双向矩阵与半关闭/异常路径验收（仅回环、测试专用假密钥）。
//!
//! 三套件 `2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` /
//! `2022-blake3-chacha20-poly1305` × 两方向（Rust 客户端→Xray 服务端；Xray 客户端
//! SOCKS→Rust 服务端）× 载荷 1 / 4096 / 262144 字节，逐字节回比较；每个单元格记录
//! **首个 SS2022 写块长度**（请求开场 salt+固定头+变长头，方向一由本 crate 写出、方向二
//! 由计数读端实测）与**请求/响应载荷 chunk 数**。
//!
//! 半关闭两项：客户端 `shutdown(Write)` 后仍按有限超时读到完整响应；Rust 服务端写完
//! 即释放连接，Xray 客户端读端在有限超时内拿到 EOF（0 字节）而非悬挂。
//!
//! 异常路径四项判据全部针对本 crate 接收侧 [`Reader`]/[`SessionReplay`] 语义，纯 Rust
//! 原语即可判定，不依赖 Xray：错误 PSK 报 [`Error::Authentication`]、截断头报
//! [`Error::Length`]、篡改 AEAD tag 报 [`Error::Authentication`]、同 salt 二次开场报
//! [`Error::Replay`]；每项都注有限超时。文件随参考套件一起以 `--ignored` 运行。

// 复用 `reverse_support` 时本文件只用到其中一部分，其余辅助函数自然成为死代码。
#![allow(dead_code)]

mod reverse_support;
#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;

use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::{
    crypto::{Key, Method},
    tcp::{
        receive::clock_at, Association, Direction, Reader, SessionReplay, Writer, MAX_CHUNK_PAYLOAD,
    },
    Error,
};
use reverse_support::*;
use serde_json::json;
use ss_core::target::TargetAddr;
use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 三套件矩阵（含 ChaCha20；`reverse_support::methods` 只到 AES-256）。
fn matrix_methods() -> [(Method, &'static str); 3] {
    [
        (Method::Aes128, "2022-blake3-aes-128-gcm"),
        (Method::Aes256, "2022-blake3-aes-256-gcm"),
        (Method::ChaCha20, "2022-blake3-chacha20-poly1305"),
    ]
}

/// 载荷规格：1、4096、262144（跨多个 65535 上限 chunk）。
fn matrix_sizes() -> [usize; 3] {
    [1, 4096, 262_144]
}

fn server_config(port: u16, method: &str, psk: &[u8]) -> serde_json::Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"shadowsocks",
            "settings":{"method":method,"password":STANDARD.encode(psk),"network":"tcp"}}],
        "outbounds":[{"protocol":"freedom"}]})
}

fn xray_client_config(port: u16, rust_port: u16, method: &str, psk: &[u8]) -> serde_json::Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"socks",
            "settings":{"auth":"noauth","udp":false}}],
        "outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{
            "address":"127.0.0.1","port":rust_port,"method":method,
            "password":STANDARD.encode(psk)}]}}]})
}

// 用例按主题拆到 `tests/xray_tcp_matrix/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致（`mod`
// 方案会把名字变成 `matrix::xxx` 等，属于改名）。代价是分文件之间不能重复
// `use`，故所有 `use` 都留在本入口文件。
//
// ⚠️ `mod reverse_support;` 与 `#[path]` 的 `mod support;` **必须留在本入口
// 文件**：`#[path]` 是相对本文件所在目录解析的，搬到子目录后相对路径要改成
// `../../../lengsuo-trojan/...`，属于跨 crate 引用的易错点。留在入口文件则
// 路径一字不改。
// ⚠️ 文件级 `#![allow(dead_code)]` 同理必须留在入口文件：它是**测试目标根**
// 属性，对根下所有模块（含 `reverse_support`）生效；子文件里放不下内层属性
// （`include!` 的文本位置不允许 inner attribute）。
include!("xray_tcp_matrix/common.rs");
include!("xray_tcp_matrix/matrix.rs");
include!("xray_tcp_matrix/half_close.rs");
include!("xray_tcp_matrix/abnormal.rs");
