//! 公网真实流量重组取证：SS2022 原语 → anytls TLS 隧道 → 公网 → VPS。
//!
//! 与 `vps_tcp.rs` 的分工：后者只断言「读到真实公网 SSH banner」，本文件断言
//! **回程重组后的字节流与发出载荷逐字节相等**，覆盖重组（跨 SS2022 chunk、跨 TCP
//! 分片）而不是只读首片，并逐档留证。
//!
//! 两条公网路径跑同一套逐档断言：
//! - [`Transport::LocalXray`]：本仓原语 → 本机 Xray SS2022 入站（回环）→ socks →
//!   anytls-client → **anytls TLS 隧道（公网）** → VPS anytls-server → VPS 回显服务。
//!   载荷字节经公网传输，对端是参考 Xray SS2022 服务端。
//! - [`Transport::VpsReference`]：本仓原语 → 本机 socks → anytls-client → **anytls
//!   TLS 隧道（公网）** → VPS anytls-server → **VPS 参考 Xray SS2022 入站** → VPS
//!   回显服务。此路径上**本仓 SS2022 线上字节本身全程经公网传输**，且由参考 Xray
//!   SS2022 服务端收发。
//!
//! ⚠️ anytls 的 SOCKS5 目标地址是**在 VPS 一侧**解析的（参考
//! `anytls-go/cmd/server/outbound_tcp.go`：`proxyOutboundTCP` 用
//! `SystemDialer.DialContext` 直连 `destination.String()`），因此路径 B 的中继
//! 地址必须写成 VPS 能自己解析到的形式（回环地址）。
//!
//! 参考对齐（`sing-shadowsocks` 参考树，commit 33d5391）：
//! - `shadowaead_2022/protocol.go`：`MaxPacketSize = 65535`，写侧按此切分 ⇒ 大档位
//!   的回程必然跨多个 SS2022 chunk，验证的是「重组」而不是「读首片」。
//! - `shadowaead_2022/service.go`：`serverConn.writeResponse` 把响应固定头与首批载荷
//!   合并，响应方向没有变长头；本 crate 的 `Reader::open` 按此解析。
//! - `shadowaead/aead.go`：`Reader.Read` 单次只取一个 chunk 的内容并缓存余量 ⇒
//!   重组由调用方按 chunk 边界累积。
//!
//! 运行前提（仓外注入；仓内不写真实公网地址、主机绝对路径与真实凭据）：
//! - `SS2022_VPS=1`：显式开启公网用例（未设置时默认跳过，CI 默认套件不跑）。
//! - `SS2022_ECHO_TARGET`：VPS 侧回显服务 `host:port`（默认 `127.0.0.1:9000`）。
//! - `SS2022_VPS_RELAY`：VPS 上参考 Xray SS2022 入站的 `host:port`（公网地址）。
//! - `SS2022_PSK_BYTES`：口令原始字节，逗号分隔十进制（默认假口令 16×0x11）。
use lengsuo_ss2022::crypto::{Key, Method};
use lengsuo_ss2022::tcp::receive::clock_at;
use lengsuo_ss2022::tcp::{Direction, Reader, SessionReplay, Writer};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// 本机 Xray SS2022 入站（回环）；其出站是 socks → anytls-client → 公网。
const LOCAL_SS2022_INBOUND: &str = "127.0.0.1:25002";
/// 本机 anytls-client 的 socks5 入口（回环）；出站是 anytls TLS 隧道 → 公网。
const LOCAL_SOCKS5: &str = "127.0.0.1:31080";
/// 单条用例总超时（秒）：覆盖全部载荷档位。
const CASE_TIMEOUT_SECS: u64 = 240;
/// 单次 chunk 读超时（秒）。
const READ_TIMEOUT_SECS: u64 = 30;
/// 变长头 padding 长度（字节）：SIP022 允许 0..=900。
const HEADER_PADDING: u16 = 8;
/// 单个载荷 chunk 上限（SIP022 `MaxPacketSize = 65535`）。
const CHUNK_MAX: usize = 65535;
/// 逐档载荷长度（字节）。末档 131071 = 65535×2+1，必然跨多个 SS2022 chunk 与
/// 多个 TCP 分片。
const SIZE_LADDER: [usize; 6] = [1, 64, 1024, 8192, 65535, 131_071];

/// 公网链路开关：必须显式 `SS2022_VPS=1`。
fn public_link_enabled() -> bool {
    std::env::var("SS2022_VPS").as_deref() == Ok("1")
}

/// VPS 侧回显服务地址（`host:port`），仓外注入。
fn echo_target() -> String {
    std::env::var("SS2022_ECHO_TARGET").unwrap_or_else(|_| "127.0.0.1:9000".to_string())
}

/// VPS 上参考 Xray SS2022 入站地址（`host:port`），仓外注入。
fn vps_relay() -> Option<String> {
    std::env::var("SS2022_VPS_RELAY")
        .ok()
        .filter(|v| !v.is_empty())
}

/// 口令原始字节：仓外注入，缺省用仓内假口令（16×0x11）。
fn psk_bytes() -> Vec<u8> {
    match std::env::var("SS2022_PSK_BYTES") {
        Ok(raw) => raw
            .split(',')
            .filter_map(|part| part.trim().parse::<u8>().ok())
            .collect(),
        Err(_) => vec![0x11; 16],
    }
}

/// 把 `host:port` 解析成目标地址；IPv4 字面量走 `TargetAddr::V4`，其余走域名。
fn parse_target(spec: &str) -> ss_core::target::TargetAddr {
    let (host, port) = spec.rsplit_once(':').expect("目标必须是 host:port");
    let port: u16 = port.parse().expect("端口必须是 u16");
    match host.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => ss_core::target::TargetAddr::V4(ip.octets(), port),
        Err(_) => ss_core::target::TargetAddr::Domain(host.to_string(), port),
    }
}

// 用例按职责拆到 `tests/vps_reassembly/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致（`mod`
// 方案会把名字变成 `cases::xxx` 等，属于改名）。代价是分文件之间不能重复
// `use`，故所有 `use` 都留在本入口文件。
include!("vps_reassembly/session.rs");
include!("vps_reassembly/cases.rs");
