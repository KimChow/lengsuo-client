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
//! ⚠️ **公网地址在本 VPS 上不可拨号**（2026-10-22 实测，见
//! `docs/ss2022-vps-reassembly.md`）：该 VPS 的云安全组只放行 TCP
//! {22, 80, 8443}，25001 从实例外一律被丢弃，**VPS 自己经公网 IP 回连
//! 25001 同样被丢弃**（回连包在出方向被 NAT 成公网源地址，入方向同样被安全组
//! 丢弃）。⇒ 路径 B 的传输跳（VPS 内 anytls-server → 参考 Xray SS2022 入站）
//! 只能走 **VPS 回环**。因此 `SS2022_VPS_RELAY` 仍按「运营者看到的公网地址」
//! 填写，拨号目标由 [`vps_relay_dial_target`] 按「同端口 + 回环」推导；
//! 入站确实在另一台机器上时用 `SS2022_VPS_RELAY_TARGET` 原样覆盖。
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
//! - `SS2022_VPS_RELAY`：VPS 上参考 Xray SS2022 入站的 `host:port`（**公网地址**，
//!   运营者看到的那个）。拨号目标由 [`vps_relay_dial_target`] 推导，见上。
//! - `SS2022_VPS_RELAY_TARGET`：可选。原样覆盖路径 B 的拨号目标（VPS 可直连的
//!   `host:port`）。仅当参考入站**不在** VPS 上时才需要。
//! - `SS2022_LOCAL_INBOUND`：可选。本机参考 Xray SS2022 入站地址（默认回环
//!   25002）。用来把纯 Python TCP 中继插在仓库原语与本机入站之间抓原始字节。
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
/// 路径 B 传输跳的 VPS 回环主机（参考入站与 VPS 上的 anytls-server 同机）。
const VPS_LOOPBACK: &str = "127.0.0.1";
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

/// 本机参考 Xray SS2022 入站地址：仓外注入（`SS2022_LOCAL_INBOUND`），默认回环。
///
/// 注入点用来把**纯 Python TCP 中继**插在仓库原语与本机参考入站之间，抓路径 A
/// 的原始线上字节（见 `docs/ss2022-vps-reassembly.md`）。
fn local_ss2022_inbound() -> String {
    std::env::var("SS2022_LOCAL_INBOUND").unwrap_or_else(|_| LOCAL_SS2022_INBOUND.to_string())
}

/// 路径 B 的传输跳**实际拨号地址**（VPS 内的 anytls-server 拨的号）。
///
/// `SS2022_VPS_RELAY` 是运营者看到的**公网地址**；但拨号发生在 **VPS 内**，
/// 而该 VPS 的云安全组只放行 TCP {22, 80, 8443} —— 25001 从实例外被丢弃，
/// **VPS 自己经公网 IP 回连 25001 也被丢弃** ⇒ 公网地址不可拨号。
/// 参考 Xray SS2022 入站与 VPS 上的 anytls-server 同机 ⇒ 拨号目标取
/// 「同端口 + VPS 回环」。
///
/// `SS2022_VPS_RELAY_TARGET` 原样覆盖（仅当参考入站确实不在 VPS 上时才需要）。
fn vps_relay_dial_target() -> Option<String> {
    let relay = vps_relay()?;
    if let Ok(explicit) = std::env::var("SS2022_VPS_RELAY_TARGET") {
        if !explicit.is_empty() {
            return Some(explicit);
        }
    }
    let (host, port) = relay.rsplit_once(':')?;
    if matches!(
        host.parse::<std::net::IpAddr>(),
        Ok(ip) if ip.is_loopback()
    ) {
        return Some(relay);
    }
    Some(format!("{VPS_LOOPBACK}:{port}"))
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
