//! UDP-over-TCP（v2）**服务端承载**的端到端用例。
//!
//! 覆盖本卡 `crates/lengsuo-anytls/src/server/udp.rs` 的接线：
//! - 正向：本仓服务端 ↔ 本仓客户端，UDP 报文经 UoT 会话往返，载荷逐字节一致；
//! - 地址族三态：IPv4（`0x00`）/ IPv6（`0x01`）/ FQDN（`0x02`）各一条；
//! - 非法地址族 fail-closed：`0x03` / `0x04` / 越界值一律拒绝，
//!   **不得**回落成「按 SOCKS5 解析」，**不得**回落成 TCP 拨号；
//! - 魔数与版本不符 ⇒ 拒绝（**不得**当普通 PUSH 处理）；
//! - 异常路径：截断的 UDP 帧、篡改的目标地址、超长域名 ⇒ fail-closed，
//!   **不得**静默直连、**不得**回落成 TCP 拨号。
//!
//! ## 参考基线
//!
//! anytls-go fd6167a `cmd/server/inbound_tcp.go`（魔法域分派）、
//! `cmd/server/outbound_tcp.go::proxyOutboundUoT`（`uot.ReadRequest` →
//! `net.ListenPacket("udp","")` → `ReportHandshakeSuccess` → `CopyPacketConn`）、
//! sing v0.5.1 `common/uot`（`Request{IsConnect, Destination}`、`AddrParser`）。
//!
//! ## 用例装配
//!
//! 用例按主题拆到 `tests/udp_over_tcp_server/` 下，用 `include!` **文本并入**同一模块
//! （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
//! 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。
//!
//! - `harness.rs`：客户端半、报文编解码助手、探针（TCP 监听 + UDP 套接字）。
//! - `families.rs`：地址族三态 + connect 模式往返。
//! - `rejections.rs`：非法地址族 / 魔数版本不符 / 异常路径。
//! - `interop.rs`：`#[ignore]` 的官方 anytls-client 互通用例。
//!
//! ⚠️ 本组用例**只做本仓自环**；与官方 anytls-client 的互通见 `interop.rs`，
//! 状态以该文件里的实跑结论为准，**不拿自环冒充参考互通**。

use lengsuo_anytls::{
    auth::Credential,
    frame::{Command, Frame},
    padding::PaddingScheme,
    server::{self, ServerConfig},
    stream::{
        socks::SocksAddr, Address, Association, Datagram, StreamError, UdpVersion, UotRequest,
        MAGIC_ADDRESS_V1, MAGIC_ADDRESS_V2,
    },
    Error,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

include!("udp_over_tcp_server/harness.rs");
include!("udp_over_tcp_server/families.rs");
include!("udp_over_tcp_server/rejections.rs");
include!("udp_over_tcp_server/interop.rs");
