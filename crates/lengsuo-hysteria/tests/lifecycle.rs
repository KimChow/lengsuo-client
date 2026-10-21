//! Hysteria 异常矩阵补缺：半关闭（half-close）与清理（cleanup）。
//!
//! 对应 `docs/audit-all1.md` §3 异常路径矩阵里 Hysteria 的两格：
//! - 「半关闭 ❌」→ `lifecycle/half_close.rs`（A 组）；
//! - 「清理 ❌」→ `lifecycle/cleanup.rs`（B 组）。
//!
//! 全部用例都是**本仓客户端 ↔ 本仓服务端**的闭环（范式照
//! `tests/rust_roundtrip.rs`）：服务端 `HysteriaServer::bind` + `accept_loop`
//! （ALPN=h3、openssl 现场自签证书进临时目录），客户端 `HysteriaClient`。
//! 这**不冒充**与官方 Xray 的互通（真实互通见 `tests/xray_hysteria*.rs`，
//! `#[ignore]`）；本卡验的是生命周期语义，不是互通。
//!
//! # 观测手段（用既有可观测点，不自造 API）
//!
//! | 观测点 | 含义 | 可观测的语义 |
//! |---|---|---|
//! | `Server::open_connections()` | `quinn::Endpoint::open_connections` | 服务端端点上的 QUIC 连接数（服务端**连接级**会话表计数） |
//! | `client.open_udp()` 的结果 | `quic/client.rs` `UdpManager.closed` | 客户端 UDP 会话表是否已被 `close_all()` **清空并关闭** |
//! | `UdpSession::recv_raw()` → `None` | 客户端 `UdpManager.sessions` 条目被丢弃 | 客户端会话表条目归零 |
//! | 目标端观察到的 UDP 源端口 | 服务端 `quic/server.rs` `UdpManager::sessions` 条目被移除后重建 | 服务端 **UDP 会话表**按条目回收（换端口=换出站 socket） |
//! | 目标 TCP 读到 EOF | 服务端 `proxy::relay` 收尾、出站 socket 释放 | 服务端 **TCP 承载**已回收 |
//! | 目标 TCP 的接入次数 | 服务端 `proxy::serve_tcp_stream_paced` | 服务端**是否**为该请求建立了出站连接（畸形帧不得放行） |
//!
//! 服务端 UDP 会话表（`quic::server::UdpManager::sessions`）是 `pub(crate)`，
//! 集成测试**读不到条目数**（客户端那份 `UdpManager.sessions` 是私有的）；
//! 故用上表**外部可观测等价物**替代，
//! 不改 `src/**`（本卡是纯测试卡）。
//!
//! 凭据/口令一律运行时生成，不落日志；回环地址 + 临时端口；
//! 每个网络操作都有 `tokio::time::timeout`；等待回收一律「轮询 + 总截止」，
//! **禁止**固定 sleep 后直接断言。

// 用例按主题拆到 `tests/lifecycle/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lengsuo_hysteria::proxy;
use lengsuo_hysteria::quic::server::{HysteriaServer, ServerConfig};
use lengsuo_hysteria::quic::{ClientConfig, ConnectError, HysteriaClient};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

// 子目录模块（`tests/lifecycle/`）：crate root 是 `tests/lifecycle.rs`，
// 裸 `mod cleanup;` 会去找 `tests/cleanup.rs`，故用 `#[path]` 显式指到
// `tests/lifecycle/cleanup.rs`。
#[path = "lifecycle/cleanup.rs"]
mod cleanup;
#[path = "lifecycle/half_close.rs"]
mod half_close;

/// 单次网络操作的上限（所有 IO 都要套 `tokio::time::timeout`）。
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(20);
/// 轮询等待「会话被回收」的总截止时间（不是单次 sleep）。
pub(crate) const RECLAIM_DEADLINE: Duration = Duration::from_secs(25);
/// 轮询间隔（只出现在轮询循环里，不用于「睡够就断言」）。
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// TLS 校验名（自签证书的 SAN 含 `DNS:localhost`）。
const SERVER_NAME: &str = "localhost";
/// 参考实现的 `closeErrCodeOK`（`transport/internet/hysteria/config.go`：
/// `0x100` = HTTP3 ErrCodeNoError）。
pub(crate) const CLOSE_ERR_CODE_OK: u32 = 0x100;

include!("lifecycle/certs.rs");
include!("lifecycle/server.rs");
include!("lifecycle/targets.rs");
include!("lifecycle/outcome.rs");
