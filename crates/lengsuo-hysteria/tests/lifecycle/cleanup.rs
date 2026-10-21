//! B 组：清理（cleanup）—— 对应 `docs/audit-all1.md` §3 矩阵的
//! 「清理」格（原为 ❌：只有「错误/debug 不泄漏」，无会话回收）。
//!
//! 语义基线（参考实现）：
//! - `transport/internet/hysteria/hub.go` `udpSessionManagerServer.run()`：
//!   QUIC 连接读错误 ⇒ `break` ⇒ `close(m.stopCh)` ⇒ **关闭全部 UDP 会话**
//!   （`close()` 里 `close(udpConn.ch)` + `delete(m.m, udpConn.id)`）。
//! - 同文件 `clean()`：每 `idleCleanupInterval`（参考 1s）扫一次表，
//!   超过 `udpIdleTimeout` 未活跃的会话被 `close()`（**按条目**回收）。
//! - `transport/internet/hysteria/dialer.go` `udpSessionManagerClient.run()`：
//!   客户端侧同样在连接断开时 `m.closed = true` + 关闭全部会话；
//!   `udp()` 在 `m.closed` 时返回 `errors.New("closed")`。
//! - `proxy/hysteria/server.go`：TCP 承载交给 `DispatchLink`，连接关闭时
//!   `buf.Copy` 读到 EOF ⇒ 出站连接被 `defer conn.Close()` 释放。
//!
//! 本仓对应实现：`quic::server::run_udp_manager`（连接错误 ⇒ `close_all()`
//! 清空 `sessions`）、`quic::server::UdpManager::clean`（空闲按条目回收）、
//! `quic::client` 的 `UdpManager::close_all`（客户端侧清空 + `closed`）、
//! `proxy::relay`（承载收尾 ⇒ 出站 socket 释放）。
//!
//! # 客户端会话表的「归零」判据
//!
//! 客户端 `UdpManager`（`quic/client.rs`）的 `sessions` 是私有字段，集成
//! 测试读不到条目数；但 `close_all()` 是**唯一**把 `closed` 置真的地方，
//! 且它与 `sessions.clear()` 在同一临界区内完成 ⇒
//! **`open_udp()` 返回 `Err(LocallyClosed)` ⟺ 表已被清空**。
//! 再配合「已开出的会话 `recv_raw()` 返回 `None`」（该条目的 sender 已被
//! 丢弃）⇒ 逐条证据 + 整体证据都齐。

// 用例按主题拆到 `tests/lifecycle/cleanup/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

use super::{
    client_udp_table, connect_with, pattern, spawn_tcp_target, spawn_udp_target, start_server,
    wait_until, ClientUdpTable, TargetEvent, TargetScript, IO_TIMEOUT, POLL_INTERVAL,
    RECLAIM_DEADLINE,
};
use std::time::Duration;

use lengsuo_hysteria::proxy;

include!("cleanup/disconnect.rs");
include!("cleanup/malformed.rs");
include!("cleanup/table.rs");
include!("cleanup/idle.rs");
include!("cleanup/leak.rs");
