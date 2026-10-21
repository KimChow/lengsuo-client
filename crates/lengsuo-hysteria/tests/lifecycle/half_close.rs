//! A 组：半关闭（half-close）—— 对应 `docs/audit-all1.md` §3 矩阵的
//! 「半关闭」格（原为 ❌）。
//!
//! 语义基线（参考实现）：
//! - `transport/internet/hysteria/conn.go` `interConn.Close()` =
//!   `stream.CancelRead(0)` + `stream.Close()`；`interConn.Write` 走
//!   `quic.Stream.Write`（**不**带 FIN 语义），半关闭由 QUIC 流的
//!   **FIN 帧**表达（quic-go 的 `stream.Close()` 发 FIN）。
//! - `proxy/hysteria/client.go` 的 TCP 分支用 `buf.Copy` 双向中继；
//!   `common/buf/copy.go` 的 `Copy` 在读到 `io.EOF` 时**正常返回 nil**
//!   ⇒ 读方向的 EOF 是**干净 EOF**，不是错误。
//! - `proxy/hysteria/server.go` 的 TCP 分支把 `interConn` 直接交给
//!   `dispatcher.DispatchLink`（`Reader: buf.NewReader(conn)`）⇒ 服务端
//!   读到客户端 FIN 后，读方向返回 EOF。
//!
//! 本仓对应实现：`proxy::TcpProxyStream::finish()`（发送侧 FIN，
//! 对齐 `interConn.Close` 的发送半边）与 `proxy::relay`（服务端把 QUIC
//! 流的 EOF 转成出站 TCP 的 `shutdown(Write)` ⇒ 目标读到干净 EOF）。
//!
//! ⚠️ 关键区分（任务书点名）：**「EOF 且缓冲空」是干净 EOF（`Ok(0)` /
//! `Ok(None)`）；「EOF 且残留半帧」才是协议错误**。本组用例逐条区分这两者。

// 用例按主题拆到 `tests/lifecycle/half_close/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

use super::{
    client_udp_table, connect_with, pattern, spawn_tcp_target, spawn_udp_target, start_server,
    wait_until, ClientUdpTable, TargetEvent, TargetScript, IO_TIMEOUT, RECLAIM_DEADLINE,
};
use lengsuo_hysteria::proxy;
use lengsuo_hysteria::tcp::{Status, TcpResponse};

include!("half_close/direction.rs");
include!("half_close/eof.rs");
include!("half_close/reuse.rs");
