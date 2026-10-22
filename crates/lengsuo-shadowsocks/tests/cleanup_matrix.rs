//! Shadowsocks 异常矩阵补缺：**清理**（ALL-1 审计 §3 缺格）——仅回环、假口令、
//! 临时端口 / 临时目录。
//!
//! 审计原文：「无 relay 关闭后的资源/状态回收断言」。
//! 本文件只补「清理」一格：错密码 / 截断 / 篡改 / 重放 / 半关闭 / 超时六格已由
//! `tests/relay_e2e.rs`、`tests/tcp.rs`、`tests/xray_tcp.rs`、`tests/salt_persist_runtime.rs`
//! 覆盖，**不重做**。
//!
//! 三组判据：
//!
//! - **A 正常收尾后回收**（`normal`）：完整往返后上游会话被回收、salt 记忆池状态
//!   符合实现真实语义、再开连接仍可用、端口可再 bind。
//! - **B 异常结束后的回收**（`abnormal` + `multichunk`）：对端中途断开 / 上游
//!   不可达 / 写入中途被截断 ⇒ 有限时间内感知、会话被回收、错误如实返回
//!   （fail-closed）。`multichunk` 专测「同一条连接上连发多个 chunk」时的转发
//!   与收尾（`copy_request` 的「后续 chunk」分支）。
//! - **C 回收不误伤**（`isolation`）：一条连接异常结束后其它并行连接仍正常；
//!   relay 关闭后在途连接按实现真实语义收尾，端口不残留占用。
//!
//! 与固定参考（Xray v26.3.27 / `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）
//! `proxy/shadowsocks/server.go` 的 `handleConnection` 对齐的是**收尾语义**：
//! 参考用 `task.Run` 并发跑两个方向，任一方向出错即 `common.Interrupt` 另一个方向
//! 并回收连接（`server.go:286-289`）。
//!
//! ⚠️ 本文件是 **Rust↔Rust** 方向的异常矩阵补缺，**不**声称完成与参考二进制的
//! 互通（互通状态见 `docs/shadowsocks-status.md`）。

#[path = "cleanup_matrix/common.rs"]
#[allow(dead_code)]
mod common;

#[path = "cleanup_matrix/probe.rs"]
#[allow(dead_code)]
mod probe;

#[path = "cleanup_matrix/proc.rs"]
#[allow(dead_code)]
mod proc;

#[path = "cleanup_matrix/normal.rs"]
mod normal;

#[path = "cleanup_matrix/abnormal.rs"]
mod abnormal;

#[path = "cleanup_matrix/multichunk.rs"]
mod multichunk;

#[path = "cleanup_matrix/isolation.rs"]
mod isolation;
