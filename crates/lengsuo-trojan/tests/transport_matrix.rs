//! Trojan **外层传输矩阵**：逐外层 × 逐用例。
//!
//! 本文件是矩阵的**驱动器**；实现拆到 `tests/transport_matrix/` 子目录
//! （单文件行数上限：软 400 / 硬 700）。
//!
//! 矩阵维度：
//!
//! - **外层**：`tcp`（raw，无升级）/ `ws`（WebSocket）/ `httpupgrade`（HTTPUpgrade）。
//! - **用例**：`normal`（正常往返）/ `wrong_password`（错密码 fail-closed）/
//!   `truncated`（请求头截断）/ `half_close`（半关闭后回程仍完整）。
//!
//! 两个方向分层：
//!
//! - `rust_matrix`：**Rust↔Rust 回环**（非忽略）。证明同一组 trojan 语义在三种
//!   外层上的判定一致（尤其半关闭的关闭语义按外层不同而不同：WS 发 `Close` 帧，
//!   TCP / HTTPUpgrade 发 FIN）。
//! - `xray_matrix`：**与固定基线 Xray 的真实互通**（`#[ignore]`，必须 `--ignored`
//!   实跑）。对端是官方二进制，**不是**自家 roundtrip。
//!
//! 判定纪律（沿用 `tests/exception_matrix.rs`）：拒绝不能只靠“我方读操作超时”。
//! 每条拒绝都要求业务目标的 accept 计数不增长（独立观测面）；能拿到对端主动
//! 结束连接时一并断言，拿不到时如实记录而不放宽判据。
//!
//! 与参考的外层清单对照见 `docs/trojan-transport.md`。

#[path = "transport_matrix/harness.rs"]
mod harness;
#[path = "transport_matrix/probe.rs"]
mod probe;
#[path = "transport_matrix/rust_matrix.rs"]
mod rust_matrix;
mod support;
#[path = "transport_matrix/xray_matrix.rs"]
mod xray_matrix;
