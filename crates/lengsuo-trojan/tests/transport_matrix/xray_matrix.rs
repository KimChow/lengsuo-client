//! 外层传输矩阵的 **与固定基线 Xray 的真实互通**部分（`#[ignore]`，
//! 必须 `--ignored` 实跑）。
//!
//! 方向：本仓 Rust 客户端（TLS → 外层传输 → trojan）→ 官方 Xray 服务端
//! （trojan 入站套 `streamSettings.network`）。**这不是自家 roundtrip**：对端是
//! 固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0` 的官方二进制。
//!
//! 逐外层 × 逐用例的判据与 `rust_matrix.rs` 同构，但证据来自参考端：
//!
//! - 正常往返：回程逐字节一致，且业务目标 accept 计数 `== 1`；
//! - 错密码：业务目标 accept 计数**不增长**，参考端主动结束连接；
//! - 截断：参考端在握手截止内**主动结束**连接（不接受“观察超时”当拒绝证据）；
//! - 半关闭：关写端之后仍能收完整个 64 KiB 回程。
//!
//! 用例命名：`xray_matrix_<外层>_<用例>`，与 `docs/trojan-transport.md` 的
//! 表格一一对应。
//!
//! 结构：本文件是**入口**，只留共享的导入；**脚手架**（参考端配置、客户端
//! 建流、拒绝观测、半关闭语义分档）在 `xray_matrix/scaffold.rs`，用例分三组
//! —— 传输面（正常 / 错密码 / 截断）在 `xray_matrix/cases_transport.rs`，
//! 半关闭在 `xray_matrix/cases_half_close.rs`，其余（错误路径 / 载荷 / 观测面 /
//! Close 帧）在 `xray_matrix/cases_misc.rs`。四者都以 `include!` 拼回**本模块**，
//! 因此用例的全限定名（`xray_matrix::xray_matrix_*`）与拆分前完全一致。

use std::sync::atomic::Ordering;
use std::time::Duration;

use lengsuo_trojan::transport::{httpupgrade, ws};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use super::harness::{
    bounded_shutdown, client_action, Action, Identity, Outcome, Outer, Target, CLOSE_BOUND,
    PASSWORD, PATH, PAYLOAD, REPLY, REPLY_BULK_LEN, TOTAL, TRUNCATION_CUTS, WAIT,
};
use super::support::{free_port, launch};

include!("xray_matrix/scaffold.rs");
include!("xray_matrix/cases_transport.rs");
include!("xray_matrix/cases_half_close.rs");
include!("xray_matrix/cases_misc.rs");
