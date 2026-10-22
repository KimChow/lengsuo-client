//! 帧层篡改用例：命令字节、长度字段、认证块。
//!
//! 口径：AnyTLS 的帧头只有 `cmd(1) | sid(4) | len(2)`
//! （参考 anytls-go `proxy/session/frame.go:37-49`），**没有帧级 MAC**。
//! 因此帧层能判定的篡改是**结构性**的：未知命令、长度与实际字节不符、
//! 命令与载荷不自洽、认证摘要不匹配。本模块逐条钉住这些判据。
//!
//! 载荷内容本身的完整性**不在帧层**——参考同样没有；那部分由 TLS 提供，
//! 见 `tls_tamper`。
#![allow(dead_code)]

use crate::harness::{
    declared_length, flip_bit, push_with_target, set_length, settings, spawn_target, Harness,
    PASSWORD, TOTAL, WAIT,
};
use lengsuo_anytls::{
    auth::Credential,
    frame::{Command, Frame},
    Error,
};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

/// 建会话、认证、发送 Settings 并读到 ServerSettings（证明会话健康）。
/// 返回已就绪的夹具。
async fn healthy_session() -> Harness {
    let mut harness = Harness::start(PASSWORD).await;
    harness.send(settings()).await;
    let frame = harness.expect(Command::ServerSettings).await;
    assert_eq!(frame.data, b"v=2", "ServerSettings 载荷");
    harness
}

// 用例正文按篡改面拆到 `tests/tamper_matrix/frame_tamper/` 下，用 `include!`
// **文本并入**同一模块（不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前
// 逐字一致。代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。
//
// ⚠️ `include!` 的路径相对**发起 include 的文件所在目录**（本文件在
// `tests/tamper_matrix/` 下），故这里写 `frame_tamper/xxx.rs` 而不是
// `tamper_matrix/frame_tamper/xxx.rs`。
//
// - `commands.rs`：命令字节类 3 条。
// - `lengths.rs`：长度字段类 3 条。
// - `auth.rs`：认证块类 3 条（含专属助手 `auth_block`）。

include!("frame_tamper/commands.rs");
include!("frame_tamper/lengths.rs");
include!("frame_tamper/auth.rs");
