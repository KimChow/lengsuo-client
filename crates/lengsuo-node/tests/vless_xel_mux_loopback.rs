//! VLESS **XEL 记录层**与 **Mux 承载**接进 node 出站产品路径的**实跑取证**
//! （Rust↔Rust 回环）。
//!
//! 对端是**本仓**协议 crate 的服务端原语（`lengsuo_vless::xel_wire` /
//! `lengsuo_vless::mux::worker`，编排见 `vless_xel_mux_loopback/support.rs`），
//! 客户端是 **node 的 VLESS 出口**（`lengsuo_node::outbound_vless::dial_vless`，
//! 走新加的 `xel` / `mux` 配置段）。
//!
//! ```text
//! node 侧：NodeConfig.xel  → XelStream（记录层）→ VLESS 请求头 + 成功响应头 → 载荷往返
//!        NodeConfig.mux  → MuxSessionIo（承载）  → 先发 mux 帧 → 读帧流时消费响应头
//! 服务端：TLS → 解 VLESS 请求头 → 写响应头 → 回环写下行
//! ```
//!
//! 覆盖八组：
//! 1. **XEL 正例**：握手成功 + 拿到成功响应头 + 载荷往返逐字节一致（**双向**）。
//! 2. **XEL 负例**：错密钥 ⇒ AEAD 认证失败 ⇒ 拨号失败（fail-closed，**不得**
//!    回落到明文、不得静默成功）。
//! 3. **XEL 负例**：配置非法 ⇒ **在建立 TCP/TLS 之前**就失败（**一条字节都不发**）。
//! 4. **XEL 负例**：载荷篡改（**记录层**里翻一个字节）⇒ 对端必须检出并断连。
//! 5. **Mux 正例**：单会话往返。
//! 6. **Mux 正例**：多会话隔离（同一条承载开两条会话，互不串扰）。
//! 7. **Mux 负例**：承载断开 ⇒ 所有逻辑会话必须失败（**不得**静默挂住）。
//! 8. **Mux 顺序**：承载上**先发 mux 帧**、再在读帧流时消费响应头（参考的
//!    `SetFlushNext()` 时序；先阻塞等响应头就是死锁）。
//!
//! **本文件只覆盖 Rust↔Rust 回环**，⛔ 不声称与参考实现互通。参考侧（固定版本
//! Xray）在**库层**已有真实对端证据（`crates/lengsuo-vless/tests/xray_vision.rs`）；
//! **node 侧**与参考对端的互通**尚未验证**（见本卡报告偏离清单）。

#[path = "vless_xel_mux_loopback/support.rs"]
mod support;

use std::time::Duration;

use lengsuo_node::outbound_vless::{dial_vless, VlessStream};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use support::{
    accept_only_watcher, server_fixture, spawn_mux_peer, vless_node, xel_section, DEADLINE, KEY,
    PAYLOAD, TAMPER_OFFSET, WAIT, XEL_DOWNLINK_HEX, XEL_SERVER_DOWNLINK_HEX, XEL_SERVER_UPLINK_HEX,
    XEL_UPLINK_HEX, XEL_WRONG_HEX,
};

/// 多会话隔离用例的 A 会话载荷（与 B 会话载荷互不相同且互不含对方）。
const PAYLOAD_A: &[u8] = b"session-A-marker-payload";
/// 多会话隔离用例的 B 会话载荷。
const PAYLOAD_B: &[u8] = b"session-B-marker-payload";
// 用例按主题拆到 `tests/vless_xel_mux_loopback/` 下，用 `include!` **文本并入**
// 同一模块（不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。
include!("vless_xel_mux_loopback/cases_xel.rs");
include!("vless_xel_mux_loopback/cases_mux.rs");
