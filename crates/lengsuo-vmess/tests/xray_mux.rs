//! Rust 客户端 ↔ 真实 Xray VMess 入站的 Mux（`v1.mux.cool`）互通（ignored）。
//!
//! 运行方式（缺 `LENGSUO_XRAY` 时每个用例明确打印原因并 return，不静默通过）：
//! ```text
//! LENGSUO_XRAY=/path/to/xray cargo test -p lengsuo-vmess --test xray_mux --locked -- --ignored --nocapture
//! ```
//!
//! 对照参考固定 commit `d2758a02`：
//! - 请求头命令 `RequestCommandMux` 且**不写地址**
//!   （`proxy/vmess/encoding/client.go:79-84`）；本仓 `request::Command` 无 Mux
//!   变体（`request.rs:40-67`），故明文头由 `xray_mux_helpers` 按
//!   `client.go:63-94` 手工拼装（测试侧代码，不改 `src/`）。
//! - 服务端把 Mux 请求的目的地固定为 `v1.mux.cool:0`
//!   （`proxy/vmess/encoding/server.go:207-211`）；`common/mux/server.go:42,63`
//!   只比较地址，不看端口；mux server 无条件挂载
//!   （`app/proxyman/inbound/always.go:83,119,141`）。
//! - 帧布局与四态：`common/mux/frame.go`、`common/mux/writer.go`；
//!   `New` 帧带 `network|port|address`，`Keep/End` 只带 4 字节元数据。
//! - 服务端分派：`common/mux/server.go:158-334`；客户端分派：
//!   `common/mux/client.go:333-419`。
//! - VMess 体分帧：AES-128-GCM 在 `encoding/server.go:280-298` 无条件走
//!   `AuthenticationReader`，与 `RequestOptionChunkStream` 位无关；回程
//!   `EncodeResponseBody`（`server.go:402-...`）同理。故本文件用
//!   `option = 0x01(ChunkStream)`、**不开** chunk masking（0x04），走明文长度段。
//!
//! 关键时序（参考 `proxy/vmess/inbound/inbound.go:187-223`）：响应头写在
//! `buf.NewBufferedWriter` 里，直到首次 `input.ReadMultiBuffer()` 返回后才
//! `SetBuffered(false)` 刷出——因此客户端必须先把 mux 帧写出去，再读响应头。
//!
//! 实测记录（2026-10-20，详见 docs/vmess-status.md「Mux 参考互通」）：
//! 首轮实跑暴露 `StreamSender::send_new(None)` 误置 `OptionData`
//! （Xray 报 `unknown status: 108`），已按参考 `writer.go:62-69` 最小修正。
//!
//! **文件结构**：本文件是测试目标入口（原 628 行超限文件）。用例按主题拆到
//! `tests/xray_mux/` 下：
//! - `tcp_session.rs`：用例 A（TCP over mux）。
//! - `udp_session.rs`：用例 B（UDP over mux）。
//! - `parallel.rs`：用例 C（双会话并行、不串包）。
//! - `isolation.rs`：用例 D①（未知 session id 隔离）。
//! - `frame_guards.rs`：用例 D②③④（超限 metaLen / 半帧关流 / 会话上限）。
//!
//! 拆法用 `include!` **文本并入**同一模块（不是 `mod` 子模块）——这样用例名
//! **不带模块前缀**，与拆分前逐字一致（`mod` 方案会把名字变成 `tcp_session::xxx`，
//! 属于改名）。代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

#[path = "xray_mux_helpers/mod.rs"]
mod helpers;
#[path = "support/mod.rs"]
mod support;

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use helpers::{
    fail, open_session, pump_until, spawn_counting_listener, spawn_udp_echo, start_fixture,
    xray_bin, MuxConn, RESPONSE_TIMEOUT,
};
use lengsuo_vmess::muxframe::{
    FrameMetadata, SessionStatus, TargetNetwork, MAX_META_LEN, OPTION_DATA, OPTION_ERROR,
};
use lengsuo_vmess::muxsession::{
    encode_frame_with_payload, ClientSession, SessionStrategy, StreamSender,
};
use lengsuo_vmess::request::KeySource;
use ss_core::target::TargetAddr;

use support::codec;

include!("xray_mux/tcp_session.rs");
include!("xray_mux/udp_session.rs");
include!("xray_mux/parallel.rs");
include!("xray_mux/isolation.rs");
include!("xray_mux/frame_guards.rs");
