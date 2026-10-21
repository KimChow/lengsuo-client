//! 截断帧必须 **fail-closed**：与「对端干净关闭」严格区分开。
//!
//! ## 缺陷背景（`docs/audit-all1.md` §6 P2-10 ①）
//!
//! 旧实现 `src/frame.rs` 的 `Frame::read` 用 `read_exact` 读帧头与载荷，
//! 于是「一个字节都没读到」与「读到一半」**都是** `ErrorKind::UnexpectedEof`；
//! 而 `src/server/session.rs` 的帧循环把 `UnexpectedEof` **一律**当作
//! 「对端干净关闭」⇒ **被截断的帧被误判为正常收尾**（fail-open）。
//!
//! ## 判据位置
//!
//! - 读侧：`src/frame.rs` 的 `Frame::read` + `frame::eof_kind`——干净 EOF 与
//!   截断是两个**不同的错误值**（`frame::Eof::Clean` / `frame::Eof::Truncated`）。
//! - 会话侧：`src/server/session.rs` 的 `serve`——干净 EOF ⇒ `Ok(stats)`；
//!   截断 ⇒ **`Err`**（不得 `Ok(stats)`）。
//!
//! ## 与参考 anytls-go v0.0.13 的一致处
//!
//! `proxy/session/session.go:190` 用 `io.ReadFull(s.conn, hdr[:])`：
//! 一个字节都没读到是 `io.EOF`（正常收尾），读到一半才是
//! `io.ErrUnexpectedEOF`（截断）⇒ **参考本来就区分这两者**，本卡是把本仓
//! 对齐到参考，而不是自创「等价」方案。
//!
//! ## 本文件的取舍
//!
//! - 只用回环地址 + 临时端口 + 运行时生成的假口令；口令不进入任何断言文本。
//! - 全部异步读都套 `tokio::time::timeout` 兜底。
//! - ⛔ 不复用 `tests/tamper_matrix/**` 与 `tests/lifecycle.rs`（均已进官方
//!   门禁登记）⇒ 自带最小夹具。
//!
//! ## 模块划分（入口 + 同名子目录）
//!
//! - `harness.rs`：共用夹具（服务端 / 回环目标 / 握手）。
//! - `clean_close.rs` / `truncated.rs`：正常关闭 ⇒ `Ok`；截断 ⇒ `Err`。
//! - `isolation.rs`：截断后资源仍回收、不污染后续会话。
//! - `read_semantics.rs` / `official.rs`：读侧三态单元判据；官方参考侧取证。
//!
//! ## 官方对端夹具的复用
//!
//! `official.rs` 的 `#[ignore]` 用例要起**官方 anytls-server** 做参考侧取证，
//! 故按 `#[path]` 挂载既有夹具（**只读引用，不改动**）：`interop_client/harness.rs`、
//! `interop_client/tls.rs`、`interop/support.rs`。
#[path = "truncated_frame/clean_close.rs"]
mod clean_close;
#[path = "truncated_frame/harness.rs"]
mod harness;
#[path = "interop_client/harness.rs"]
mod interop_harness;
#[path = "truncated_frame/isolation.rs"]
mod isolation;
#[path = "truncated_frame/official.rs"]
mod official;
#[path = "truncated_frame/read_semantics.rs"]
mod read_semantics;
#[path = "interop/support.rs"]
mod support;
#[path = "interop_client/tls.rs"]
mod tls;
#[path = "truncated_frame/truncated.rs"]
mod truncated;
