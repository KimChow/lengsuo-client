//! AnyTLS 异常矩阵「篡改」格：载荷 / 帧头命令字节 / 长度字段 / 认证块
//! 四类篡改必须全部 fail-closed。
//!
//! ## 参考基线
//!
//! 任务书指定的 Xray commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`
//! （v26.3.27）**不含任何 anytls 代码**——实测该提交全树 `grep -i anytls`
//! 零命中，故 Xray 无法作为 AnyTLS 篡改语义的参考。
//! AnyTLS 的实际参考是 **anytls-go v0.0.13**
//! （`scripts/reference_manifest.json` 的 `anytls` 条目，commit
//! `9666872946857b50a74fdb692896d77b53773cb2`；协议基线
//! `fd6167acd6d73b9fa3e607659951847fbc9e6c50`）。
//! 详见 `docs/anytls-tamper.md` 的「参考基线」与「不一致处」。
//!
//! ## 篡改面的分层（本卡的核心口径）
//!
//! - **传输层（TLS）**：参考对每条连接无条件 `tls.Server`
//!   （anytls-go `cmd/server/inbound_tcp.go:27`），故真实部署里
//!   「一帧载荷被改 1 bit」表现为 **TLS 记录载荷被改 1 bit**，
//!   由 AEAD 检出并断连 ⇒ `tls_tamper`。
//! - **帧层**：AnyTLS 帧头只有 `cmd(1) | sid(4) | len(2)`
//!   （anytls-go `proxy/session/frame.go:37-49`），**没有帧级 MAC**；
//!   帧层的判据是**结构约束**：未知命令、长度与实际字节不符、
//!   命令与载荷不自洽、认证摘要不匹配 ⇒ `frame_tamper`。
//! - **认证块**：口令摘要（32B）参与常量时间比对 ⇒ `frame_tamper`。
//!
//! ⚠️ 口径边界（**不隐瞒**）：PUSH 帧**载荷内容**在帧层没有完整性保护——
//! 本仓与参考**一致**（参考同样只有结构校验）。所以「载荷篡改 ⇒ 拒绝」在
//! 帧层只能由 TLS 提供；本卡据此逐层取证，不把 TLS 的能力冒充成帧层能力。
//! 详见 `docs/anytls-tamper.md` 的「篡改面的分层口径」。
//!
//! 本卡只补篡改格；⛔ 不重做重放 / 半关闭（已由 `tests/lifecycle.rs` 覆盖）。
#[path = "tamper_matrix/datagram_regression.rs"]
mod datagram_regression;
#[path = "tamper_matrix/frame_tamper.rs"]
mod frame_tamper;
#[path = "tamper_matrix/harness.rs"]
mod harness;
#[path = "interop_client/harness.rs"]
mod interop_harness;
#[path = "tamper_matrix/isolation.rs"]
mod isolation;
#[path = "tamper_matrix/official_interop.rs"]
mod official_interop;
/// 测试专用 PKI（openssl 现签，只写临时目录、用后即删）。
/// 复用 `tests/tls_trust/pki.rs`（**只读引用，不改动**），与
/// `tests/lifecycle.rs` 复用 `tests/interop/support.rs` 同一范式。
#[path = "tls_trust/pki.rs"]
mod pki;
/// 官方 anytls-server 互通夹具（**只读引用，不改动**）：与
/// `tests/lifecycle.rs` 复用同一组文件，保证两卡的参考互通口径一致。
#[path = "interop/support.rs"]
mod support;
#[path = "interop_client/tls.rs"]
mod tls;
#[path = "tamper_matrix/tls_tamper.rs"]
mod tls_tamper;
#[path = "tamper_matrix/truncation_reorder.rs"]
mod truncation_reorder;
