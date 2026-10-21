//! VLESS Vision **线路原语**（`lengsuo_vless::vision_wire`）的具名用例。
//!
//! 覆盖任务书要求的三类：
//! 1. **正常往返**：既有原语 → 新 API → 还原 ⇒ 载荷**逐字节一致**；
//! 2. **错误输入 fail-closed**：非法参数 / 截断输入 ⇒ **显式报错**，不是静默产出
//!    垃圾数据；
//! 3. **与既有实现的等价性**：新 API 的线上输出与既有原语的输出**逐字节相同**
//!    （这是「接线正确、没改语义」的硬证据）。
//!
//! 关键点：第 3 类用**确定性 RNG**（计数器 RNG）让 vision padding 的随机长度
//! 可复现，于是「新 API 写出的线上字节」可以和「直接调用既有
//! `VisionClient` / `RecordWriter` 得到的字节」逐字节对比——任何接线偏差都会
//! 在这里暴露。
//!
//! 承载流用 `tokio::io::duplex`（内存管道），只用回环、无外部依赖。
//! 本文件不含 `unsafe`。
//!
//! **目录结构**（按职责拆分，避免单文件超 400 行软目标；与
//! `tests/exception_matrix/` 同一套路）：
//! - `vision_wire/common.rs` —— 共用夹具（确定性 RNG、假凭据、读空助手）；
//! - `vision_wire/roundtrip.rs` —— 正常往返；
//! - `vision_wire/failclosed.rs` —— 错误输入 fail-closed；
//! - `vision_wire/equivalence.rs` —— 与既有实现的逐字节等价性；
//! - `vision_wire/session.rs` —— `VisionSession` 端到端（本仓客户端 ↔ 本仓服务端）；
//! - `vision_wire/interop.rs` —— 与固定版本 Xray 互通的**共用件**；
//! - `vision_wire/interop_case.rs` —— 响应头**线上字节**的互通用例（`#[ignore]`）。
//!
//! 与 `tests/vision_wire_xray.rs` **互补**：那边验「首包 / padding 规则」，这边
//! 验「下行响应头在参考侧的确切线上字节」。

mod support;

#[path = "vision_wire/common.rs"]
mod common;
#[path = "vision_wire/equivalence.rs"]
mod equivalence;
#[path = "vision_wire/failclosed.rs"]
mod failclosed;
#[path = "vision_wire/interop.rs"]
mod interop;
#[path = "vision_wire/interop_case.rs"]
mod interop_case;
#[path = "vision_wire/roundtrip.rs"]
mod roundtrip;
#[path = "vision_wire/session.rs"]
mod session;
