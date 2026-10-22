//! L2 会话向量的 **JSON 数据**（**纯 JSON 文本**，无注释无尾逗号）。
//!
//! 单独成文件的原因：这份 JSON 有 160+ 行，塞进 `session_vectors.rs` 会顶破
//! 400 行软目标 ⇒ 按「数据 / 逻辑」拆开（`session_data.rs` 只放数据，
//! `session_vectors.rs` 只放解析与重算逻辑）。
//!
//! # 单一真相：数据在**仓根 `vectors/session-vectors.json`**
//!
//! 本常量用 `include_str!` **指向那一个文件** ⇒ 编译产物里的常量**就是**
//! 该文件的内容，**结构上不可能**与文件漂移（移动端也直接读同一份文件）。
//! **改向量只能改文件**，不许在 Rust 侧另存一份。
//!
//! ⚠️ 数据由 `generator::regenerate_session_vectors_json`（`#[ignore]`）
//! **重算**生成，输出**写进仓根 `vectors/session-vectors.json`**，
//! 文件内容必须与生成器输出**逐字节相同**
//! （由 `session_vectors_json_is_canonical` 守住）。

/// 会话向量 JSON（**纯 JSON 文本**，来自仓根 `vectors/session-vectors.json`）。
pub const SESSION_VECTORS_JSON: &str = include_str!("../../../../vectors/session-vectors.json");
