//! Agent loop 测试（模式白名单 + Plan 门禁）。共享 Mock 见 `agent_support`。
//!
//! 原单文件 408 行，2026-10-18 按主题机械拆分为两组（断言与用例顺序零变化）：
//! `chat_and_whitelist.rs` = 原 L14-217（①/②/⑧ 走查 + ③ 白名单），
//! `plan_gate.rs` = 原 L219-408（Plan 门禁各分支）。共享 Mock 仍在 `agent_support`，
//! 本入口只保留 mod 声明（原文件除 use 外无其它共享 helpers）。

#[path = "../agent_support/mod.rs"]
mod agent_support;

mod chat_and_whitelist;
mod plan_gate;
