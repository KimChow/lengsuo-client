//! agent-prompts：提示词引擎（模式模板 × 变量注入）。
//!
//! 纯域逻辑：不读写文件、不访问网络、不取系统时钟；输出完全由
//! [`PromptMode`] + [`PromptVars`] 决定，同输入同输出（无时间戳注入）。
//! 规格源：worktree 根 `PROMPTS-SPEC.md`（v0 冻结要点）。
//!
//! 结构：[`PromptTemplate`] 由 [`Segment`] 序列组成（文本段 / 变量位 / 门禁段），
//! [`Composer::build`] 按模式取模板并渲染；`plan` 复用 `craft` 模板再追加
//! [`Composer::plan_gate`] 门禁片段，`expert` 在 `craft` 之上追加专家协作段。
//!
//! ```
//! use agent_prompts::{Composer, PromptMode, PromptVars};
//!
//! let vars = PromptVars {
//!     ai_name: "小澜".into(),
//!     user_name: "Kim".into(),
//!     soul: "冷静、直接。".into(),
//!     workspace: "/work/demo".into(),
//!     date: "2026-05-06".into(),
//!     user_rules: String::new(),     // 空 → 不追加「用户自定义规则」段
//!     memory_digest: String::new(),   // 空 → 不追加「记忆摘要」段
//! };
//! let prompt = Composer::build(PromptMode::Plan, &vars);
//! assert!(prompt.contains("## 工具能力（craft · 全工具）")); // craft 段完整复用
//! assert!(prompt.contains(Composer::plan_gate()));           // 追加规划门禁
//! assert!(!prompt.contains("记忆摘要"));                       // 空槽位不留标题
//! ```

mod compose;
mod model;
mod template;

pub use compose::Composer;
pub use model::{PromptMode, PromptTemplate, PromptVars, Segment};
