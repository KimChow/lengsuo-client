//! 组装器：模式模板 × 变量注入 → 提示词文本。

use crate::model::{PromptMode, PromptVars};
use crate::template;

/// 提示词组装器（无状态；纯函数式，全部能力在关联函数上）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Composer;

impl Composer {
    /// 模式模板 + 变量替换 + 硬规则段，产出完整系统提示词。
    ///
    /// 确定性：输出只取决于 `mode` 与 `vars`，不注入时间戳、不读环境变量、不做 IO。
    pub fn build(mode: PromptMode, vars: &PromptVars) -> String {
        template::template_for(mode).render(vars)
    }

    /// plan 门禁片段（可单独取用，供宿主追加到自有模板末尾）。
    pub fn plan_gate() -> &'static str {
        template::PLAN_GATE
    }
}
