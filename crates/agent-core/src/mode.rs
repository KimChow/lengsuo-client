//! 模式策略（波次 1 卡 3：模式 = 工具白名单 + 模板 + 硬规则三层同切）。
//!
//! 白名单是**逻辑工具名集合**，语义按 参考客户端 基线的类别面命名（`类别.动作`），
//! 与 `agent-tools` 的真实工具名对接在合并期做（名字以实际注册表为准替换）。
//! 模板只作为**文本片段**由本卡提供（渲染归 `agent-prompts`）；硬规则文案全模式统一追加。
//!
//! 五个模式与 [`crate::schema::Mode`] 一一对应（该枚举已含 `Expert`，此处复用不重复定义）：
//! - `Quick`：空集，仅 chat；
//! - `Ask`：只读白名单（读文件/读网络/列任务/用技能）；
//! - `Plan`：craft 集合去掉全部写/执行类，另加 `plan.enter` / `plan.exit` 门禁工具；
//! - `Craft`：全集；
//! - `Expert`：Craft 再加 `plan.enter` / `plan.exit`。

use std::collections::BTreeSet;

use crate::schema::Mode;

/// 只读类逻辑工具名（Ask 白名单主体，也是 craft 全集的只读段）。
pub const READONLY_TOOLS: [&str; 7] = [
    "fs.read",
    "fs.glob",
    "fs.search",
    "web.fetch",
    "web.search",
    "task.list",
    "skill.use",
];

/// 写/执行类逻辑工具名（craft 全集的写段；Plan 模式据此从全集剔除）。
pub const WRITE_TOOLS: [&str; 6] = [
    "fs.write",
    "fs.delete",
    "shell.exec",
    "task.create",
    "task.update",
    "skill.install",
];

/// 规划门禁工具名（真门禁工具：进入规划 / 退出规划）。
pub const PLAN_ENTER: &str = "plan.enter";

/// 退出规划门禁工具名（`args.approved` 决定是否转为实际执行）。
pub const PLAN_EXIT: &str = "plan.exit";

/// 全部逻辑工具名（craft 全集 = 只读段 + 写段）。
pub fn all_tools() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = READONLY_TOOLS.to_vec();
    names.extend_from_slice(&WRITE_TOOLS);
    names
}

/// 写/执行类工具名（供门禁与交付物提醒判定复用）。
pub fn write_tools() -> Vec<&'static str> {
    WRITE_TOOLS.to_vec()
}

/// 某模式的策略：工具白名单 + 模板片段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModePolicy {
    /// 允许的逻辑工具名集合（不在集合内的调用由 loop 直接以 denied 结果回填，不执行）。
    pub tools: BTreeSet<String>,
    /// 模式能力面模板片段（纯文本，渲染由调用方/`agent-prompts` 承担）。
    pub template: &'static str,
}

impl ModePolicy {
    /// 取某模式的策略（等价于 [`mode_policy`]）。
    pub fn of(mode: Mode) -> Self {
        mode_policy(mode)
    }

    /// 集合内是否含该工具。
    pub fn allows(&self, tool: &str) -> bool {
        self.tools.contains(tool)
    }

    /// 集合大小。
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }
}

/// 模式策略（白名单 + 模板片段）的唯一出口。
pub fn mode_policy(mode: Mode) -> ModePolicy {
    ModePolicy {
        tools: mode_tools(&mode),
        template: mode_template(&mode),
    }
}

/// 某模式的工具白名单。
pub fn mode_tools(mode: &Mode) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    match mode {
        Mode::Quick => {}
        Mode::Ask => {
            add_all(&mut set, &READONLY_TOOLS);
        }
        Mode::Plan => {
            add_all(&mut set, &READONLY_TOOLS);
            set.insert(PLAN_ENTER.to_string());
            set.insert(PLAN_EXIT.to_string());
        }
        Mode::Craft | Mode::Expert => {
            add_all(&mut set, &all_tools());
        }
    }
    if matches!(mode, Mode::Expert) {
        set.insert(PLAN_ENTER.to_string());
        set.insert(PLAN_EXIT.to_string());
    }
    set
}

fn add_all(set: &mut BTreeSet<String>, names: &[&str]) {
    for name in names {
        set.insert((*name).to_string());
    }
}

/// 某模式的能力面模板片段（硬规则由 [`HARD_RULES`] 全模式统一追加）。
pub fn mode_template(mode: &Mode) -> &'static str {
    match mode {
        Mode::Quick => QUICK_TEMPLATE,
        Mode::Ask => ASK_TEMPLATE,
        Mode::Plan => PLAN_TEMPLATE,
        Mode::Craft => CRAFT_TEMPLATE,
        Mode::Expert => EXPERT_TEMPLATE,
    }
}

/// 硬规则文案（全模式统一追加；第一条为卡面冻结要点）。
pub const HARD_RULES: &str = "## 硬规则
- 不得声称读过/写过/搜过未实际发生的操作。
- 工具结果只按实际返回值陈述；被拒绝或未发起的调用不得转述为已完成。";

const QUICK_TEMPLATE: &str = "## 能力边界（quick · 只答不操作）
- 本模式不启用任何工具：不读取文件、不写入文件、不执行命令、不访问网络。
- 只基于用户提供的信息与既有知识作答；需要真实读写或执行时请切换到 ask、plan 或 craft。";

const ASK_TEMPLATE: &str = "## 工具能力（ask · 只读白名单）
- 允许的工具仅限只读类别：fs.read、fs.glob、fs.search、web.fetch、web.search、task.list、skill.use。
- 只读白名单之外的动作一律不发起：不写入、不删除、不执行命令。";

const PLAN_TEMPLATE: &str = "## 工具能力（plan · 只读 + 规划门禁）
- 可用工具为只读类别加 plan.enter / plan.exit：规划阶段不启用任何写/执行工具。
- 先给出计划（目标、步骤、影响文件、验证方式、风险），由用户经 plan.exit 批准后才进入实际执行。";

const CRAFT_TEMPLATE: &str = "## 工具能力（craft · 全工具）
- 可用工具覆盖只读与写/执行两类：fs.read、fs.glob、fs.search、web.fetch、web.search、task.list、skill.use、fs.write、fs.delete、shell.exec、task.create、task.update、skill.install。
- 每个工具调用都必须真实发起，是否放行由调用方的权限门决定；被拒绝时不得假装已执行。
- 改动工作区前先读取现状，收尾时列出实际产生的变更与交付物。";

const EXPERT_TEMPLATE: &str = "## 工具能力（expert · 全工具 + 规划门禁）
- 可用工具为 craft 全集再加 plan.enter / plan.exit：需要时可进入规划态，批准后续跑。
- 可把子任务分派给专家角色（研究、编码、评审、测试），并汇总其结论与证据。
- 专家产出同样受硬规则与权限门约束：未实际发生的调用不得转述为已完成。";

#[cfg(test)]
mod tests {
    use super::*;

    fn names(mode: Mode) -> Vec<String> {
        mode_tools(&mode).into_iter().collect()
    }

    #[test]
    fn quick_policy_has_no_tools() {
        assert!(mode_policy(Mode::Quick).tools.is_empty());
    }

    #[test]
    fn ask_policy_is_readonly_whitelist() {
        let ask = mode_policy(Mode::Ask);
        assert_eq!(ask.tool_count(), READONLY_TOOLS.len());
        for tool in READONLY_TOOLS {
            assert!(ask.allows(tool), "ask 应含只读工具 {tool}");
        }
        for tool in WRITE_TOOLS {
            assert!(!ask.allows(tool), "ask 不应含写/执行工具 {tool}");
        }
        assert!(!ask.allows(PLAN_EXIT));
    }

    #[test]
    fn plan_policy_drops_writes_and_adds_gate_tools() {
        let plan = mode_policy(Mode::Plan);
        for tool in READONLY_TOOLS {
            assert!(plan.allows(tool), "plan 应含只读工具 {tool}");
        }
        for tool in WRITE_TOOLS {
            assert!(!plan.allows(tool), "plan 不应含写/执行工具 {tool}");
        }
        assert!(plan.allows(PLAN_ENTER) && plan.allows(PLAN_EXIT));
        assert_eq!(
            plan.tool_count(),
            READONLY_TOOLS.len() + 2,
            "plan = craft - 写/执行 + 两个门禁工具"
        );
    }

    #[test]
    fn craft_policy_is_full_set_without_gate_tools() {
        let craft = mode_policy(Mode::Craft);
        assert_eq!(craft.tool_count(), all_tools().len());
        assert!(names(Mode::Craft).iter().all(|n| !n.starts_with("plan.")));
    }

    #[test]
    fn expert_policy_is_craft_plus_gate_tools() {
        let expert = mode_policy(Mode::Expert);
        assert_eq!(expert.tool_count(), all_tools().len() + 2);
        for tool in all_tools() {
            assert!(expert.allows(tool), "expert 应含 craft 工具 {tool}");
        }
        assert!(expert.allows(PLAN_ENTER) && expert.allows(PLAN_EXIT));
        assert!(
            mode_tools(&Mode::Craft).is_subset(&expert.tools),
            "expert 白名单必须包含 craft 全集"
        );
    }

    #[test]
    fn templates_are_distinct_per_mode_and_carry_hard_rules() {
        let mut seen = std::collections::BTreeSet::new();
        for mode in Mode::ALL {
            let policy = mode_policy(mode);
            assert!(seen.insert(policy.template), "{mode:?} 模板与他模式重复");
            assert!(policy.template.contains(mode.as_str()));
        }
        assert!(HARD_RULES.contains("不得声称读过/写过/搜过未实际发生的操作"));
    }
}
