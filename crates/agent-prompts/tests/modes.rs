//! 五模式能力面与公共头/硬规则的快照式断言（PROMPTS-SPEC 冻结要点）：
//! 能力面按 quick → ask → craft → plan(=craft+gate) → expert(=craft+协作) 递增。

mod common;

use agent_prompts::{Composer, PromptMode};
use common::{
    assert_no_blank_line_runs, assert_no_empty_section, bare_vars, full_vars, has_all, has_none,
    ALL_MODES, CRAFT_LINES, GATE_LINES,
};

// ---- 公共头：身份 + 日期 + 工作区 + 记忆摘要 ----

#[test]
fn common_header_carries_identity_date_workspace_memory() {
    for mode in ALL_MODES {
        let out = Composer::build(mode, &full_vars());
        assert!(out.contains("LAN-XIAO"), "{mode:?} 缺 ai_name");
        assert!(out.contains("KIM-USR"), "{mode:?} 缺 user_name");
        assert!(out.contains("SOUL-冷静直接先验证"), "{mode:?} 缺 soul");
        assert!(out.contains("DATE-2026-05-06"), "{mode:?} 缺 date");
        assert!(out.contains("WS-/home/kim/demo"), "{mode:?} 缺 workspace");
        assert!(
            out.contains("## 记忆摘要\nMEM-项目：提示词引擎"),
            "{mode:?} 缺记忆摘要"
        );
        assert!(!out.contains('{'), "{mode:?} 残留未替换的花括号");
    }
}

#[test]
fn mode_label_is_declared_in_header() {
    for mode in ALL_MODES {
        let out = Composer::build(mode, &full_vars());
        let label = format!("# 系统提示词 · 模式：{}", mode.as_str());
        assert!(
            out.starts_with(&label),
            "{mode:?} 头部应为 {label}\n实际：{out}"
        );
    }
}

// ---- 硬规则：全模式必须存在 ----

#[test]
fn hard_rule_about_unperformed_actions_in_all_modes() {
    for mode in ALL_MODES {
        let out = Composer::build(mode, &full_vars());
        assert!(
            out.contains("- 不得声称读过/写过/搜过未实际发生的操作。"),
            "{mode:?} 缺硬规则"
        );
        assert!(out.contains("## 硬规则"), "{mode:?} 缺硬规则段标题");
    }
}

// ---- 五模式能力面 ----

#[test]
fn quick_declares_no_tools_and_answer_only() {
    let out = Composer::build(PromptMode::Quick, &full_vars());
    has_all(
        &out,
        &[
            "## 能力边界（quick · 只答不操作）",
            "- 本模式不启用任何工具：不读取文件、不写入文件、不执行命令、不访问网络、不操作浏览器。",
            "- 只基于用户提供的信息与既有知识作答；不改动任何文件，不安排执行任务。",
        ],
    );
    // quick 不含任何工具说明
    has_none(
        &out,
        &[
            "## 工具能力（ask · 只读白名单）",
            "## 工具能力（craft · 全工具）",
            "## 规划门禁（plan）",
            "## 专家协作（expert）",
            "fs.read",
            "shell.exec",
            "browser.open",
            "权限门",
        ],
    );
}

#[test]
fn ask_documents_readonly_whitelist_only() {
    let out = Composer::build(PromptMode::Ask, &full_vars());
    has_all(
        &out,
        &[
            "## 工具能力（ask · 只读白名单）",
            "- 允许的工具仅限只读类别：fs.list、fs.read、fs.search。",
            "- 只读白名单之外的动作一律不发起：不写入、不删除、不执行命令、不访问外部网络、不操作浏览器。",
            "- 需要改动时先说明缺口与所需授权，请用户切换到 plan 或 craft。",
        ],
    );
    has_none(
        &out,
        &[
            "## 工具能力（craft · 全工具）",
            "## 规划门禁（plan）",
            "## 专家协作（expert）",
            "fs.write",
            "fs.delete",
            "shell.exec",
            "net.fetch",
            "browser.open",
            "- 本模式不启用任何工具",
        ],
    );
}

#[test]
fn craft_documents_full_tool_surface() {
    let out = Composer::build(PromptMode::Craft, &full_vars());
    has_all(&out, &CRAFT_LINES);
    has_none(
        &out,
        &[
            "## 工具能力（ask · 只读白名单）",
            "## 规划门禁（plan）",
            "## 专家协作（expert）",
            "- 本模式不启用任何工具",
        ],
    );
}

#[test]
fn plan_is_craft_plus_gate() {
    let craft = Composer::build(PromptMode::Craft, &full_vars());
    let plan = Composer::build(PromptMode::Plan, &full_vars());
    has_all(&plan, &CRAFT_LINES); // craft 段完整复用
    has_all(&plan, &GATE_LINES);
    has_none(&plan, &["## 专家协作（expert）"]);

    // 门禁段插在 craft 段之后、硬规则之前
    let craft_at = plan.find("## 工具能力（craft · 全工具）").unwrap();
    let gate_at = plan.find("## 规划门禁（plan）").unwrap();
    let hard_at = plan.find("## 硬规则").unwrap();
    assert!(craft_at < gate_at && gate_at < hard_at, "plan 段落顺序错误");

    // 除门禁段与模式标题行外，plan 与 craft 逐字一致（craft 段完整复用）
    let gate_block = format!("{}\n\n", Composer::plan_gate());
    let removed = plan.replace(&gate_block, "");
    assert_ne!(removed, plan, "门禁段未被单独定位");
    assert_eq!(removed.replace("模式：plan", "模式：craft"), craft);
}

#[test]
fn expert_is_craft_plus_expertise_section() {
    let out = Composer::build(PromptMode::Expert, &full_vars());
    has_all(&out, &CRAFT_LINES);
    has_all(
        &out,
        &[
            "## 专家协作（expert）",
            "- 可把子任务分派给专家角色（研究、编码、评审、测试），并汇总其结论与证据。",
            "- 专家分工必须在计划里显式列出：谁负责什么、如何验收，不重复结论。",
            "- 专家的产出同样受硬规则与权限门约束：未实际发生的调用不得转述为已完成。",
        ],
    );
    has_none(
        &out,
        &["## 规划门禁（plan）", "## 工具能力（ask · 只读白名单）"],
    );
}

#[test]
fn different_modes_produce_different_prompts() {
    let base = Composer::build(PromptMode::Quick, &full_vars());
    for mode in [
        PromptMode::Ask,
        PromptMode::Plan,
        PromptMode::Craft,
        PromptMode::Expert,
    ] {
        assert_ne!(
            base,
            Composer::build(mode, &full_vars()),
            "{mode:?} 与 quick 相同"
        );
    }
}

#[test]
fn every_mode_renders_without_hollow_sections() {
    for mode in ALL_MODES {
        let out = Composer::build(mode, &bare_vars());
        assert_no_empty_section(&out);
        assert_no_blank_line_runs(&out);
    }
}

// ---- 快照：quick + 可选变量全空的完整输出 ----

#[test]
fn snapshot_quick_minimal_vars() {
    let out = Composer::build(PromptMode::Quick, &bare_vars());
    assert_eq!(
        out,
        "# 系统提示词 · 模式：quick\n\
         \n\
         ## 身份\n\
         你是 小澜（Lengsuo 智能体工作平台的执行助手）。本次服务对象：Kim。\n\
         \n\
         人格设定：\n\
         冷静、直接、先验证再下结论。\n\
         \n\
         ## 环境\n\
         - 日期：2026-05-06\n\
         - 工作区：/home/kim/work/demo\n\
         \n\
         ## 能力边界（quick · 只答不操作）\n\
         - 本模式不启用任何工具：不读取文件、不写入文件、不执行命令、不访问网络、不操作浏览器。\n\
         - 只基于用户提供的信息与既有知识作答；不改动任何文件，不安排执行任务。\n\
         - 需要真实读写或执行时，请让用户切换到 ask、plan 或 craft 模式。\n\
         \n\
         ## 硬规则\n\
         - 不得声称读过/写过/搜过未实际发生的操作。\n\
         - 不虚构文件路径、命令、输出或测试结果；不确定就明说不知道。\n\
         - 工具结果只按实际返回值陈述，不改写、不美化、不补全。\n\
         - 做不到时直说原因与缺口，不用看似合理的假成功填充回复。\n"
    );
}
