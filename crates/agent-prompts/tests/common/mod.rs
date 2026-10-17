//! 共享测试夹具与断言辅助。部分辅助只被其中一个测试目标使用，故整体放行 dead_code。
#![allow(dead_code)]

use agent_prompts::{PromptMode, PromptVars};

/// 完整变量样本：每个字段都是可 grep 的独特标记。
pub fn full_vars() -> PromptVars {
    PromptVars {
        ai_name: "LAN-XIAO".into(),
        user_name: "KIM-USR".into(),
        soul: "SOUL-冷静直接先验证".into(),
        workspace: "WS-/home/kim/demo".into(),
        date: "DATE-2026-05-06".into(),
        user_rules: "RULE-回复不超过三行".into(),
        memory_digest: "MEM-项目：提示词引擎；决定：plan 复用 craft 模板".into(),
    }
}

/// 最小变量集（记忆摘要与用户规则为空）。
pub fn bare_vars() -> PromptVars {
    PromptVars {
        ai_name: "小澜".into(),
        user_name: "Kim".into(),
        soul: "冷静、直接、先验证再下结论。".into(),
        workspace: "/home/kim/work/demo".into(),
        date: "2026-05-06".into(),
        user_rules: String::new(),
        memory_digest: String::new(),
    }
}

pub const ALL_MODES: [PromptMode; 5] = [
    PromptMode::Quick,
    PromptMode::Ask,
    PromptMode::Plan,
    PromptMode::Craft,
    PromptMode::Expert,
];

/// craft 能力段的全部关键行（plan 与 expert 必须原样带上，不得缩水）。
pub const CRAFT_LINES: [&str; 5] = [
    "## 工具能力（craft · 全工具）",
    "- 可用工具覆盖读、写、执行、网络与浏览器五类：fs.list、fs.read、fs.write、fs.delete、shell.exec、net.fetch、browser.open。",
    "- 每个工具调用都必须真实发起，由运行时权限门裁决；被拒绝或待确认时不得假装已执行。",
    "- 涉及写入、删除、命令执行、外部网络与浏览器操作的敏感动作需要用户确认。",
    "- 改动工作区文件前先读取现状，收尾时列出实际产生的变更。",
];

/// plan 门禁片段的关键语义行。
pub const GATE_LINES: [&str; 4] = [
    "## 规划门禁（plan）",
    "- 当前处于规划状态：先给出计划（目标、步骤、影响文件、验证方式、风险），等待用户批准。",
    "- 批准之前不得承诺或暗示任何写操作已经完成，也不得发起写入、删除、命令执行、外部网络或浏览器动作。",
    "- 计划被批准后才退出规划状态，转为实际执行。",
];

pub fn has_all(text: &str, lines: &[&str]) {
    for line in lines {
        assert!(
            text.contains(line),
            "缺少期望行：{line}\n--- 实际 ---\n{text}"
        );
    }
}

pub fn has_none(text: &str, lines: &[&str]) {
    for line in lines {
        assert!(
            !text.contains(line),
            "出现不应存在的行：{line}\n--- 实际 ---\n{text}"
        );
    }
}

/// 结构守卫：不渲染空段落标题（后面必须紧跟内容行）。
pub fn assert_no_empty_section(text: &str) {
    let lines: Vec<&str> = text.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.starts_with("## ") {
            let next = lines.get(i + 1);
            assert!(
                next.map(|n| !n.trim().is_empty()).unwrap_or(false),
                "空段落标题（后面没有内容）：{line}\n--- 实际 ---\n{text}"
            );
        }
    }
}

/// 结构守卫：段间只允许一个空行，省略段不得留下连续空行。
pub fn assert_no_blank_line_runs(text: &str) {
    let mut prev_blank = false;
    for line in text.lines() {
        let blank = line.trim().is_empty();
        assert!(!(blank && prev_blank), "出现连续空行\n--- 实际 ---\n{text}");
        prev_blank = blank;
    }
}
