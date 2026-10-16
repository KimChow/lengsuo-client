//! 变量注入、可省略段、用户规则追加、确定性与公开模板 API 的断言。

mod common;

use agent_prompts::{Composer, PromptMode, PromptTemplate, Segment};
use common::{assert_no_empty_section, bare_vars, full_vars, has_all, ALL_MODES};

// ---- 变量替换正确 ----

#[test]
fn variables_are_substituted_without_leftover_placeholders() {
    for mode in ALL_MODES {
        let out = Composer::build(mode, &full_vars());
        assert!(!out.contains("{{"), "{mode:?} 残留 {{ 占位符");
        assert!(!out.contains("}}"), "{mode:?} 残留 }} 占位符");
        for key in [
            "ai_name",
            "user_name",
            "soul",
            "workspace",
            "date",
            "user_rules",
            "memory_digest",
        ] {
            assert!(!out.contains(key), "{mode:?} 残留变量名 {key}");
        }
    }
}

#[test]
fn variable_positions_match_expected_lines() {
    let out = Composer::build(PromptMode::Craft, &full_vars());
    assert!(out.contains("你是 LAN-XIAO"));
    assert!(out.contains("本次服务对象：KIM-USR。"));
    assert!(out.contains("人格设定：\nSOUL-冷静直接先验证\n"));
    assert!(out.contains("- 日期：DATE-2026-05-06"));
    assert!(out.contains("- 工作区：WS-/home/kim/demo"));
}

#[test]
fn variable_values_are_not_rescanned_for_placeholders() {
    let mut vars = bare_vars();
    vars.soul = "{{workspace}}".into(); // 注入值里的花括号原样透传，不二次替换
    let out = Composer::build(PromptMode::Quick, &vars);
    assert!(out.contains("人格设定：\n{{workspace}}\n"));
    assert!(
        out.contains("- 工作区：/home/kim/work/demo"),
        "真实变量仍应正常注入"
    );
}

// ---- 用户自定义规则追加 ----

#[test]
fn user_rules_appended_when_non_empty() {
    let out = Composer::build(PromptMode::Craft, &full_vars());
    assert!(
        out.contains("## 用户自定义规则\nRULE-回复不超过三行"),
        "缺用户规则段"
    );
    // 追加在最后（硬规则之后）
    let hard_at = out.find("## 硬规则").unwrap();
    let rules_at = out.find("## 用户自定义规则").unwrap();
    assert!(rules_at > hard_at, "用户规则应在硬规则之后追加");
}

#[test]
fn user_rules_section_absent_when_empty() {
    for mode in ALL_MODES {
        let out = Composer::build(mode, &bare_vars());
        assert!(!out.contains("用户自定义规则"), "{mode:?} 空规则仍留段");
    }
}

// ---- 空记忆摘要不留空洞标记 ----

#[test]
fn empty_memory_digest_leaves_no_hollow_marker() {
    for mode in ALL_MODES {
        let out = Composer::build(mode, &bare_vars());
        assert!(!out.contains("记忆摘要"), "{mode:?} 空摘要仍留标题");
        assert_no_empty_section(&out);
    }
}

#[test]
fn whitespace_only_memory_digest_is_treated_as_empty() {
    let mut vars = bare_vars();
    vars.memory_digest = "   \n\t  \n".into();
    let out = Composer::build(PromptMode::Craft, &vars);
    assert!(!out.contains("记忆摘要"), "纯空白摘要未视为空");
    assert_no_empty_section(&out);
}

#[test]
fn memory_digest_holds_layered_memory_text() {
    let mut vars = bare_vars();
    vars.memory_digest =
        "长期记忆：\n- 用户偏好中文提交信息\n会话记忆：\n- 当前任务是提示词引擎".into();
    let out = Composer::build(PromptMode::Ask, &vars);
    has_all(&out, &["## 记忆摘要", "长期记忆：", "会话记忆："]);
    assert_no_empty_section(&out);
}

// ---- 确定性 ----

#[test]
fn build_is_deterministic_for_same_input() {
    for mode in ALL_MODES {
        let a = Composer::build(mode, &full_vars());
        let b = Composer::build(mode, &full_vars());
        assert_eq!(a, b, "{mode:?} 两次 build 不一致");
        let c = Composer::build(mode, &bare_vars());
        let d = Composer::build(mode, &bare_vars());
        assert_eq!(c, d, "{mode:?} 空变量两次 build 不一致");
    }
}

#[test]
fn no_clock_injection_date_comes_only_from_vars() {
    let mut vars = full_vars();
    vars.date = "DATE-FROZEN".into();
    let out = Composer::build(PromptMode::Craft, &vars);
    assert!(out.contains("- 日期：DATE-FROZEN"));
    // 只改 date，其余结构不变：差异应局限在该行
    let mut vars2 = vars.clone();
    vars2.date = "DATE-OTHER".into();
    let out2 = Composer::build(PromptMode::Craft, &vars2);
    let diff: Vec<&str> = out
        .lines()
        .zip(out2.lines())
        .filter(|(a, b)| a != b)
        .map(|(a, _)| a)
        .collect();
    assert_eq!(diff, vec!["- 日期：DATE-FROZEN"]);
}

// ---- 公开模板 API：段序列可直接构造 ----

#[test]
fn template_segments_are_public_and_renderable() {
    let tpl = PromptTemplate::new(
        PromptMode::Craft,
        vec![
            Segment::Text("# 自定义头 · {{ai_name}}\n- 工作区：{{workspace}}".into()),
            Segment::Var("soul"),
            Segment::Var("memory_digest"),
            Segment::Var("date"),        // 普通变量作为独立段时输出裸值
            Segment::Var("unknown_key"), // 未知键：整段省略
            Segment::Gate,
            Segment::Var("user_rules"),
        ],
    );
    assert_eq!(tpl.mode(), PromptMode::Craft);
    assert_eq!(tpl.segments().len(), 7);

    let out = tpl.render(&bare_vars());
    assert_eq!(
        out,
        "# 自定义头 · 小澜\n- 工作区：/home/kim/work/demo\n\n\
         人格设定：\n冷静、直接、先验证再下结论。\n\n\
         2026-05-06\n\n\
         ## 规划门禁（plan）\n\
         - 当前处于规划状态：先给出计划（目标、步骤、影响文件、验证方式、风险），等待用户批准。\n\
         - 批准之前不得承诺或暗示任何写操作已经完成，也不得发起写入、删除、命令执行、外部网络或浏览器动作。\n\
         - 计划被批准后才退出规划状态，转为实际执行。\n"
    );
}

#[test]
fn gate_segment_equals_plan_gate() {
    let tpl = PromptTemplate::new(PromptMode::Plan, vec![Segment::Gate]);
    assert_eq!(
        tpl.render(&bare_vars()),
        format!("{}\n", Composer::plan_gate())
    );
    assert!(Composer::plan_gate().starts_with("## 规划门禁（plan）"));
}
