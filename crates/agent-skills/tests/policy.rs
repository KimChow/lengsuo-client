//! `SkillPolicy` 限制元数据测试：allowed-tools 只收窄、无法解析即 fail-closed。
//!
//! 假数据：技能与工具名均为测试专用虚构名，不含真实凭据。

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use agent_skills::parse_skill_with_policy;
use agent_skills::SkillPolicy;
use tempfile::TempDir;

fn make_skill(root: &Path, dir_name: &str, content: &str) -> PathBuf {
    let dir = root.join(dir_name);
    fs::create_dir_all(&dir).expect("创建技能目录");
    fs::write(dir.join("SKILL.md"), content).expect("写入 SKILL.md");
    dir
}

/// 解析 front-matter 里的限制字段（正文仍需非空，沿用既有约束）。
fn policy_of(dir: &Path) -> SkillPolicy {
    let (_, policy) = parse_skill_with_policy(dir).expect("解析技能");
    policy
}

fn host_tools(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| (*n).to_string()).collect()
}

/// 宿主授权的工具集（顺序无关，生效集一律升序）。
const HOST: &[&str] = &["Bash", "Grep", "Read", "Write"];

#[test]
fn declared_tools_narrow_host_grant() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "narrow",
        "---\nname: narrow\nallowed-tools: Grep, Read\n---\n正文\n",
    );
    let policy = policy_of(&dir);
    assert!(policy.declares_tools, "应识别为已声明 allowed-tools");
    assert_eq!(policy.declared_tools, vec!["Grep", "Read"]);
    assert_eq!(
        policy.effective_tools(&host_tools(HOST)),
        vec!["Grep", "Read"]
    );
    assert!(policy.fail_closed_fields.is_empty());
}

#[test]
fn declared_tools_can_never_expand_host_grant() {
    let tmp = TempDir::new().unwrap();
    // 技能自报 Bash/Write，但宿主只授权 Read/Grep ⇒ 交集里没有 Bash/Write。
    let dir = make_skill(
        tmp.path(),
        "booster",
        "---\nname: booster\nallowed-tools: Bash, Write, Read\n---\n正文\n",
    );
    let policy = policy_of(&dir);
    let effective = policy.effective_tools(&host_tools(&["Grep", "Read"]));
    assert_eq!(
        effective,
        vec!["Read"],
        "超出宿主授权的声明项必须被丢弃: {effective:?}"
    );
    assert!(!effective.contains(&"Bash".to_string()));
    assert!(!effective.contains(&"Write".to_string()));
}

#[test]
fn declared_tools_intersecting_nothing_yields_no_tools() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "mismatch",
        "---\nname: mismatch\nallowed-tools: Bash\n---\n正文\n",
    );
    let policy = policy_of(&dir);
    assert!(
        policy
            .effective_tools(&host_tools(&["Read", "Grep"]))
            .is_empty(),
        "声明项与宿主授权无交集 ⇒ 生效集为空（不扩大）"
    );
}

#[test]
fn no_declaration_inherits_host_grant_without_expanding() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(tmp.path(), "plain", "---\nname: plain\n---\n正文\n");
    let policy = policy_of(&dir);
    assert!(!policy.declares_tools, "未声明 allowed-tools");
    assert_eq!(
        policy.effective_tools(&host_tools(HOST)),
        vec!["Bash", "Grep", "Read", "Write"],
        "未声明即不额外收窄，但仍不超出宿主授权"
    );
    // 宿主不授权任何工具时，未声明也不凭空获得工具。
    assert!(policy.effective_tools(&BTreeSet::new()).is_empty());
}

#[test]
fn flow_sequence_of_bare_names_is_supported() {
    let tmp = TempDir::new().unwrap();
    for (case, value, want) in [
        ("带空格", "[Read, Grep]", vec!["Grep", "Read"]),
        ("无空格", "[Read,Grep]", vec!["Grep", "Read"]),
        ("单项", "[Read]", vec!["Read"]),
    ] {
        let dir = make_skill(
            tmp.path(),
            "flow",
            &format!("---\nname: flow\nallowed-tools: {value}\n---\n正文\n"),
        );
        let policy = policy_of(&dir);
        assert_eq!(policy.declared_tools, want, "{case} 应支持: {policy:?}");
        assert!(
            policy.fail_closed_fields.is_empty(),
            "{case} 不该 fail-closed"
        );
    }
}

#[test]
fn unsupported_allowed_tools_syntax_fails_closed_to_no_tools() {
    let tmp = TempDir::new().unwrap();
    // 工具参数级限定与内联注释不在本卡支持范围：不可靠解析 ⇒ fail-closed，
    // 绝不能当成「不限制工具」。
    for case in [
        "Bash(git add:*)",
        "Read, Bash(ls:*)",
        "Read Write",
        "Read # 只读",
        "[Read",
        "Read]",
    ] {
        let dir = make_skill(
            tmp.path(),
            "bad",
            &format!("---\nname: bad\nallowed-tools: {case}\n---\n正文\n"),
        );
        let policy = policy_of(&dir);
        let effective = policy.effective_tools(&host_tools(HOST));
        assert!(
            effective.is_empty(),
            "{case:?} 应 fail-closed 为空集: {effective:?}"
        );
        assert!(
            policy
                .fail_closed_fields
                .contains(&"allowed-tools".to_string()),
            "{case:?} 应记录 fail-closed 字段: {policy:?}"
        );
    }
}

#[test]
fn explicit_empty_allowed_tools_declares_no_tools() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "none",
        "---\nname: none\nallowed-tools:\n---\n正文\n",
    );
    let policy = policy_of(&dir);
    assert!(
        policy.declares_tools,
        "显式空值仍是已声明（只是声明为空集）"
    );
    assert!(policy.declared_tools.is_empty());
    assert!(policy.effective_tools(&host_tools(HOST)).is_empty());
    assert!(
        !policy
            .fail_closed_fields
            .contains(&"allowed-tools".to_string()),
        "空值可可靠解析，不算 fail-closed 降级: {policy:?}"
    );
}

#[test]
fn invocation_flags_default_to_open_for_both_sources() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(tmp.path(), "both", "---\nname: both\n---\n正文\n");
    let policy = policy_of(&dir);
    assert!(policy.allows(agent_skills::InvocationSource::User));
    assert!(policy.allows(agent_skills::InvocationSource::Model));
    assert!(policy.fail_closed_fields.is_empty());
}

#[test]
fn disable_model_invocation_blocks_only_model() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "user-only",
        "---\nname: user-only\ndisable-model-invocation: true\n---\n正文\n",
    );
    let policy = policy_of(&dir);
    assert!(policy.disable_model_invocation);
    assert!(
        policy.allows(agent_skills::InvocationSource::User),
        "用户显式触发仍可行"
    );
    assert!(
        !policy.allows(agent_skills::InvocationSource::Model),
        "模型自助调用必须被拒"
    );
}

#[test]
fn user_invocable_false_blocks_only_user() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "internal",
        "---\nname: internal\nuser-invocable: false\n---\n正文\n",
    );
    let policy = policy_of(&dir);
    assert!(!policy.user_invocable);
    assert!(
        !policy.allows(agent_skills::InvocationSource::User),
        "用户菜单显式触发必须被拒"
    );
    assert!(policy.allows(agent_skills::InvocationSource::Model));
}

#[test]
fn both_flags_set_blocks_every_invocation_source() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "sealed",
        "---\nname: sealed\ndisable-model-invocation: true\nuser-invocable: false\n---\n正文\n",
    );
    let policy = policy_of(&dir);
    assert!(!policy.allows(agent_skills::InvocationSource::User));
    assert!(!policy.allows(agent_skills::InvocationSource::Model));
}

#[test]
fn unparsable_flag_values_take_safe_defaults() {
    let tmp = TempDir::new().unwrap();
    // 布尔值只认字面 true/false；`yes`/`1`/`True` 之类一律按最保守方向处理。
    let dir = make_skill(
        tmp.path(),
        "soft-disable",
        "---\nname: soft-disable\ndisable-model-invocation: yes\n---\n正文\n",
    );
    let policy = policy_of(&dir);
    assert!(
        policy.disable_model_invocation,
        "不可靠的 disable-model-invocation 必须 fail-closed 为 true: {policy:?}"
    );
    assert!(
        policy
            .fail_closed_fields
            .contains(&"disable-model-invocation".to_string()),
        "应记录降级字段: {policy:?}"
    );

    let dir2 = make_skill(
        tmp.path(),
        "soft-user",
        "---\nname: soft-user\nuser-invocable: True\n---\n正文\n",
    );
    let policy2 = policy_of(&dir2);
    assert!(
        !policy2.user_invocable,
        "不可靠的 user-invocable 必须 fail-closed 为 false: {policy2:?}"
    );
    assert!(policy2
        .fail_closed_fields
        .contains(&"user-invocable".to_string()));
}

#[test]
fn quoted_flag_values_are_accepted() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "quoted",
        "---\nname: quoted\ndisable-model-invocation: \"true\"\nallowed-tools: 'Read'\n---\n正文\n",
    );
    let policy = policy_of(&dir);
    assert!(policy.disable_model_invocation);
    assert_eq!(policy.declared_tools, vec!["Read"]);
    assert!(
        policy.fail_closed_fields.is_empty(),
        "引号已支持: {policy:?}"
    );
}

#[test]
fn skills_without_front_matter_get_open_default_policy() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(tmp.path(), "bare", "正文而已\n");
    let policy = policy_of(&dir);
    assert_eq!(policy, SkillPolicy::default());
    assert!(!policy.declares_tools);
    assert!(policy.allows(agent_skills::InvocationSource::User));
    assert!(policy.allows(agent_skills::InvocationSource::Model));
    // 未声明限制仍不可能超出宿主授权。
    assert_eq!(policy.effective_tools(&host_tools(&["Read"])), vec!["Read"]);
    assert!(policy.effective_tools(&BTreeSet::new()).is_empty());
}

#[test]
fn unrelated_front_matter_keys_do_not_affect_policy() {
    let tmp = TempDir::new().unwrap();
    let dir = make_skill(
        tmp.path(),
        "noise",
        "---\nname: noise\nmodel: sonnet\nallowed_tools: Read\nlicense: MIT\n---\n正文\n",
    );
    let policy = policy_of(&dir);
    // 下划线变体不在支持范围：既不识别为声明，也不记为降级字段（未知 key 忽略）。
    assert!(
        !policy.declares_tools,
        "未知 key 不当作限制声明: {policy:?}"
    );
    assert!(policy.fail_closed_fields.is_empty(), "实得 {policy:?}");
    assert_eq!(policy.effective_tools(&host_tools(&["Read"])), vec!["Read"]);
}
