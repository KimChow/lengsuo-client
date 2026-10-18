//! 权限精简（permission-slim）：execpolicy 资源级门 + 沙箱优先门（wb A22-1）。
//!
//! 覆盖黄金向量与设计文档 §3/§4：
//! - `.ssh/id_rsa` 读 → deny（即使 saved allow）；`.cargo/registry` → allow；未知域名 → ask；
//! - saved allow 覆盖项目层 ask；deny 层不被 saved 覆盖；
//! - 多请求汇总：任一 deny → deny；ask+allow 混合 → ask；
//! - 沙箱优先：probe Some + 命令类 → allow；probe None → 仍 ask；
//! - 工具级门短路顺序不变（未注册/白名单/readonly 仍是 deny，敏感动作仍是 ask）。

use std::collections::BTreeSet;

use agent_core::permission::{Decision, PermissionGate};
use agent_core::schema::{Mode, PermissionMode};
use agent_core::tool::{ToolKind, ToolRegistry, ToolSpec};
use agent_execpolicy::{AccessKind, Decision as PolicyDecision, Matcher, Policy, Rule};
use serde_json::json;

fn registry() -> ToolRegistry {
    let mut r = ToolRegistry::new();
    for (name, kind, sensitive) in [
        ("fs.read", ToolKind::Read, false),
        ("fs.write", ToolKind::Write, true),
        ("net.fetch", ToolKind::Network, false),
        ("shell.exec", ToolKind::Exec, true),
    ] {
        r.register(ToolSpec {
            name: name.into(),
            description: format!("{name} 测试用"),
            kind,
            sensitive_arguments: sensitive,
            timeout_ms: 5_000,
        });
    }
    r
}

fn rule(pattern: &str, decision: PolicyDecision) -> Rule {
    Rule {
        pattern: pattern.into(),
        matcher: Matcher::Glob,
        decision,
        reason: None,
    }
}

/// 策略层装进单段规则的辅助。
fn policy_segment(kind: AccessKind, rules: Vec<Rule>) -> Policy {
    let mut p = Policy::empty();
    match kind {
        AccessKind::File => p.file = rules,
        AccessKind::Process => p.process = rules,
        AccessKind::Network => p.network = rules,
    }
    p
}

/// 基线门：内置安全基线 + 全工具白名单（Craft），无 auto 放行。
fn base_gate() -> PermissionGate {
    PermissionGate::new(registry())
        .with_whitelist(
            Mode::Craft,
            BTreeSet::from([
                "fs.read".to_string(),
                "fs.write".to_string(),
                "shell.exec".to_string(),
                "net.fetch".to_string(),
            ]),
        )
        .with_policy(Policy::security_baseline())
}

// ---------- 黄金向量：安全基线 ----------

#[test]
fn ssh_key_read_is_denied_by_baseline() {
    let g = base_gate().with_auto_allowed("fs.read");
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "fs.read",
        &json!({"path": ".ssh/id_rsa"}),
    );
    assert!(matches!(d, Decision::Deny(_)), "基线 deny 必须命中：{d:?}");
    assert!(
        !d.explain().contains(".ssh/id_rsa"),
        "deny 说明不回显参数值：{}",
        d.explain()
    );
}

#[test]
fn ssh_deny_survives_saved_allow() {
    // 用户曾「永久允许」读 .ssh —— deny 层不被 saved 覆盖（phase1 先查配置层）。
    let saved = policy_segment(
        AccessKind::File,
        vec![rule(".ssh/**", PolicyDecision::Allow)],
    );
    let g = base_gate().with_saved_policy(saved);
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "fs.read",
        &json!({"path": ".ssh/id_rsa"}),
    );
    assert!(
        matches!(d, Decision::Deny(_)),
        "saved allow 不得越过 deny：{d:?}"
    );
}

#[test]
fn cargo_registry_read_is_allowed() {
    let g = base_gate();
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "fs.read",
        &json!({"path": ".cargo/registry/cache"}),
    );
    assert_eq!(d, Decision::Allow, "包管理器缓存基线放行");
}

#[test]
fn unknown_domain_asks_known_allowed_domain_allows() {
    // 已知域名 allow 规则放宽审批（phase2 全 allow）；未知域名无命中 → 维持 ask（fail-closed）。
    let known = policy_segment(
        AccessKind::Network,
        vec![rule("example.com", PolicyDecision::Allow)],
    );
    let g = base_gate().with_policy(known);
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "net.fetch",
        &json!({"url": "https://example.com/x"}),
    );
    assert_eq!(d, Decision::Allow, "已放行域名 → allow");
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "net.fetch",
        &json!({"url": "https://unknown-domain.org/x"}),
    );
    assert_eq!(d, Decision::Ask, "未知域名无规则 → ask");
}

// ---------- 分层语义：saved 覆盖项目层 ask ----------

#[test]
fn saved_allow_overrides_project_ask_layer() {
    let project = policy_segment(
        AccessKind::File,
        vec![rule("secrets/**", PolicyDecision::Ask)],
    );
    let saved = policy_segment(
        AccessKind::File,
        vec![rule("secrets/**", PolicyDecision::Allow)],
    );
    let g = base_gate().with_policy(project).with_saved_policy(saved);
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "fs.read",
        &json!({"path": "secrets/token.txt"}),
    );
    assert_eq!(d, Decision::Allow, "saved（后层）覆盖项目层 ask");
}

#[test]
fn project_deny_overrides_saved_allow_layer_absence() {
    // deny 在配置层：saved 存在也无法放行。
    let project = policy_segment(
        AccessKind::Network,
        vec![rule("*.evil", PolicyDecision::Deny)],
    );
    let saved = policy_segment(AccessKind::Network, vec![rule("**", PolicyDecision::Allow)]);
    let g = base_gate().with_policy(project).with_saved_policy(saved);
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "net.fetch",
        &json!({"url": "https://api.evil/x"}),
    );
    assert!(
        matches!(d, Decision::Deny(_)),
        "deny 层不被 saved 覆盖：{d:?}"
    );
}

// ---------- 多请求汇总 ----------

#[test]
fn multi_path_any_deny_denies_all() {
    let g = base_gate().with_auto_allowed("fs.read");
    // 一次列出两个路径：一个命中 deny（.ssh），一个放行（.cargo）→ 整体 deny。
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "fs.read",
        &json!({"paths": [".cargo/registry/x", ".ssh/id_rsa"]}),
    );
    assert!(
        matches!(d, Decision::Deny(_)),
        "任一请求 deny → 整体 deny：{d:?}"
    );
}

#[test]
fn multi_path_ask_plus_allow_asks() {
    // 无 auto 放行时 ask+ask 也是 ask；这里构造 allow+ask 混合：
    // .cargo allow、未知路径无规则 ask → 汇总 ask。
    let g = base_gate();
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "fs.read",
        &json!({"paths": [".cargo/registry/x", "docs/readme.md"]}),
    );
    assert_eq!(d, Decision::Ask, "ask+allow 混合 → ask");
}

// ---------- 沙箱优先门（A22-1） ----------

#[test]
fn sandbox_available_allows_command_without_approval() {
    let g = base_gate().with_sandbox_probe(|| Some("LinuxSeccomp".to_string()));
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "shell.exec",
        &json!({"command": "ls -la"}),
    );
    assert_eq!(d, Decision::Allow, "可沙箱的命令类工具跳过人工审批");
}

#[test]
fn no_sandbox_keeps_ask() {
    let g = base_gate(); // probe 未注入 = None
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "shell.exec",
        &json!({"command": "ls -la"}),
    );
    assert_eq!(d, Decision::Ask, "无沙箱后端维持 ask，不退化为放行");
}

#[test]
fn sandbox_probe_none_string_keeps_ask() {
    let g = base_gate().with_sandbox_probe(|| None);
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "shell.exec",
        &json!({"command": "ls -la"}),
    );
    assert_eq!(d, Decision::Ask);
}

#[test]
fn sandbox_does_not_skip_sensitive_ask() {
    // 敏感动作强制 ask 是不可配置跳过的红线：沙箱优先门不得越过它。
    let g = base_gate().with_sandbox_probe(|| Some("LinuxSeccomp".to_string()));
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "shell.exec",
        &json!({"command": "rm -rf /"}),
    );
    assert_eq!(d, Decision::Ask, "敏感动作必须仍是 ask");
}

#[test]
fn sandbox_gate_does_not_rescue_denied_command() {
    let project = policy_segment(
        AccessKind::Process,
        vec![rule("shutdown**", PolicyDecision::Deny)],
    );
    let g = base_gate()
        .with_policy(project)
        .with_sandbox_probe(|| Some("LinuxSeccomp".to_string()));
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "shell.exec",
        &json!({"command": "shutdown now"}),
    );
    assert!(matches!(d, Decision::Deny(_)), "deny 仍是 deny：{d:?}");
}

// ---------- 工具级门短路顺序不变（对外契约） ----------

#[test]
fn tool_level_short_circuits_are_preserved() {
    let g = base_gate();
    assert!(
        matches!(
            g.check(Mode::Craft, PermissionMode::Full, "not.a.tool", &json!({})),
            Decision::Deny(_)
        ),
        "未注册仍 deny"
    );
    assert!(
        matches!(
            g.check(
                Mode::Ask,
                PermissionMode::Full,
                "fs.read",
                &json!({"path": "a.txt"})
            ),
            Decision::Deny(_)
        ),
        "白名单缺失仍 deny"
    );
    assert!(
        matches!(
            g.check(
                Mode::Craft,
                PermissionMode::ReadOnly,
                "shell.exec",
                &json!({"command": "ls"})
            ),
            Decision::Deny(_)
        ),
        "readonly 仍挡执行类"
    );
}

#[test]
fn policy_allow_reshapes_explain() {
    let g = base_gate();
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "fs.read",
        &json!({"path": ".cargo/registry/x"}),
    );
    assert_eq!(d, Decision::Allow);
    assert!(
        d.explain().starts_with("allow:"),
        "explain 风格不变：{}",
        d.explain()
    );
}

// ---------- 内置基线的隐式追加（不依赖调用方显式装基线） ----------

#[test]
fn implicit_baseline_denies_ssh_without_explicit_policy() {
    // 只配白名单、不装任何 with_policy：内置安全基线仍须生效（资源级门隐式追加）。
    let g = PermissionGate::new(registry())
        .with_whitelist(Mode::Craft, BTreeSet::from(["fs.read".to_string()]));
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "fs.read",
        &json!({"path": ".ssh/id_rsa"}),
    );
    assert!(matches!(d, Decision::Deny(_)), "隐式基线必须拦 .ssh：{d:?}");
}

// ---------- 命令串中的 URL 派生 Network 请求 ----------

#[test]
fn exec_command_url_is_assessed_against_network_rules() {
    let project = policy_segment(
        AccessKind::Network,
        vec![rule("*.evil", PolicyDecision::Deny)],
    );
    let g = base_gate().with_policy(project);
    let d = g.check(
        Mode::Craft,
        PermissionMode::Full,
        "shell.exec",
        &json!({"command": "curl https://api.evil/x"}),
    );
    assert!(
        matches!(d, Decision::Deny(_)),
        "命令串里的 URL 也要过网络规则：{d:?}"
    );
}

// ---------- 无资源请求的工具：维持工具级底案（fail-closed，不主动放宽） ----------

#[test]
fn tool_without_resource_requests_keeps_tool_verdict() {
    // 设计 §3 的「空 reqs」在资源级门内解读为「本门不施加约束」，
    // 最终结论仍是工具级底案：白名单内但未 auto 放行 → ask（deny-by-default 不退化为放行）。
    let g = base_gate();
    let d = g.check(Mode::Craft, PermissionMode::Full, "fs.read", &json!({}));
    assert_eq!(d, Decision::Ask, "无资源请求不得自动放宽为 allow");
}
