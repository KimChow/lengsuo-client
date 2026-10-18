//! 黄金向量：策略判定语义（首个命中生效、无命中 Ask）与安全基线（wb tsbx_rules 形态）。
//!
//! 目标串按约定为「相对家目录归一化后的字符串」：`.ssh/id_rsa`、`example.com`、
//! `rm -rf /var/tmp/x` 等。纯逻辑断言，无 IO、无平台依赖。

use agent_execpolicy::{
    assess, AccessKind, AccessRequest, Assessment, Decision, Matcher, Policy, Rule,
};

fn req(kind: AccessKind, target: &str) -> AccessRequest {
    AccessRequest {
        kind,
        target: target.to_string(),
    }
}

fn rule(matcher: Matcher, pattern: &str, decision: Decision) -> Rule {
    Rule {
        pattern: pattern.to_string(),
        matcher,
        decision,
        reason: None,
    }
}

fn glob(pattern: &str, decision: Decision) -> Rule {
    rule(Matcher::Glob, pattern, decision)
}

fn prefix(pattern: &str, decision: Decision) -> Rule {
    rule(Matcher::Prefix, pattern, decision)
}

/// 单段策略构造器（file/process/network 之一）。
fn policy_one(section: AccessKind, rules: Vec<Rule>) -> Policy {
    let mut p = Policy::empty();
    match section {
        AccessKind::File => p.file = rules,
        AccessKind::Process => p.process = rules,
        AccessKind::Network => p.network = rules,
    }
    p
}

// ---------- 安全基线（Default / security_baseline） ----------

#[test]
fn baseline_denies_ssh_read() {
    let a = assess(
        &Policy::security_baseline(),
        &req(AccessKind::File, ".ssh/id_ed25519"),
    );
    assert_eq!(a.decision, Decision::Deny);
    assert!(a.matched_rule.is_some());
}

#[test]
fn baseline_denies_ssh_nested_any_operation() {
    // "全操作（含读取）"：深层路径同样落 Deny（glob ** 跨段）。
    let a = assess(
        &Policy::security_baseline(),
        &req(AccessKind::File, ".ssh/keys/sub/id_rsa"),
    );
    assert_eq!(a.decision, Decision::Deny);
}

#[test]
fn baseline_denies_gnupg_write() {
    let a = assess(
        &Policy::security_baseline(),
        &req(AccessKind::File, ".gnupg/private-keys-v1.d/key.key"),
    );
    assert_eq!(a.decision, Decision::Deny);
}

#[test]
fn baseline_allows_package_manager_caches() {
    // 包管理器缓存目录全部 Allow（读）。
    for target in [
        ".cargo/registry/index",
        ".npm/_cacache/content",
        ".rustup/toolchains/stable",
        ".cache/pip/http-v2/abc",
        ".cache/go-build/aa/a1b2",
        ".m2/repository/org/example/pom",
        ".gradle/caches/modules",
        ".nuget/packages/newtonsoft.json",
    ] {
        let a = assess(&Policy::security_baseline(), &req(AccessKind::File, target));
        assert_eq!(a.decision, Decision::Allow, "target={target}");
    }
}

#[test]
fn baseline_unknown_network_domain_is_ask() {
    let a = assess(
        &Policy::security_baseline(),
        &req(AccessKind::Network, "example.com"),
    );
    assert_eq!(a.decision, Decision::Ask);
    assert!(a.matched_rule.is_none());
}

#[test]
fn baseline_process_is_ask() {
    let a = assess(
        &Policy::security_baseline(),
        &req(AccessKind::Process, "rm -rf /var/tmp/scratch"),
    );
    assert_eq!(a.decision, Decision::Ask);
}

#[test]
fn baseline_can_be_replaced_by_custom_policy() {
    // 基线可被自定义策略覆盖：自定义策略未写 .ssh 规则 ⇒ .ssh 读取回到 Ask。
    let custom = policy_one(AccessKind::File, vec![glob("**", Decision::Allow)]);
    let a = assess(&custom, &req(AccessKind::File, ".ssh/id_rsa"));
    assert_eq!(a.decision, Decision::Allow);
    // 规格：安全基线即默认策略（Default），可被自定义策略整体替换；
    // 无规则的策略需显式 Policy::empty() 构造。
    assert_eq!(Policy::default(), Policy::security_baseline());
    assert_ne!(Policy::default(), Policy::empty());
}

// ---------- 判定语义 ----------

#[test]
fn no_rules_never_matches_yields_ask() {
    let a = assess(&Policy::empty(), &req(AccessKind::File, "anything.txt"));
    assert_eq!(a.decision, Decision::Ask);
    assert!(a.matched_rule.is_none());
    assert!(!a.reason.is_empty());
}

#[test]
fn first_matching_rule_wins() {
    // 两条都命中的规则：排前者生效，排后者的相反决策被忽略。
    let early_allow = policy_one(
        AccessKind::File,
        vec![
            glob("docs/**", Decision::Allow),
            glob("**/*.md", Decision::Deny),
        ],
    );
    let a = assess(&early_allow, &req(AccessKind::File, "docs/notes.md"));
    assert_eq!(a.decision, Decision::Allow);

    let early_deny = policy_one(
        AccessKind::File,
        vec![
            glob("**/*.md", Decision::Deny),
            glob("docs/**", Decision::Allow),
        ],
    );
    let a = assess(&early_deny, &req(AccessKind::File, "docs/notes.md"));
    assert_eq!(a.decision, Decision::Deny);
}

#[test]
fn sections_do_not_leak_across_kinds() {
    // file 段的 Deny 不影响 network 判定（各段独立）。
    let p = policy_one(AccessKind::File, vec![glob("**", Decision::Deny)]);
    assert_eq!(
        assess(&p, &req(AccessKind::Network, "example.org")).decision,
        Decision::Ask
    );
    assert_eq!(
        assess(&p, &req(AccessKind::File, "x")).decision,
        Decision::Deny
    );
}

// ---------- glob 边界（** 与 *） ----------

#[test]
fn single_star_does_not_cross_slash() {
    let p = policy_one(AccessKind::File, vec![glob("logs/*.log", Decision::Deny)]);
    assert_eq!(
        assess(&p, &req(AccessKind::File, "logs/a.log")).decision,
        Decision::Deny
    );
    assert_eq!(
        assess(&p, &req(AccessKind::File, "logs/sub/a.log")).decision,
        Decision::Ask,
        "* 不得跨 /"
    );
}

#[test]
fn double_star_crosses_and_matches_zero_segments() {
    let p = policy_one(
        AccessKind::File,
        vec![glob("logs/**/*.log", Decision::Deny)],
    );
    // ** 匹配零段：logs/a.log
    assert_eq!(
        assess(&p, &req(AccessKind::File, "logs/a.log")).decision,
        Decision::Deny
    );
    // ** 匹配多段：logs/x/y/a.log
    assert_eq!(
        assess(&p, &req(AccessKind::File, "logs/x/y/a.log")).decision,
        Decision::Deny
    );
    // 不匹配前缀不同目录
    assert_eq!(
        assess(&p, &req(AccessKind::File, "other/a.log")).decision,
        Decision::Ask
    );
}

#[test]
fn double_star_matches_everything_below_prefix() {
    let p = policy_one(AccessKind::File, vec![glob(".ssh/**", Decision::Deny)]);
    for target in [".ssh/a", ".ssh/a/b", ".ssh/a/b/c/d.txt"] {
        assert_eq!(
            assess(&p, &req(AccessKind::File, target)).decision,
            Decision::Deny,
            "target={target}"
        );
    }
    // ".ssh" 本体不在 ".ssh/**" 语义内（文档化边界）。
    assert_eq!(
        assess(&p, &req(AccessKind::File, ".ssh")).decision,
        Decision::Ask
    );
}

#[test]
fn question_mark_matches_one_char_not_slash() {
    let p = policy_one(AccessKind::File, vec![glob("a?c", Decision::Deny)]);
    assert_eq!(
        assess(&p, &req(AccessKind::File, "abc")).decision,
        Decision::Deny
    );
    assert_eq!(
        assess(&p, &req(AccessKind::File, "a/c")).decision,
        Decision::Ask,
        "? 不得匹配 /"
    );
}

#[test]
fn prefix_matcher_is_literal_startswith() {
    let p = policy_one(AccessKind::Process, vec![prefix("rm ", Decision::Deny)]);
    assert_eq!(
        assess(&p, &req(AccessKind::Process, "rm -rf /tmp/x")).decision,
        Decision::Deny
    );
    assert_eq!(
        assess(&p, &req(AccessKind::Process, "echo rm hi")).decision,
        Decision::Ask
    );
}

// ---------- 规则文件格式（tsbx_rules.json 三段式） ----------

const TSBX_JSON: &str = r#"{
  "file": [
    { "pattern": ".ssh/**",    "match": "glob",   "decision": "deny",  "reason": "ssh 私钥" },
    { "pattern": ".gnupg/**",  "match": "glob",   "decision": "deny",  "reason": "gnupg 密钥" },
    { "pattern": ".cargo/",    "match": "prefix", "decision": "allow", "reason": "cargo 缓存" }
  ],
  "process": [
    { "pattern": "sudo ", "match": "prefix", "decision": "deny", "reason": "禁止提权" }
  ],
  "network": [
    { "pattern": "*.internal.example", "match": "glob", "decision": "allow" }
  ]
}"#;

#[test]
fn parses_tsbx_shaped_json_and_assesses() {
    let p = Policy::from_json_str(TSBX_JSON).expect("合法规则文件应解析成功");
    let a = assess(&p, &req(AccessKind::File, ".ssh/id_rsa"));
    assert_eq!(a.decision, Decision::Deny);
    assert_eq!(a.reason, "ssh 私钥");
    assert_eq!(
        assess(&p, &req(AccessKind::File, ".cargo/registry")).decision,
        Decision::Allow
    );
    assert_eq!(
        assess(&p, &req(AccessKind::Process, "sudo shutdown")).decision,
        Decision::Deny
    );
    assert_eq!(
        assess(&p, &req(AccessKind::Network, "api.internal.example")).decision,
        Decision::Allow
    );
    // 未提供 reason 的命中规则：自动生成非空理由。
    let a = assess(&p, &req(AccessKind::Network, "api.internal.example"));
    assert!(!a.reason.is_empty());
    assert!(matches!(
        a,
        Assessment {
            matched_rule: Some(_),
            ..
        }
    ));
}

#[test]
fn json_round_trip_is_stable() {
    let p = Policy::from_json_str(TSBX_JSON).unwrap();
    let s = p.to_json_string().unwrap();
    let p2 = Policy::from_json_str(&s).unwrap();
    assert_eq!(p, p2);
}

#[test]
fn missing_sections_deserialize_to_empty() {
    // 只有 file 段的文件：process/network 缺省为空 ⇒ 相应请求 Ask。
    let p = Policy::from_json_str(r#"{"file":[]}"#).unwrap();
    assert_eq!(
        assess(&p, &req(AccessKind::Process, "ls")).decision,
        Decision::Ask
    );
}

#[test]
fn unknown_field_is_rejected_fail_closed() {
    // 拼错的字段（decison）不得被静默忽略。
    let bad = r#"{"file":[{"pattern":"a","match":"glob","decison":"allow"}]}"#;
    assert!(Policy::from_json_str(bad).is_err());
}

#[test]
fn unknown_decision_or_matcher_is_rejected() {
    assert!(Policy::from_json_str(
        r#"{"file":[{"pattern":"a","match":"glob","decision":"maybe"}]}"#
    )
    .is_err());
    assert!(Policy::from_json_str(
        r#"{"file":[{"pattern":"a","match":"regex","decision":"allow"}]}"#
    )
    .is_err());
}

#[test]
fn required_rule_fields_must_be_present() {
    // match 与 pattern、decision 都是必填：缺任一报错，不给隐式默认。
    assert!(Policy::from_json_str(r#"{"file":[{"pattern":"a","decision":"allow"}]}"#).is_err());
    assert!(Policy::from_json_str(r#"{"file":[{"match":"glob","decision":"allow"}]}"#).is_err());
    assert!(Policy::from_json_str(r#"{"file":[{"pattern":"a","match":"glob"}]}"#).is_err());
}
