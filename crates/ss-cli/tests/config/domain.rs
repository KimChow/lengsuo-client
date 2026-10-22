// ---- 域名匹配与路由引擎：大小写归一、后缀锚定、首个命中优先 ----

// ---------------------------------------------------------------------------
// §13.1 测试清单 #3 通配与域名匹配（用于验证 §10.3 #15 小写归一化与 #16 精确匹配）
// ---------------------------------------------------------------------------

fn rule(domain: &str, suffixes: &[&str], action: Action) -> Rule {
    Rule {
        name: "r".into(),
        r#match: ss_cli::config::Match {
            domain: domain.into(),
            domain_suffix: suffixes.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        },
        action,
    }
}

#[test]
fn domain_match_is_case_insensitive_exact() {
    let m = ss_cli::config::Match {
        domain: "EXAMPLE.com".into(),
        ..Default::default()
    };
    assert!(m.matches("example.com"));
    assert!(!m.matches("sub.example.com"));
    assert!(!m.matches("example.com."));
    assert!(!m.matches("exampleXcom"));
}

#[test]
fn domain_suffix_anchored_at_dot_label() {
    let m = ss_cli::config::Match {
        domain_suffix: vec!["example.com".into()],
        ..Default::default()
    };
    assert!(m.matches("example.com"));
    assert!(m.matches("a.example.com"));
    assert!(m.matches("a.b.example.com"));
    assert!(!m.matches("fooexample.com"));
    assert!(!m.matches("notexample.com"));
}

#[test]
fn rule_engine_first_match_wins_case_insensitive_and_cidr() {
    let cfg = Fixture::default().cfg;
    assert_eq!(cfg.match_route("192.168.1.1").action, Action::Direct);
    assert_eq!(cfg.match_route("10.20.30.40").action, Action::Direct);
    assert_eq!(cfg.match_route("8.8.8.8").action, Action::Proxy);
    assert_eq!(
        cfg.match_route("2001:4860:4860::8888").action,
        Action::Proxy
    );
}

#[test]
fn full_pipeline_config_then_rule_engine() {
    let p = setup::tmp("cfg-pipeline", "pipeline.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_88__@1.2.3.4:8388"
rules:
  - name: corp
    match:
      domain_suffix: ["corp.Example.COM"]
    action: direct
  - name: any
    match: {}
    action: proxy
"#,
    )
    .unwrap();
    let cfg = ss_cli::config::load_config(&p).unwrap();
    assert_eq!(
        cfg.match_route("api.corp.example.com").action,
        Action::Direct
    );
    assert_eq!(cfg.match_route("www.example.com").action, Action::Proxy);
    let _ = std::fs::remove_file(&p);
}
