mod setup;

use setup::Fixture;
use ss_cli::config::{Action, MuxConfig, Rule, SsUrlError};

// ---------------------------------------------------------------------------
// §13.1 SS URL 解析（§10.2 #16）
// ---------------------------------------------------------------------------

#[test]
fn parses_full_url_and_roundtrips() {
    let raw = "ss://chacha20-ietf-poly1305:https://ardot.tencent.com/file/...@198.51.100.7:8443#home";
    let u = ss_cli::config::SsUrl::parse(raw).unwrap();
    assert_eq!(u.method.0, "chacha20-ietf-poly1305");
    assert_eq!(u.password, "https://ardot.tencent.com/file/...");
    assert_eq!(u.addr.ip().to_string(), "198.51.100.7");
    assert_eq!(u.addr.port(), 8443);
    assert_eq!(u.remark.as_deref(), Some("home"));
    assert_eq!(u.to_string(), raw);
}

#[test]
fn accepts_all_supported_cipher_names_case_insensitively() {
    for m in [
        "aes-128-gcm",
        "AES-192-GCM",
        "Chacha20-IETF-Poly1305",
        "aes-256-gcm",
    ] {
        let raw = format!("ss://{m}:http://localhost:8080@127.0.0.1:1080");
        let u = ss_cli::config::SsUrl::parse(&raw)
            .unwrap_or_else(|e| panic!("{m} rejected: {e:?}"));
        assert_eq!(u.method.0, m.to_lowercase());
    }
}

#[test]
fn rejects_unknown_cipher() {
    let raw = "ss://rc4-md5:https://ardot.tencent.com/file/@127.0.0.1:1080";
    assert!(matches!(
        ss_cli::config::SsUrl::parse(raw),
        Err(SsUrlError::UnsupportedMethod(_))
    ));
}

#[test]
fn rejects_missing_scheme_and_blank_fields() {
    assert!(matches!(
        ss_cli::config::SsUrl::parse("198.51.100.7:8443"),
        Err(SsUrlError::MissingScheme)
    ));
    assert!(matches!(
        ss_cli::config::SsUrl::parse("ss://@127.0.0.1:1080"),
        Err(SsUrlError::EmptyCredentials)
    ));
    assert!(matches!(
        ss_cli::config::SsUrl::parse("ss://aes-256-gcm:pw@"),
        Err(SsUrlError::MissingHost)
    ));
}

#[test]
fn rejects_invalid_port() {
    let raw = "ss://aes-256-gcm:否已开通@127.0.0.1:99999";
    assert!(matches!(
        ss_cli::config::SsUrl::parse(raw),
        Err(SsUrlError::InvalidPort)
    ));
}

#[test]
fn debug_redacts_password_in_all_three_paths() {
    let u = ss_cli::config::SsUrl::parse("ss://aes-256-gcm:SECRETPW@127.0.0.1:1080").unwrap();
    let dbg = format!("{u:?}");
    assert!(dbg.contains("__SEC_b13c1893b368b445dc07d100cad4c85d_70__"), "{dbg}");
    assert!(!dbg.contains("SECRETPW"), "{dbg}");

    let err = ss_cli::config::SsUrl::parse("ss://aes-256-gcm:SECRETPW@")
        .err()
        .unwrap();
    let edbg = format!("{err:?}");
    assert!(!edbg.contains("SECRETPW"), "{edbg}");

    let cfg = Fixture::default().cfg;
    let cdbg = format!("{cfg:?}");
    assert!(!cdbg.contains("https://raw.githubusercontent.com/sagernet/sing-shadowsocks/main/LICENSE"), "{cdbg}");
    let json = serde_json::to_string(&cfg).unwrap();
    assert!(!json.contains("https://raw.githubusercontent.com/sagernet/sing-shadowsocks/main/LICENSE"), "{json}");
    let disp = format!("{}", cfg.outbound.ss_url);
    assert!(!disp.contains("https://raw.githubusercontent.com/sagernet/sing-shadowsocks/main/LICENSE"), "{disp}");
}

// ---------------------------------------------------------------------------
// §13.1 配置加载与校验（§10.2 #17）
// ---------------------------------------------------------------------------

#[test]
fn valid_yaml_fixture_loads_with_expected_fields() {
    let f = Fixture::default();
    let cfg = &f.cfg;
    assert_eq!(cfg.rules.len(), 2);
    assert_eq!(cfg.rules[0].name, "lan-direct");
    assert!(matches!(cfg.rules[0].action, Action::Direct));
    assert_eq!(cfg.rules[1].name, "proxy-else");
    assert!(matches!(cfg.rules[1].action, Action::Proxy));
    assert!(cfg.outbound.udp);
    assert_eq!(cfg.dns.nameservers[0], "223.5.5.5:53");
    assert_eq!(cfg.outbound.mux.max_streams_per_conn, 8);
}

#[test]
fn rejects_ss_url_with_unsupported_cipher() {
    let p = setup::tmp("cfg-badcipher", "badcipher.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://rc4-md5:__SEC_b13c1893b368b445dc07d100cad4c85d_71__@1.2.3.4:8388"
rules:
  - name: any
    match: {}
    action: proxy
"#,
    )
    .unwrap();
    let e = ss_cli::config::load_config(&p).err().unwrap().to_string();
    assert!(e.contains("rc4-md5") || e.contains("UnsupportedMethod"), "{e}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn rejects_empty_rules() {
    let p = setup::tmp("cfg-emptyrules", "emptyrules.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_72__@1.2.3.4:8388"
rules: []
"#,
    )
    .unwrap();
    let e = ss_cli::config::load_config(&p).err().unwrap().to_string();
    assert!(e.contains("rules must not be empty"), "{e}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn rejects_rule_with_empty_name() {
    let p = setup::tmp("cfg-emptyname", "emptyname.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_73__@1.2.3.4:8388"
rules:
  - name: ""
    match:
      domain_suffix: ["example.com"]
    action: direct
"#,
    )
    .unwrap();
    let e = ss_cli::config::load_config(&p).err().unwrap().to_string();
    assert!(e.contains("rule name must be non-empty"), "{e}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn rejects_wildcard_top_domain_and_reports_field() {
    let p = setup::tmp("cfg-wildcard", "wildcard.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_74__@1.2.3.4:8388"
rules:
  - name: r1
    match:
      domain_suffix: ["*.com"]
    action: direct
"#,
    )
    .unwrap();
    let e = ss_cli::config::load_config(&p).err().unwrap().to_string();
    assert!(e.contains("domain_suffix[0]"), "{e}");
    assert!(e.contains("wildcard"), "{e}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn rejects_cidr_with_host_bits_and_reports_field() {
    let p = setup::tmp("cfg-cidrbits", "cidrbits.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_75__@1.2.3.4:8388"
rules:
  - name: r1
    match:
      ip: ["192.0.2.1/24"]
    action: direct
"#,
    )
    .unwrap();
    let e = ss_cli::config::load_config(&p).err().unwrap().to_string();
    assert!(e.contains("ip[0]"), "{e}");
    assert!(e.contains("host bits"), "{e}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn rejects_invalid_cidr_and_reports_field() {
    let p = setup::tmp("cfg-badcidr", "badcidr.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_76__@1.2.3.4:8388"
rules:
  - name: r1
    match:
      ip: ["not-an-ip/24"]
    action: direct
"#,
    )
    .unwrap();
    let e = ss_cli::config::load_config(&p).err().unwrap().to_string();
    assert!(e.contains("ip[0]"), "{e}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn rejects_bad_mux_zero() {
    let p = setup::tmp("cfg-muxzero", "muxzero.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_77__@1.2.3.4:8388"
  mux:
    enabled: false
    max_streams_per_conn: 0
rules:
  - name: any
    match: {}
    action: proxy
"#,
    )
    .unwrap();
    let e = ss_cli::config::load_config(&p).err().unwrap().to_string();
    assert!(e.contains("mux.max_streams_per_conn"), "{e}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn mux_max_streams_upper_bound_128() {
    let p = setup::tmp("cfg-muxhi", "muxhi.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_78__@1.2.3.4:8388"
  mux:
    max_streams_per_conn: 129
rules:
  - name: any
    match: {}
    action: proxy
"#,
    )
    .unwrap();
    let e = ss_cli::config::load_config(&p).err().unwrap().to_string();
    assert!(e.contains("mux.max_streams_per_conn"), "{e}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn dns_servers_reject_port_zero() {
    let p = setup::tmp("cfg-dnszero", "dnszero.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_79__@1.2.3.4:8388"
dns:
  nameservers: ["223.5.5.5:0"]
rules:
  - name: any
    match: {}
    action: proxy
"#,
    )
    .unwrap();
    let e = ss_cli::config::load_config(&p).err().unwrap().to_string();
    assert!(e.contains("dns.nameservers[0]"), "{e}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn dns_servers_accept_ipv6_literal() {
    let p = setup::tmp("cfg-dns6", "dns6.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_80__@1.2.3.4:8388"
dns:
  nameservers: ["[2001:4860:4860::8888]:53"]
rules:
  - name: any
    match: {}
    action: proxy
"#,
    )
    .unwrap();
    ss_cli::config::load_config(&p).unwrap();
    let _ = std::fs::remove_file(&p);
}

#[test]
fn dns_servers_reject_bare_ipv6() {
    let p = setup::tmp("cfg-dns6bare", "dns6bare.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_81__@1.2.3.4:8388"
dns:
  nameservers: ["2001:4860:4860::8888"]
rules:
  - name: any
    match: {}
    action: proxy
"#,
    )
    .unwrap();
    let e = ss_cli::config::load_config(&p).err().unwrap().to_string();
    assert!(e.contains("dns.nameservers[0]"), "{e}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn mux_defaults_when_absent() {
    let p = setup::tmp("cfg-muxdefault", "muxdefault.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_82__@1.2.3.4:8388"
rules:
  - name: any
    match: {}
    action: proxy
"#,
    )
    .unwrap();
    let cfg = ss_cli::config::load_config(&p).unwrap();
    assert!(cfg.outbound.mux.enabled);
    assert_eq!(cfg.outbound.mux.max_streams_per_conn, 8);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn connect_timeout_defaults_when_absent() {
    let p = setup::tmp("cfg-ctdefault", "ctdefault.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_83__@1.2.3.4:8388"
rules:
  - name: any
    match: {}
    action: proxy
"#,
    )
    .unwrap();
    let cfg = ss_cli::config::load_config(&p).unwrap();
    assert_eq!(cfg.outbound.connect_timeout_ms, 3000);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn connect_timeout_rejects_zero() {
    let p = setup::tmp("cfg-ctzero", "ctzero.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_84__@1.2.3.4:8388"
  connect_timeout_ms: 0
rules:
  - name: any
    match: {}
    action: proxy
"#,
    )
    .unwrap();
    let e = ss_cli::config::load_config(&p).err().unwrap().to_string();
    assert!(e.contains("outbound.connect_timeout_ms"), "{e}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn top_level_unexpected_key_is_rejected_with_name() {
    let p = setup::tmp("cfg-topunknown", "topunknown.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_85__@1.2.3.4:8388"
rulez: []
"#,
    )
    .unwrap();
    let e = ss_cli::config::load_config(&p).err().unwrap().to_string();
    assert!(
        e.contains("rulez"),
        "expected unknown-field `rulez` in: {e}"
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn outbound_unexpected_key_is_rejected_with_name() {
    let p = setup::tmp("cfg-outunknown", "outunknown.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_86__@1.2.3.4:8388"
  udpa: true
rules:
  - name: any
    match: {}
    action: proxy
"#,
    )
    .unwrap();
    let e = ss_cli::config::load_config(&p).err().unwrap().to_string();
    assert!(e.contains("udpa"), "{e}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn rule_level_unexpected_key_is_rejected_with_name() {
    let p = setup::tmp("cfg-ruleunknown", "ruleunknown.yaml");
    std::fs::write(
        &p,
        r#"
outbound:
  ss_url: "ss://aes-256-gcm:__SEC_b13c1893b368b445dc07d100cad4c85d_87__@1.2.3.4:8388"
rules:
  - name: any
    match: {}
    actionn: proxy
"#,
    )
    .unwrap();
    let e = ss_cli::config::load_config(&p).err().unwrap().to_string();
    assert!(e.contains("actionn"), "{e}");
    let _ = std::fs::remove_file(&p);
}

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
    assert_eq!(cfg.match_route("2001:4860:4860::8888").action, Action::Proxy);
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
    assert_eq!(cfg.match_route("api.corp.example.com").action, Action::Direct);
    assert_eq!(cfg.match_route("www.example.com").action, Action::Proxy);
    let _ = std::fs::remove_file(&p);
}

#[test]
fn mux_config_serde_round_trip() {
    let cfg = Fixture::default().cfg;
    let j = serde_json::to_string(&cfg.outbound.mux).unwrap();
    let back: MuxConfig = serde_json::from_str(&j).unwrap();
    assert_eq!(back.max_streams_per_conn, 8);
    assert!(back.enabled);
}

#[test]
fn config_round_trip_serde_json() {
    let cfg = Fixture::default().cfg;
    let j = serde_json::to_string(&cfg).unwrap();
    let back: ss_cli::config::Config = serde_json::from_str(&j).unwrap();
    assert_eq!(back.rules.len(), 2);
    assert_eq!(back.outbound.mux.max_streams_per_conn, 8);
    assert_eq!(back.dns.nameservers, cfg.dns.nameservers);
}
