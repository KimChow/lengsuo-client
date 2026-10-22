// ---- 配置加载与规则校验：YAML 夹具、规则名、域名通配与 CIDR ----

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
    assert!(
        e.contains("rc4-md5") || e.contains("UnsupportedMethod"),
        "{e}"
    );
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
