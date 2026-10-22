// ---- 未知键拒绝：顶层、出站段与规则段都必须报出字段名 ----

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
