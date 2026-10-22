// ---- mux / dns / 连接超时：取值范围、缺省值与 IPv6 字面量 ----

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
