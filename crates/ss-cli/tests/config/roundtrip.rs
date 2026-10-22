// ---- serde 往返：mux 段与整份配置的 JSON 往返 ----

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
