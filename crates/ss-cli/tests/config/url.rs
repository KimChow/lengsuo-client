// ---- SS URL 解析：往返、加密名、错误分类与口令脱敏 ----

// ---------------------------------------------------------------------------
// §13.1 SS URL 解析（§10.2 #16）
// ---------------------------------------------------------------------------

#[test]
fn parses_full_url_and_roundtrips() {
    let raw =
        "ss://chacha20-ietf-poly1305:https://ardot.tencent.com/file/...@198.51.100.7:8443#home";
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
        let u =
            ss_cli::config::SsUrl::parse(&raw).unwrap_or_else(|e| panic!("{m} rejected: {e:?}"));
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
    assert!(
        dbg.contains("__SEC_b13c1893b368b445dc07d100cad4c85d_70__"),
        "{dbg}"
    );
    assert!(!dbg.contains("SECRETPW"), "{dbg}");

    let err = ss_cli::config::SsUrl::parse("ss://aes-256-gcm:SECRETPW@")
        .err()
        .unwrap();
    let edbg = format!("{err:?}");
    assert!(!edbg.contains("SECRETPW"), "{edbg}");

    let cfg = Fixture::default().cfg;
    let cdbg = format!("{cfg:?}");
    assert!(
        !cdbg.contains("https://raw.githubusercontent.com/sagernet/sing-shadowsocks/main/LICENSE"),
        "{cdbg}"
    );
    let json = serde_json::to_string(&cfg).unwrap();
    assert!(
        !json.contains("https://raw.githubusercontent.com/sagernet/sing-shadowsocks/main/LICENSE"),
        "{json}"
    );
    let disp = format!("{}", cfg.outbound.ss_url);
    assert!(
        !disp.contains("https://raw.githubusercontent.com/sagernet/sing-shadowsocks/main/LICENSE"),
        "{disp}"
    );
}
