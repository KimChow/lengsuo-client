// ① TLS 配置面：默认关闭时不得触碰 rustls 配置 / 启用时必须提供会话缓存。
fn raw_tls() -> quinn::rustls::ClientConfig {
    let provider = Arc::new(quinn::rustls::crypto::ring::default_provider());
    quinn::rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS 版本")
        .with_root_certificates(quinn::rustls::RootCertStore::empty())
        .with_no_client_auth()
}

// ---- ① 默认关闭时不得触碰 rustls 配置 ----

#[test]
fn default_config_leaves_tls_untouched() {
    let cfg = EarlyDataConfig::default();
    assert!(!cfg.enabled, "默认必须关闭 0-RTT");
    assert_eq!(cfg.resumption_capacity, 256);

    let mut tls = raw_tls();
    assert!(!tls.enable_early_data);
    configure_tls(&mut tls, &cfg, None).expect("关闭时配置应为 no-op");
    assert!(!tls.enable_early_data, "关闭时不得设置 enable_early_data");
}

#[test]
fn enabled_config_sets_early_data_and_requires_cache() {
    let cfg = EarlyDataConfig {
        enabled: true,
        ..Default::default()
    };
    let mut tls = raw_tls();
    let cache = Arc::new(MemorySessionCache::new(4));
    configure_tls(&mut tls, &cfg, Some(cache)).expect("启用配置应成功");
    assert!(tls.enable_early_data, "启用时必须设置 enable_early_data");

    let mut tls = raw_tls();
    assert_eq!(
        configure_tls(&mut tls, &cfg, None).expect_err("无缓存必须 fail-closed"),
        EarlyDataError::MissingSessionCache
    );
    assert!(!tls.enable_early_data);

    let weird = EarlyDataConfig {
        enabled: true,
        max_early_data: Some(0),
        ..Default::default()
    };
    assert_eq!(
        configure_tls(
            &mut raw_tls(),
            &weird,
            Some(Arc::new(MemorySessionCache::new(1)))
        )
        .expect_err("0 预算自相矛盾"),
        EarlyDataError::ZeroEarlyDataBudget
    );
}
