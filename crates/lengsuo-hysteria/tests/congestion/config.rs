// `CongestionConfig` 校验矩阵：模式解析 / 下限校验 / force-brutal / from_strs / CC-RX 取值。
// ---------------------------------------------------------------------------
// CongestionConfig 校验矩阵
// ---------------------------------------------------------------------------

/// 模式解析：合法集 + 空串折算 + 未识别拒绝（fail-closed，不落 CUBIC）。
#[test]
fn congestion_mode_parse_matrix() {
    assert_eq!(CongestionMode::parse("").unwrap(), CongestionMode::Brutal);
    assert_eq!(
        CongestionMode::parse("brutal").unwrap(),
        CongestionMode::Brutal
    );
    assert_eq!(
        CongestionMode::parse("BRUTAL").unwrap(),
        CongestionMode::Brutal
    );
    assert_eq!(
        CongestionMode::parse(" force-brutal ").unwrap(),
        CongestionMode::ForceBrutal
    );
    assert_eq!(CongestionMode::parse("bbr").unwrap(), CongestionMode::Bbr);
    assert_eq!(CongestionMode::parse("Reno").unwrap(), CongestionMode::Reno);

    for bad in ["cubic", "cubic2", "BRR", "brutal-force", "bbr2", "null"] {
        let err =
            CongestionMode::parse(bad).expect_err(&format!("{bad:?} 应被拒绝（不得静默落 CUBIC）"));
        assert!(
            matches!(err, ConfigError::UnknownMode { .. }),
            "{bad:?} 期望 UnknownMode，实得 {err:?}"
        );
    }
}

/// 构建期下限校验：非 0 且 < 65536 拒绝；0 与 >= 65536 通过。
#[test]
fn congestion_config_min_bound_matrix() {
    // 0（未配置）允许。
    assert!(CongestionConfig::new(CongestionMode::Brutal, Bandwidth(0), Bandwidth(0)).is_ok());

    // 恰好下限允许。
    assert!(CongestionConfig::new(
        CongestionMode::Brutal,
        Bandwidth(BRUTAL_MIN_BPS),
        Bandwidth(BRUTAL_MIN_BPS)
    )
    .is_ok());

    // 低于下限拒绝（rx 侧）。
    let err = CongestionConfig::new(CongestionMode::Brutal, Bandwidth(1), Bandwidth(0))
        .expect_err("rx=1 应被拒绝");
    assert!(matches!(
        err,
        ConfigError::Bandwidth(BandwidthError::BelowMinimum { .. })
    ));

    // 低于下限拒绝（tx 侧）。
    let err = CongestionConfig::new(CongestionMode::Brutal, Bandwidth(0), Bandwidth(65535))
        .expect_err("tx=65535 应被拒绝");
    assert!(matches!(
        err,
        ConfigError::Bandwidth(BandwidthError::BelowMinimum { .. })
    ));
}

/// `force-brutal` 必须显式 up（参考 `force-brutal requires up`）。
/// 注意参考判的是 `up`，即本仓 `tx`。
#[test]
fn force_brutal_requires_tx() {
    let err = CongestionConfig::new(
        CongestionMode::ForceBrutal,
        Bandwidth(BRUTAL_MIN_BPS),
        Bandwidth(0),
    )
    .expect_err("force-brutal 无 tx 应被拒绝");
    assert_eq!(err, ConfigError::ForceBrutalRequiresRx);

    assert!(CongestionConfig::new(
        CongestionMode::ForceBrutal,
        Bandwidth(0),
        Bandwidth(BRUTAL_MIN_BPS)
    )
    .is_ok());
}

/// `from_strs` 端到端：合法/非法单位/未知模式。
#[test]
fn congestion_config_from_strs_matrix() {
    let cfg = CongestionConfig::from_strs("brutal", "0.5m", "1m").unwrap();
    assert_eq!(cfg.rx.bps(), 65536);
    assert_eq!(cfg.tx.bps(), 131072);

    // 空串 = 缺省。
    let cfg = CongestionConfig::from_strs("", "", "").unwrap();
    assert!(cfg.rx.is_unset() && cfg.tx.is_unset());
    assert_eq!(cfg.mode, CongestionMode::Brutal);

    // 未知模式。
    assert!(matches!(
        CongestionConfig::from_strs("cubic", "1m", "1m"),
        Err(ConfigError::UnknownMode { .. })
    ));

    // 非法单位。
    assert!(matches!(
        CongestionConfig::from_strs("brutal", "1x", "1m"),
        Err(ConfigError::Bandwidth(
            BandwidthError::UnsupportedUnit { .. }
        ))
    ));

    // 越界拒绝（不截断）：rx = "16384" bps 输入 → 2048 B/s < 65536 下限。
    assert!(matches!(
        CongestionConfig::from_strs("brutal", "16384", "1m"),
        Err(ConfigError::Bandwidth(BandwidthError::BelowMinimum { .. }))
    ));
}

/// `rx` 承载的即参考 `BrutalDown`，也就是写入 `Hysteria-CC-RX` 的值。
#[test]
fn rx_matches_cc_rx() {
    let cfg =
        CongestionConfig::new(CongestionMode::Brutal, Bandwidth(131072), Bandwidth(65536)).unwrap();
    assert_eq!(cfg.cc_rx_value(), Bandwidth(131072));
    // 编码后应逐字节等于参考 FormatUint(BrutalDown)。
    assert_eq!(
        lengsuo_hysteria::congestion::header::encode(cfg.cc_rx_value()),
        "131072"
    );
}
