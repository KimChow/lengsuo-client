// 负例（默认运行）：未识别模式 / 未移植模式 / 非法速率 / 通告帧严格性。
// ===================== 负例（默认运行） =====================

/// 模式字符串未识别 ⇒ fail-closed，不静默落回 CUBIC（客户端一路）。
#[tokio::test]
async fn unknown_congestion_mode_is_rejected() {
    let server = start_server("neg-unknown", 0, 0, "").await;
    let mut config = client_config(&server, 256 * 1024, 0);
    config.congestion = "cubic-ish".to_string();
    match HysteriaClient::connect(config).await {
        Err(ConnectError::Congestion(CongestionError::UnknownMode { mode })) => {
            assert_eq!(mode, "cubic-ish");
        }
        Err(e) => panic!("期望 UnknownMode，实得 {e}"),
        Ok(_) => panic!("未识别模式必须报错，不得落回 CUBIC"),
    }
}

/// 服务端模式未识别：`bind` 期 fail-closed，错误指明未识别模式。
#[test]
fn server_unknown_mode_is_rejected() {
    let (cert, key) = gen_cert(&test_dir("neg-srv-unknown"));
    let mut config = ServerConfig::new(
        "127.0.0.1:0".parse().expect("监听地址"),
        vec![cert],
        key,
        AUTH.to_string(),
    );
    config.congestion = "reno-ish".to_string();
    match HysteriaServer::bind(config) {
        Err(ServerError::Congestion(CongestionError::UnknownMode { mode })) => {
            assert_eq!(mode, "reno-ish");
        }
        Err(e) => panic!("期望 Congestion(UnknownMode)，实得 {e}"),
        Ok(_) => panic!("服务端未识别模式必须 bind 失败"),
    }
}

/// 参考有但本仓未移植的模式（`bbr` / `reno` / `force-brutal`）⇒ 报错，
/// **不**假装生效、**不**静默落回 CUBIC。
#[test]
fn unimplemented_modes_are_rejected() {
    for mode in ["bbr", "reno", "force-brutal"] {
        assert_eq!(
            parse_mode(mode),
            Err(CongestionError::Unimplemented {
                mode: mode.to_string()
            }),
            "{mode} 必须 fail-closed"
        );
    }
    // 空串 = 缺省 = CUBIC（不注入）。
    assert_eq!(parse_mode(""), Ok(None));
    assert_eq!(parse_mode("  "), Ok(None));
    assert_eq!(parse_mode("brutal"), Ok(Some(Mode::Brutal)));
}

/// 协商速率 0 ⇒ 拒绝（不当 0 速率跑）。
#[test]
fn zero_negotiated_rate_is_rejected() {
    // 客户端协商：任一侧为 0 ⇒ 参考回落分支（`None`，不注入）。
    assert_eq!(
        client_rate(0, CcHeader::Bps(Bandwidth(256 * 1024))),
        Ok(None)
    );
    assert_eq!(
        client_rate(256 * 1024, CcHeader::Bps(Bandwidth(0))),
        Ok(None)
    );
    assert_eq!(client_rate(256 * 1024, CcHeader::Auto), Ok(None));
    // 注入层：拿到 `Some(0)` 必须报错（不得装 0 速率控制器）。
    assert_eq!(
        inject(
            &mut quinn::TransportConfig::default(),
            Some(Mode::Brutal),
            Some(0)
        ),
        Err(CongestionError::Rate(ConfigError::ZeroBandwidth))
    );
    // 回落分支（`None`）⇒ 不注入，沿用 CUBIC。
    assert!(inject(
        &mut quinn::TransportConfig::default(),
        Some(Mode::Brutal),
        None
    )
    .is_ok());
}

/// 亚字节/秒 ⇒ 拒绝（`BandwidthTooLow`；8 bps = 1 字节/秒 是最低档）。
///
/// 两种语义必须分清（对齐参考 `hub.go:193-200`）：
/// - **未配置**（`tx == 0`）⇒ 回落分支 ⇒ `Ok(0)`，**不是**错误；
/// - **已配置非法速率**（如 `Some(0)` 直接注入）⇒ `Err(ZeroBandwidth)`，fail-closed。
#[test]
fn sub_byte_rate_is_rejected() {
    // 未配置（tx = 0）⇒ 参考的回落分支：不限速，返回 Ok(0)。
    let unset = CongestionConfig {
        mode: CongestionMode::Brutal,
        rx: Bandwidth(0),
        tx: Bandwidth(0),
    };
    assert_eq!(
        server_send_rate(&unset, 0),
        Ok(0),
        "tx 未配置属参考回落分支，不得报错"
    );
    // 已配置 1 字节/秒 ⇒ 合法，且被限速到 1（不是回落）。
    let one = CongestionConfig {
        mode: CongestionMode::Brutal,
        rx: Bandwidth(0),
        tx: Bandwidth(1),
    };
    assert_eq!(
        server_send_rate(&one, 1),
        Ok(1),
        "min(BrutalUp=1, clientDown=1) = 1"
    );
    // 注入层：协商出 0 ⇒ 报错。
    assert_eq!(
        inject(
            &mut quinn::TransportConfig::default(),
            Some(Mode::Brutal),
            Some(0)
        ),
        Err(CongestionError::Rate(ConfigError::ZeroBandwidth))
    );
    // 以**比特/秒**给速率的入口：低于 8 bps 一律拒绝。
    for bps in [1u64, 4, 7] {
        assert_eq!(
            lengsuo_congestion::brutal::BrutalConfig::new(bps, 0),
            Err(ConfigError::BandwidthTooLow { got: bps, min: 8 })
        );
    }
    assert!(lengsuo_congestion::brutal::BrutalConfig::new(8, 0).is_ok());
}

/// 拥塞通告帧往返：非通告负载一律拒绝（不得误判成协商）。
#[test]
fn announce_frame_is_strict() {
    let frame = lengsuo_hysteria::congestion::announce_frame(256 * 1024);
    assert_eq!(parse_announce(&frame), Some(256 * 1024));
    let mut req = vec![0u8; frame.len()];
    req[0] = 0x01;
    assert_eq!(parse_announce(&req), None);
    assert_eq!(parse_announce(&frame[..4]), None);
}
