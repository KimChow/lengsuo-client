//! Brutal 参数/协商面测试：`Bandwidth` 解析矩阵、CC 头编解码向量、
//! `CongestionConfig` 校验矩阵、协商推导。
//!
//! 期望值均来自参考 Xray（`infra/conf/transport_internet.go` 的
//! `Bandwidth.Bps()` 行 460-511 与 `QuicParams` 校验行 1897-1920，
//! `hub.go`/`dialer.go` 的 switch 分支）。每条断言注明参考出处。

use lengsuo_hysteria::congestion::{
    bandwidth::BandwidthError, negotiate_client_rate, negotiate_server_rate, Bandwidth, CcHeader,
    ConfigError, CongestionConfig, CongestionMode, HeaderError, BRUTAL_MIN_BPS,
};

// ---------------------------------------------------------------------------
// Bandwidth 解析矩阵
// ---------------------------------------------------------------------------

/// 合法取值，覆盖所有单位后缀与大小写/空格/小数形态。
/// 期望值按参考公式 `uint64(val*mul)/8` 手算。
#[test]
fn bandwidth_parse_valid_matrix() {
    let cases: &[(&str, u64)] = &[
        // 缺省：空串与纯空白 → 0（参考 `if s == "" { return 0, nil }`，
        // 注意参考是先 TrimSpace 再判空，故纯空白也走这一支）。
        ("", 0),
        ("   ", 0),
        ("\t\n", 0),
        // 无单位 = 字节/秒。`"65536"` → 65536/8 = 8192。
        ("65536", 8192),
        ("b", 0), // 数字段为空 → ParseFloat("") 失败？不：这里 s="b"，
        // idx=0 → numStr="" → ParseFloat("") 应失败。见下方 invalid 矩阵的
        // 独立用例；此处置 0 占位会被下面的断言替换（保留在 invalid 中）。
        // 单位 b/bps：mul=1。
        ("8192b", 1024),
        ("8192B", 1024),    // 大小写不敏感（ToLower）
        ("8192 bps", 1024), // 单位前空格（TrimSpace 单位段）
        ("16k", 2048),      // 16*1024/8
        ("16K", 2048),
        ("16kb", 2048),
        ("16KBps", 2048),
        ("1m", 131072), // 1*1024*1024/8
        ("1Mbps", 131072),
        ("1M", 131072),
        ("1g", 134217728), // 1*1024^3/8
        ("1Gbps", 134217728),
        ("1t", 137438953472), // 1*1024^4/8
        ("1Tbps", 137438953472),
        // 小数：先浮点乘、再截断为 u64、最后整除 8。
        // 0.5m = 0.5*1048576 = 524288 → /8 = 65536。
        ("0.5m", 65536),
        ("0.5 mbps", 65536),
        // 截断语义：0.7b = 0.7 → uint64(0.7)=0 → /8 = 0。
        ("0.7b", 0),
        // 1.5k = 1536 → /8 = 192。
        ("1.5k", 192),
    ];

    for (input, expected) in cases {
        // 跳过占位项（"b" 单独在 invalid 矩阵断言）。
        if *input == "b" {
            continue;
        }
        let got = Bandwidth::parse(input)
            .unwrap_or_else(|e| panic!("Bandwidth::parse({input:?}) 意外失败：{e}"));
        assert_eq!(
            got.bps(),
            *expected,
            "Bandwidth::parse({input:?}) = {} bps，期望 {expected}",
            got.bps()
        );
    }
}

/// 参考的边界：`65536` 字节/秒恰好落在下限（未除 8 前的输入）。
/// 参考下限判据作用在 `Bps()` **之后**（字节/秒），即 65536 B/s。
#[test]
fn bandwidth_min_boundary_values() {
    // 65536 B/s == 下限，允许。
    let at_min = Bandwidth::parse("65536").unwrap();
    assert_eq!(at_min.bps(), 8192);
    assert!(at_min.bps() < BRUTAL_MIN_BPS); // 说明输入需换算后再判

    // 要用单位写出恰好 65536 B/s：0.5m → 65536。
    let exactly = Bandwidth::parse("0.5m").unwrap();
    assert_eq!(exactly.bps(), BRUTAL_MIN_BPS);
    assert!(exactly.bps() >= BRUTAL_MIN_BPS);
}

/// 非法输入一律 fail-closed。参考在这些输入上会 `ParseFloat` 失败或
/// 落到 `unsupported unit`（也可能因 Go 语义取到 NaN/越界未定义值）——
/// 本仓把两类失败都显式化。
#[test]
fn bandwidth_parse_invalid_matrix() {
    // 数字段为空：参考 numStr="" → ParseFloat("") 失败。
    for input in ["b", "k", "mbps", "  kbps  "] {
        let err = Bandwidth::parse(input).expect_err(&format!("{input:?} 应被拒绝（数字段为空）"));
        assert!(
            matches!(err, BandwidthError::InvalidNumber { .. }),
            "{input:?} 期望 InvalidNumber，实得 {err:?}"
        );
    }

    // 数字段有非数字非点：被截断成合法数字 + 非法单位。
    // "1.2.3m" → numStr="1.2.3"，ParseFloat 失败。
    let err = Bandwidth::parse("1.2.3m").unwrap_err();
    assert!(
        matches!(err, BandwidthError::InvalidNumber { .. }),
        "1.2.3m 期望 InvalidNumber，实得 {err:?}"
    );

    // 不支持的单位（参考 default 分支）。
    for input in ["1x", "1kbx", "1兆", "1p", "1pb", "1e3q"] {
        let err = Bandwidth::parse(input).unwrap_err();
        assert!(
            matches!(err, BandwidthError::UnsupportedUnit { .. }),
            "{input:?} 期望 UnsupportedUnit，实得 {err:?}"
        );
    }

    // 溢出 u64：参考 `uint64(val*mul)` 越界为未定义；本仓 fail-closed。
    // 注意 `1e30t` 会在 'e' 处切分 → 数字段 "1"、单位 "e30t"（非法单位），
    // 故用纯数字段触发真正的溢出路径。
    let err = Bandwidth::parse("99999999999999999999999999t").unwrap_err();
    assert!(
        matches!(err, BandwidthError::Overflow { .. }),
        "巨大数值期望 Overflow，实得 {err:?}"
    );

    // 科学计数法在数字段内不被接受（参考按 [0-9.] 截断，'e' 起为「单位」）。
    // "1e3" → numStr="1", unit="e3" → UnsupportedUnit。
    let err = Bandwidth::parse("1e3").unwrap_err();
    assert!(
        matches!(err, BandwidthError::UnsupportedUnit { .. }),
        "1e3 期望 UnsupportedUnit，实得 {err:?}"
    );
}

/// 溢出必须被拒绝，不得截断成任意值。
#[test]
fn bandwidth_overflow_is_rejected_not_truncated() {
    // 10^30 * 1024^4 远超 u64::MAX（约 1.8e19）。
    let err = Bandwidth::parse("1000000000000000000000000000000t").unwrap_err();
    assert!(
        matches!(
            err,
            BandwidthError::Overflow { .. } | BandwidthError::InvalidNumber { .. }
        ),
        "巨大数值应被拒绝，实得 {err:?}"
    );
}

/// `0` 与缺省语义：均为「未指定」，且**不**被最小值检查拒绝。
#[test]
fn bandwidth_zero_and_unset_semantics() {
    assert!(Bandwidth::parse("").unwrap().is_unset());
    assert!(Bandwidth::parse("0").unwrap().is_unset());
    assert!(Bandwidth::parse("0b").unwrap().is_unset());
    assert!(!Bandwidth::parse("0.5m").unwrap().is_unset());
    // 参考判据 `up > 0 && up < 65536`：0 不触发下限拒绝。
    assert_eq!(Bandwidth(0), Bandwidth::default());
}

// ---------------------------------------------------------------------------
// CC 头编解码确定性向量
// ---------------------------------------------------------------------------

/// 编码：`Bandwidth` → 十进制字符串，对齐 `strconv.FormatUint(_, 10)`。
#[test]
fn cc_header_encode_vectors() {
    assert_eq!(
        lengsuo_hysteria::congestion::header::encode(Bandwidth(0)),
        "0"
    );
    assert_eq!(
        lengsuo_hysteria::congestion::header::encode(Bandwidth(65536)),
        "65536"
    );
    assert_eq!(
        lengsuo_hysteria::congestion::header::encode(Bandwidth(u64::MAX)),
        "18446744073709551615"
    );
    assert_eq!(lengsuo_hysteria::congestion::header::encode_auto(), "auto");
}

/// 解码：严格路径区分 `"auto"` / 合法 u64 / 非法。
#[test]
fn cc_header_decode_vectors() {
    assert_eq!(CcHeader::decode("auto").unwrap(), CcHeader::Auto);
    assert_eq!(CcHeader::decode("0").unwrap(), CcHeader::Bps(Bandwidth(0)));
    assert_eq!(
        CcHeader::decode("65536").unwrap(),
        CcHeader::Bps(Bandwidth(65536))
    );
    assert_eq!(
        CcHeader::decode("18446744073709551615").unwrap(),
        CcHeader::Bps(Bandwidth(u64::MAX))
    );

    // 非法：空串、负号、前导 +、空白、超 u64、非数字。
    assert!(matches!(
        CcHeader::decode(""),
        Err(HeaderError::InvalidValue { .. })
    ));
    assert!(matches!(
        CcHeader::decode("-1"),
        Err(HeaderError::InvalidValue { .. })
    ));
    assert!(matches!(
        CcHeader::decode("+1"),
        Err(HeaderError::InvalidValue { .. })
    ));
    assert!(matches!(
        CcHeader::decode(" 1"),
        Err(HeaderError::InvalidValue { .. })
    ));
    assert!(matches!(
        CcHeader::decode("1 "),
        Err(HeaderError::InvalidValue { .. })
    ));
    assert!(matches!(
        CcHeader::decode("18446744073709551616"),
        Err(HeaderError::OutOfRange { .. })
    ));
    assert!(matches!(
        CcHeader::decode("12x"),
        Err(HeaderError::InvalidValue { .. })
    ));
    // 大写 AUTO 不是哨兵（参考 `== "auto"` 为大小写敏感比较）。
    assert!(matches!(
        CcHeader::decode("AUTO"),
        Err(HeaderError::InvalidValue { .. })
    ));
}

/// 宽容路径复刻参考 `_ := strconv.ParseUint(...)`：非法即 0。
#[test]
fn cc_header_decode_or_unset_matches_reference_leniency() {
    assert_eq!(
        CcHeader::decode_or_unset("not-a-number"),
        CcHeader::Bps(Bandwidth(0))
    );
    assert_eq!(
        CcHeader::decode_or_unset("18446744073709551616"),
        CcHeader::Bps(Bandwidth(0))
    );
    // 但 "auto" 仍被识别（参考在客户端侧显式判 serverAuto == "auto"）。
    assert_eq!(CcHeader::decode_or_unset("auto"), CcHeader::Auto);
}

/// 头名逐字节对齐参考常量。
#[test]
fn cc_header_names_match_reference() {
    assert_eq!(lengsuo_hysteria::congestion::HEADER_CC_RX, "Hysteria-CC-RX");
    assert_eq!(lengsuo_hysteria::congestion::HEADER_CC_TX, "Hysteria-CC-TX");
    assert_eq!(lengsuo_hysteria::congestion::CC_AUTO, "auto");
}

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

// ---------------------------------------------------------------------------
// 协商推导（对齐 hub.go / dialer.go 的 switch）
// ---------------------------------------------------------------------------

use lengsuo_hysteria::congestion::bandwidth::Bandwidth as BW;

/// 客户端：`min(local up, server down)`，缺参回落 BBR（None）。
#[test]
fn negotiate_client_brutal_branch() {
    let local = CongestionConfig::new(CongestionMode::Brutal, BW(0), BW(10_000_000)).unwrap();

    // 正常 min。
    assert_eq!(
        negotiate_client_rate(&local, CcHeader::Bps(BW(4_000_000))),
        Some(4_000_000)
    );
    // 服务端更高 → 取本地 up。
    assert_eq!(
        negotiate_client_rate(&local, CcHeader::Bps(BW(99_000_000))),
        Some(10_000_000)
    );
    // 服务端 "auto" → 回落 BBR（None）。
    assert_eq!(negotiate_client_rate(&local, CcHeader::Auto), None);
    // 服务端 down=0 → 回落 BBR。
    assert_eq!(negotiate_client_rate(&local, CcHeader::Bps(BW(0))), None);

    // 本地 up=0 → 回落 BBR（即使服务端给了值）。
    let local_no_up = CongestionConfig::new(CongestionMode::Brutal, BW(0), BW(0)).unwrap();
    assert_eq!(
        negotiate_client_rate(&local_no_up, CcHeader::Bps(BW(4_000_000))),
        None
    );
}

/// 客户端 `force-brutal` 不做 min，直接用本地 up。
#[test]
fn negotiate_client_force_brutal_ignores_server() {
    let local = CongestionConfig::new(CongestionMode::ForceBrutal, BW(0), BW(10_000_000)).unwrap();
    assert_eq!(
        negotiate_client_rate(&local, CcHeader::Bps(BW(1))),
        Some(10_000_000)
    );
    assert_eq!(
        negotiate_client_rate(&local, CcHeader::Auto),
        Some(10_000_000)
    );
}

/// `reno` / `bbr` 均不改 Brutal 速率（None）。
#[test]
fn negotiate_client_reno_bbr_are_none() {
    let reno = CongestionConfig::new(CongestionMode::Reno, BW(0), BW(10_000_000)).unwrap();
    let bbr = CongestionConfig::new(CongestionMode::Bbr, BW(0), BW(10_000_000)).unwrap();
    assert_eq!(
        negotiate_client_rate(&reno, CcHeader::Bps(BW(4_000_000))),
        None
    );
    assert_eq!(
        negotiate_client_rate(&bbr, CcHeader::Bps(BW(4_000_000))),
        None
    );
}

/// 回归：配置层的 CC-RX 取值 → 线上头值 → 解析回来，全链路一致。
///
/// 说明：`h3_auth` 的线上常量 `COMMON_HEADER_CC_RX` 用小写
/// `"hysteria-cc-rx"`（HTTP/2·3 头名大小写不敏感，与参考 Go 的规范形
/// `"Hysteria-CC-RX"` 线上等价）；本模块导出的 `HEADER_CC_RX` 用参考原形。
/// 此处断言二者仅大小写之差，避免将来漂移成不同的头名。
#[test]
fn config_cc_rx_round_trips_via_wire_header_value() {
    use lengsuo_hysteria::congestion::header::{encode, HEADER_CC_RX};
    use lengsuo_hysteria::h3_auth::COMMON_HEADER_CC_RX;

    assert_eq!(
        HEADER_CC_RX.to_ascii_lowercase(),
        COMMON_HEADER_CC_RX,
        "配置层头名与线上头名不一致"
    );

    let cfg = CongestionConfig::new(CongestionMode::Brutal, BW(4_000_000), BW(10_000_000)).unwrap();
    let wire = encode(cfg.cc_rx_value());
    assert_eq!(wire, "4000000");
    assert_eq!(
        CcHeader::decode(&wire).unwrap(),
        CcHeader::Bps(BW(4_000_000))
    );
    // 服务端读到该值后，协商结果 = min(服务端 up, 客户端 down)。
    let srv = CongestionConfig::new(CongestionMode::Brutal, BW(0), BW(10_000_000)).unwrap();
    assert_eq!(
        negotiate_server_rate(&srv, CcHeader::decode(&wire).unwrap()),
        Some(4_000_000)
    );
}

/// 服务端：`min(BrutalUp, clientDown)`；**无 "auto" 分支**
/// （参考对客户端头用 `ParseUint` 忽略错误 → "auto" 退化为 0 → BBR）。
#[test]
fn negotiate_server_branch() {
    let srv = CongestionConfig::new(CongestionMode::Brutal, BW(0), BW(10_000_000)).unwrap();
    assert_eq!(
        negotiate_server_rate(&srv, CcHeader::Bps(BW(4_000_000))),
        Some(4_000_000)
    );
    assert_eq!(
        negotiate_server_rate(&srv, CcHeader::Bps(BW(99_000_000))),
        Some(10_000_000)
    );
    // clientDown = 0 → BBR。
    assert_eq!(negotiate_server_rate(&srv, CcHeader::Bps(BW(0))), None);
    // "auto" → 服务端不认 → BBR。
    assert_eq!(negotiate_server_rate(&srv, CcHeader::Auto), None);

    // 服务端 force-brutal 直接用自己的 up。
    let forced = CongestionConfig::new(CongestionMode::ForceBrutal, BW(0), BW(10_000_000)).unwrap();
    assert_eq!(
        negotiate_server_rate(&forced, CcHeader::Bps(BW(1))),
        Some(10_000_000)
    );
}
