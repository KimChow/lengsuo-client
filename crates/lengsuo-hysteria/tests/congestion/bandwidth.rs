// `Bandwidth` 解析矩阵：合法取值 / 下限边界 / 非法输入 / 溢出 / 缺省语义。
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
