// CC 头编解码确定性向量：编码 / 严格解码 / 宽容解码 / 头名常量。
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
