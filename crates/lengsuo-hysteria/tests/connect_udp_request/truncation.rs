// 截断：每个真前缀都必须报出所需的绝对长度。
#[test]
fn every_request_truncation_reports_needed_length() {
    // 帧布局：0..2 类型，2 地址长度，3..18 地址，18 padding 长度，19..22 padding。
    let bytes = frame(b"example.com:443", b"pad");
    assert_eq!(bytes.len(), 22);
    let expectations: &[(usize, usize)] = &[
        (0, 1),   // 类型首字节
        (1, 2),   // 类型第 2 字节
        (2, 3),   // 地址长度字段
        (3, 18),  // 地址体
        (17, 18), // 地址最后 1 字节
        (18, 19), // padding 长度字段
        (19, 22), // padding 体
        (21, 22),
    ];
    for (got, need) in expectations {
        assert_eq!(
            request_error(&bytes[..*got]),
            Error::Truncated {
                need: *need,
                got: *got
            },
            "只剩 {got} 字节"
        );
    }
    // 全量扫描：任何真前缀都必须失败，且 need 大于可用字节。
    for got in 0..bytes.len() {
        match request_error(&bytes[..got]) {
            Error::Truncated { need, got: seen } => {
                assert_eq!(seen, got);
                assert!(need > got, "need 应大于可用字节");
            }
            other => panic!("只剩 {got} 字节应报截断，实际 {other:?}"),
        }
    }
    assert_eq!(
        ConnectUdpRequest::decode(&bytes).ok().map(|(_, used)| used),
        Some(22),
        "完整帧应成功"
    );
    // 定界版本同样按截断拒绝。
    assert_eq!(
        ConnectUdpRequest::decode_exact(&bytes[..21]).expect_err("前缀必截断"),
        Error::Truncated { need: 22, got: 21 }
    );
}
