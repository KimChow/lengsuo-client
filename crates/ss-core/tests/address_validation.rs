use ss_core::target::TargetAddr;

#[test]
fn empty_domain_is_rejected() {
    assert!(TargetAddr::decode(&[3, 0, 1, 187]).is_err());
}

#[test]
fn embedded_nul_domain_is_rejected() {
    assert!(TargetAddr::decode(&[3, 3, b'a', 0, b'b', 1, 187]).is_err());
}

#[test]
fn checked_encode_rejects_bad_domains_without_partial_output() {
    for host in [String::new(), "a".repeat(256), "a\0b".into()] {
        let mut output = vec![42];
        assert!(TargetAddr::Domain(host, 443)
            .encode_checked(&mut output)
            .is_err());
        assert_eq!(output, vec![42]);
    }
}

#[test]
fn maximum_domain_length_is_preserved() {
    let target = TargetAddr::Domain("a".repeat(255), 443);
    let mut output = Vec::new();
    target.encode_checked(&mut output).unwrap();
    let (decoded, used) = TargetAddr::decode(&output).unwrap();
    assert_eq!(decoded, target);
    assert_eq!(used, output.len());
}

// ---- W4 核验卡追加：地址族读端的截断 / 族字节边界回归锁 ----

#[test]
fn ipv6_compressed_forms_roundtrip_via_decode() {
    let mut localhost = [0u8; 16];
    localhost[15] = 1;
    let doc = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    for (ip, port) in [(localhost, 53u16), (doc, 8080)] {
        let mut buf = vec![0x04];
        buf.extend_from_slice(&ip);
        buf.extend_from_slice(&port.to_be_bytes());
        let (decoded, used) = TargetAddr::decode(&buf).unwrap();
        assert_eq!(decoded, TargetAddr::V6(ip, port));
        assert_eq!(used, buf.len());
    }
}

#[test]
fn ipv6_truncation_reports_exact_need() {
    let mut body = vec![0x04];
    body.extend_from_slice(&[0u8; 15]);
    assert!(matches!(
        TargetAddr::decode(&body),
        Err(ss_core::Error::TooShort { need: 19, got: 16 })
    ));
    // 端口断半：18 字节同样报 need=19。
    let mut with_half_port = vec![0x04];
    with_half_port.extend_from_slice(&[0u8; 16]);
    with_half_port.push(0x00);
    assert!(matches!(
        TargetAddr::decode(&with_half_port),
        Err(ss_core::Error::TooShort { need: 19, got: 18 })
    ));
}

#[test]
fn empty_buffer_reports_need_one() {
    assert!(matches!(
        TargetAddr::decode(&[]),
        Err(ss_core::Error::TooShort { need: 1, got: 0 })
    ));
}

#[test]
fn domain_port_truncation_reports_exact_need() {
    let buf = [0x03, 3, b'a', b'b', b'c', 0x00];
    assert!(matches!(
        TargetAddr::decode(&buf),
        Err(ss_core::Error::TooShort { need: 7, got: 6 })
    ));
}

#[test]
fn non_utf8_domain_is_rejected() {
    assert!(TargetAddr::decode(&[0x03, 2, 0xFF, 0xFE, 0x01, 0xBB]).is_err());
}

#[test]
fn unmapped_family_bytes_are_rejected() {
    assert!(matches!(
        TargetAddr::decode(&[0x07, 0, 0, 0, 0, 0, 0]),
        Err(ss_core::Error::InvalidAddressType(7))
    ));
    assert!(matches!(
        TargetAddr::decode(&[0x02, 0, 0, 0, 0, 0, 0]),
        Err(ss_core::Error::InvalidAddressType(2))
    ));
}

#[test]
fn decode_accepts_non_charset_domain_documenting_v_s3() {
    // 现状锁定（有意偏离 V-S3）：decode 只拒 NUL 与非 UTF-8。参考
    // address.go:219 在 TCP/UDP 两条路径上都以 isValidDomain 拒绝 `a/b.c`，
    // 本共享类型按现状接受；是否对齐由主理人定夺（见 shadowsocks 核验报告）。
    let (decoded, used) = TargetAddr::decode(&[0x03, 5, b'a', b'/', b'b', b'.', b'c', 1, 187])
        .expect("现状（V-S3）：decode 不校验字符集");
    assert_eq!(decoded, TargetAddr::Domain("a/b.c".into(), 443));
    assert_eq!(used, 9);
}
