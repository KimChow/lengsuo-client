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
