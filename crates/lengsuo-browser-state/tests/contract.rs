use lengsuo_browser_state::*;
fn sample() -> Snapshot {
    Snapshot {
        environment: "env-1".into(),
        generation: 7,
        was_running: true,
    }
}
#[test]
fn canonical_and_recovery() {
    let bytes = encode(&sample()).unwrap();
    assert_eq!(
        bytes,
        [b"LBST\x01\x05env-1".as_slice(), &7u64.to_be_bytes(), &[1]].concat()
    );
    let got = decode(&bytes, "env-1", 7).unwrap();
    assert_eq!(got.snapshot, sample());
    assert_eq!(got.action, RecoveryAction::NeedsReconciliation);
}
#[test]
fn truncation_trailing_and_versions() {
    let b = encode(&sample()).unwrap();
    for n in 0..b.len() {
        assert!(decode(&b[..n], "env-1", 0).is_err());
    }
    let mut extra = b.clone();
    extra.push(0);
    assert!(decode(&extra, "env-1", 0).is_err());
    for version in [0, 2, 255] {
        let mut x = b.clone();
        x[4] = version;
        assert!(decode(&x, "env-1", 0).is_err());
    }
    let mut x = b.clone();
    *x.last_mut().unwrap() = 2;
    assert!(decode(&x, "env-1", 0).is_err());
}
#[test]
fn binding_and_floor() {
    let b = encode(&sample()).unwrap();
    assert_eq!(decode(&b, "env-2", 0), Err(StateError::WrongEnvironment));
    assert_eq!(decode(&b, "env-1", 8), Err(StateError::Stale));
    assert!(decode(&b, "env-1", 6).is_ok());
}
#[test]
fn identifier_bounds_and_generation() {
    for env in [
        "".to_string(),
        "../env".into(),
        "a/b".into(),
        "a\0b".into(),
        "é".into(),
        "x".repeat(65),
    ] {
        let mut s = sample();
        s.environment = env;
        assert!(encode(&s).is_err());
    }
    let mut s = sample();
    s.generation = 0;
    assert!(encode(&s).is_err());
    s.generation = u64::MAX;
    s.environment = "a".repeat(64);
    s.was_running = false;
    assert_eq!(
        decode(&encode(&s).unwrap(), &s.environment, 0)
            .unwrap()
            .snapshot,
        s
    );
}
