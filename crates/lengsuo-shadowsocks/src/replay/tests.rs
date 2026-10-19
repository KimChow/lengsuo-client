use super::*;

#[test]
fn construction_rejects_zero_capacity_or_window() {
    assert!(matches!(
        ReplayFilter::new(0, Duration::from_secs(1)),
        Err(Error::InvalidCapacity { capacity: 0 })
    ));
    assert!(matches!(
        ReplayFilter::new(1, Duration::ZERO),
        Err(Error::InvalidWindow)
    ));
}

#[test]
fn duplicate_rejected_and_fresh_salt_accepted() {
    let mut filter = ReplayFilter::new(8, Duration::from_secs(10)).unwrap();
    filter.record(b"same", 0).unwrap();
    assert!(matches!(filter.record(b"same", 5), Err(Error::Duplicate)));
    // 拒绝不改变窗口大小。
    assert_eq!(filter.len(), 1);
    filter.record(b"other", 5).unwrap();
    assert_eq!(filter.len(), 2);
}

#[test]
fn capacity_evicts_oldest_and_time_window_expires() {
    let mut filter = ReplayFilter::new(2, Duration::from_millis(100)).unwrap();
    filter.record(b"s1", 0).unwrap();
    filter.record(b"s2", 50).unwrap();
    filter.record(b"s3", 60).unwrap();
    // 容量 2：s1 被最旧逐出，可再次作为新 salt 记录；s2/s3 仍在窗内。
    assert!(!filter.contains(b"s1"));
    assert!(filter.contains(b"s2") && filter.contains(b"s3"));
    filter.record(b"s1", 80).unwrap();
    assert_eq!(filter.len(), 2);

    let mut windowed = ReplayFilter::new(4, Duration::from_millis(100)).unwrap();
    windowed.record(b"a", 0).unwrap();
    windowed.record(b"b", 1000).unwrap();
    // a 的窗口在 100 处到期，b 在 1000 处新记录 ⇒ a 被逐出。
    assert!(!windowed.contains(b"a"));
    assert!(windowed.contains(b"b"));
}

#[test]
fn save_and_load_roundtrip_preserves_window_and_rejects_replay() {
    let dir = std::env::temp_dir().join(format!("lengsuo-ss-replay-self-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("replay.bin");
    let key = MacKey::new(b"unit-test-key".to_vec());
    let now = 1_000_000u64;
    let mut filter = ReplayFilter::new(16, Duration::from_secs(60)).unwrap();
    filter.record(&[0x5Au8; 32], now).unwrap();
    filter.record(&[0x6Bu8; 16], now + 1).unwrap();
    filter.save_with_key(&path, now, &key).unwrap();

    let loaded = ReplayFilter::load_with_keys(&path, now, &key, None)
        .unwrap()
        .unwrap();
    assert!(!loaded.key_rotated);
    let mut restored = loaded.filter;
    assert_eq!(restored.capacity(), 16);
    assert_eq!(restored.window(), Duration::from_secs(60));
    assert!(restored.contains(&[0x5Au8; 32]));
    assert!(restored.contains(&[0x6Bu8; 16]));
    assert!(matches!(
        restored.record(&[0x5Au8; 32], now + 2),
        Err(Error::Duplicate)
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_file_loads_as_fresh_state() {
    let path = std::env::temp_dir().join(format!("lengsuo-ss-missing-{}.bin", std::process::id()));
    let key = MacKey::new(b"k".to_vec());
    assert!(ReplayFilter::load_with_keys(&path, 0, &key, None)
        .unwrap()
        .is_none());
}
