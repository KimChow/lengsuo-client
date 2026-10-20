use super::*;
use std::time::Duration;

/// 测试假口令，与任何生产凭据无关。
const PASSWORD: &[u8] = b"unit-salt-store-password";
/// 临时状态文件路径（系统临时目录 + 进程号，用例结束删除）。
fn temp_path(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "lengsuo-salt-store-{tag}-{}.bin",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn open_rejects_zero_capacity_and_window() {
    let path = temp_path("bad-params");
    let config = SaltStoreConfig::new(&path, 0, Duration::from_secs(1));
    assert!(matches!(
        SaltStore::open(&config, CipherSuite::Aes256Gcm, PASSWORD),
        Err(SaltStoreError::Config(_))
    ));
    let config = SaltStoreConfig::new(&path, 8, Duration::ZERO);
    assert!(matches!(
        SaltStore::open(&config, CipherSuite::Aes256Gcm, PASSWORD),
        Err(SaltStoreError::Config(_))
    ));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn missing_file_starts_empty_and_roundtrips() {
    let path = temp_path("roundtrip");
    let config = SaltStoreConfig::new(&path, 16, Duration::from_secs(60));
    let store = SaltStore::open(&config, CipherSuite::Aes256Gcm, PASSWORD).expect("首次开库");
    assert!(store.is_empty(), "首次开库应为空窗口");
    store
        .record(b"salt-one", ReplayFilter::system_now_millis())
        .expect("记录应成功");
    store.flush().expect("回写应成功");
    drop(store);

    let reopened = SaltStore::open(&config, CipherSuite::Aes256Gcm, PASSWORD).expect("重开应成功");
    assert_eq!(reopened.len(), 1, "重开后应记住一条");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn corrupt_file_fails_closed_instead_of_empty_window() {
    let path = temp_path("corrupt");
    let config = SaltStoreConfig::new(&path, 16, Duration::from_secs(60));
    let store = SaltStore::open(&config, CipherSuite::Aes256Gcm, PASSWORD).expect("开库");
    store
        .record(b"salt-one", ReplayFilter::system_now_millis())
        .expect("记录应成功");
    store.flush().expect("回写应成功");
    drop(store);

    // 破坏 MAC 区的最后一个字节。
    let mut bytes = std::fs::read(&path).expect("读状态文件失败");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&path, &bytes).expect("写回失败");

    let err = SaltStore::open(&config, CipherSuite::Aes256Gcm, PASSWORD)
        .expect_err("损坏必须 fail-closed");
    assert!(
        matches!(err, SaltStoreError::Replay(ReplayError::MacMismatch)),
        "应报 MAC 不符，实际 {err}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn wrong_password_cannot_open_state_file() {
    let path = temp_path("wrongpass");
    let config = SaltStoreConfig::new(&path, 16, Duration::from_secs(60));
    let store = SaltStore::open(&config, CipherSuite::Aes256Gcm, PASSWORD).expect("开库");
    store.flush().expect("回写应成功");
    drop(store);

    let err = SaltStore::open(&config, CipherSuite::Aes256Gcm, b"another-password")
        .expect_err("口令不符必须报错");
    assert!(
        matches!(err, SaltStoreError::Replay(ReplayError::MacMismatch)),
        "应报 MAC 不符，实际 {err}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn rotation_loads_and_upgrades_to_current_key() {
    let path = temp_path("rotate");
    let old = b"old-password-bytes";
    let new = b"new-password-bytes";
    let config = SaltStoreConfig::new(&path, 16, Duration::from_secs(60));
    let store = SaltStore::open(&config, CipherSuite::Aes256Gcm, old).expect("旧口令开库");
    store
        .record(b"salt-one", ReplayFilter::system_now_millis())
        .expect("记录应成功");
    store.flush().expect("回写应成功");
    drop(store);

    // 新口令 + 旧口令 ⇒ 命中上一代密钥 ⇒ 加载成功并升级重写。
    let rotating = SaltStoreConfig::new(&path, 16, Duration::from_secs(60))
        .with_previous_password(old.to_vec());
    let store = SaltStore::open(&rotating, CipherSuite::Aes256Gcm, new).expect("轮换开库应成功");
    assert_eq!(store.len(), 1, "轮换后应记住旧文件里的 salt");
    drop(store);

    // 升级重写已生效：旧口令不再可用。
    let err = SaltStore::open(&config, CipherSuite::Aes256Gcm, old)
        .expect_err("升级重写后旧口令必须失效");
    assert!(
        matches!(err, SaltStoreError::Replay(ReplayError::MacMismatch)),
        "应报 MAC 不符，实际 {err}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn replay_rejection_does_not_trigger_a_write() {
    // 被判定为重放的连接**不改变窗口**，因此不应触发写盘
    // （否则每次重放尝试都引发一次 fsync ⇒ 放大型 DoS 面）。
    let path = temp_path("nodirty");
    let config = SaltStoreConfig::new(&path, 16, Duration::from_secs(60));
    let store = SaltStore::open(&config, CipherSuite::Aes256Gcm, PASSWORD).expect("开库");
    store
        .record(b"salt-one", ReplayFilter::system_now_millis())
        .expect("记录应成功");
    store.flush().expect("回写应成功");
    let before = std::fs::read(&path).expect("读状态文件失败");

    // 同 salt 再次记录 ⇒ 重放拒绝。
    let err = store
        .record(b"salt-one", ReplayFilter::system_now_millis())
        .expect_err("同 salt 必须被判重放");
    assert!(matches!(
        err,
        SaltStoreError::Replay(ReplayError::Duplicate)
    ));

    // 收尾回写：窗口没变 ⇒ 不写盘（文件内容不变）。
    store.flush_on_close().expect("收尾回写应成功");
    let after = std::fs::read(&path).expect("读状态文件失败");
    assert_eq!(before, after, "重放拒绝不应触发写盘");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn interval_policy_throttles_writes_but_close_always_writes() {
    let path = temp_path("policy");
    let config = SaltStoreConfig::new(&path, 16, Duration::from_secs(60))
        .with_flush_policy(FlushPolicy::Interval(Duration::from_secs(3600)));
    let store = SaltStore::open(&config, CipherSuite::Aes256Gcm, PASSWORD).expect("开库");
    store
        .record(b"salt-one", ReplayFilter::system_now_millis())
        .expect("记录应成功");
    // 间隔策略：首次记录后立即写盘（从未回写过 ⇒ due）。
    assert!(path.exists(), "首次记录后应立刻回写一次");
    // 第二次记录：间隔未到 ⇒ 不写盘（文件内容不变）。
    let before = std::fs::read(&path).expect("读状态文件失败");
    std::thread::sleep(Duration::from_millis(20));
    store
        .record(b"salt-two", ReplayFilter::system_now_millis())
        .expect("记录应成功");
    let after = std::fs::read(&path).expect("读状态文件失败");
    assert_eq!(before, after, "间隔未到时不应回写");
    // 收尾回写：间隔策略下 `flush_on_close` 也按间隔节流，但强制 `flush` 一定写。
    store.flush().expect("强制回写应成功");
    let forced = std::fs::read(&path).expect("读状态文件失败");
    assert_ne!(before, forced, "强制回写必须更新文件");
    let _ = std::fs::remove_file(&path);
}
