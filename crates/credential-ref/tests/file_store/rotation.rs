//! 盐轮换、Debug 脱敏与并发安全（自原 file_store.rs 原样搬移）。

use crate::fixtures::*;
use std::sync::Arc;
#[test]
fn invalid_reference_put_is_rejected_without_touching_file() {
    let dir = TempDir::new("invalid-ref");
    let path = dir.file("creds.bin");
    let (store, _clock) = store_at(&path, 0);
    let good = put_env(&store, TARGET, PLAINTEXT);
    let before = read_bytes(&path);

    let err = store
        .put(
            &CredentialRef::env("", u64::MAX),
            &Plaintext::from(PLAINTEXT),
        )
        .expect_err("empty target rejected");
    assert!(matches!(err, StoreError::InvalidReference), "got {err:?}");
    assert_error_clean(&err, &[PLAINTEXT]);
    assert_eq!(
        read_bytes(&path),
        before,
        "rejected put must not rewrite the file"
    );
    assert_eq!(
        store.get(&good).expect("still readable").as_bytes(),
        PLAINTEXT.as_bytes()
    );
}

#[test]
fn each_write_rotates_salt_so_identical_values_differ_on_disk() {
    let dir = TempDir::new("salt-rotation");
    let path = dir.file("creds.bin");
    let mut snapshots = Vec::new();
    for round in 0..3u64 {
        let clock = ManualClock::new(round);
        let store = FileStore::with_clock(&path, PASSPHRASE, clock.clock()).expect("open");
        // 每轮独立 target：本测试验证「每次写盐都轮换」，不依赖同 target 复写语义。
        store
            .put(
                &CredentialRef::env(format!("{TARGET}-{round}"), u64::MAX),
                &Plaintext::from(PLAINTEXT),
            )
            .expect("put");
        let bytes = read_bytes(&path);
        // 头部定长前缀含 16 字节 salt（偏移 20..36）。
        snapshots.push(bytes[OFFSET_SALT..OFFSET_SALT + 16].to_vec());
        // 同一明文的同长度值，整库字节也必须随 nonce/salt 变化。
        assert!(!windows_contains(&bytes, PLAINTEXT.as_bytes()));
    }
    assert_ne!(snapshots[0], snapshots[1], "salt must rotate per write");
    assert_ne!(snapshots[1], snapshots[2], "salt must rotate per write");
    // 轮换 salt 后旧文件仍可正常读回最新值。
    let reopened =
        FileStore::with_clock(&path, PASSPHRASE, credential_ref::fixed_clock(0)).expect("reopen");
    // 三轮写入的 target 各不相同（-0/-1/-2）；最后一个 target 必须可读回恰 1 条。
    assert_eq!(
        reopened
            .list(&Scope::Env(format!("{TARGET}-2")))
            .expect("list")
            .len(),
        1,
        "轮换 salt 后最新写入仍可读回"
    );
}

#[test]
fn file_store_debug_is_redacted() {
    let dir = TempDir::new("debug");
    let path = dir.file("creds.bin");
    let (store, _clock) = store_at(&path, 0);
    let reference = put_env(&store, TARGET, PLAINTEXT);
    let rendered = format!("{store:?}");
    for needle in [
        PLAINTEXT,
        TARGET,
        PASSPHRASE,
        &reference.id().as_uuid().to_string(),
    ] {
        assert!(
            !rendered.contains(needle),
            "Debug leaks {needle:?}: {rendered}"
        );
    }
    assert!(
        rendered.contains("<redacted>"),
        "Debug not redacted: {rendered}"
    );
    assert!(
        rendered.contains("entries"),
        "Debug should expose only the count"
    );
}

#[test]
fn concurrent_reads_writes_and_deletes_do_not_panic() {
    let dir = TempDir::new("concurrent");
    let path = dir.file("creds.bin");
    let clock = ManualClock::new(0);
    let store =
        Arc::new(FileStore::with_clock(&path, PASSPHRASE, clock.clock()).expect("open store"));

    let threads: Vec<_> = (0..6u8)
        .map(|index| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                for round in 0..12u16 {
                    let reference = CredentialRef::env(format!("env-{index}"), u64::MAX);
                    let value = format!("tok-{index}-{round}");
                    store
                        .put(&reference, &Plaintext::from(value.as_str()))
                        .expect("put");
                    assert_eq!(
                        store.get(&reference).expect("get").as_bytes(),
                        value.as_bytes()
                    );
                    let _ = store
                        .list(&Scope::Env(format!("env-{index}")))
                        .expect("list");
                    if round % 4 == 0 {
                        assert!(store.delete(&reference).expect("delete"));
                    }
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("thread must not panic");
    }

    // 只有未被删除的记录留下：6 线程 × 每 4 轮删 1 条。
    let remaining = store.list(&Scope::Env("unused".into())).expect("list");
    assert!(remaining.is_empty());
    let total: usize = (0..6u8)
        .map(|index| {
            store
                .list(&Scope::Env(format!("env-{index}")))
                .expect("list")
                .len()
        })
        .sum();
    assert_eq!(total, 6 * 9, "rounds 0,4,8 deleted per thread; 9 survive");

    // 并发结束后文件仍是自洽容器，可完整重开。
    let reopened = FileStore::with_clock(&path, PASSPHRASE, credential_ref::fixed_clock(0))
        .expect("reopen after concurrent writes");
    assert_eq!(
        reopened
            .list(&Scope::Env("env-0".into()))
            .expect("list")
            .len(),
        9
    );
    assert!(!file_contains(&path, b"tok-"));
}
