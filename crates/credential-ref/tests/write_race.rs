//! 并发写后落盘完整性回归：证明「内存视图」与「磁盘内容」在并发下不失真。
//!
//! 与 `file_store.rs::concurrent_reads_writes_and_deletes_do_not_panic` 的区别：
//! 本文件用**精确作用域**逐条核对记录，只考察写盘原子性，不依赖任何作用域聚合语义。

mod support;

use std::sync::Arc;

use credential_ref::{CredentialRef, FileStore, Plaintext, Scope, SecretStore};
use support::{ManualClock, TempDir};

const PASSPHRASE: &str = "race-passphrase-DoNotLog";

/// 并发写不同记录后，磁盘上必须一条不少（无丢失更新）。
#[test]
fn concurrent_writes_all_survive_on_disk() {
    let dir = TempDir::new("race-survive");
    let path = dir.file("creds.bin");
    let clock = ManualClock::new(0);
    let store =
        Arc::new(FileStore::with_clock(&path, PASSPHRASE, clock.clock()).expect("open store"));

    let threads: Vec<_> = (0..6u8)
        .map(|index| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                for round in 0..12u16 {
                    let target = format!("env-{index}-{round}");
                    let reference = CredentialRef::env(target.clone(), u64::MAX);
                    let value = format!("tok-{index}-{round}");
                    store
                        .put(&reference, &Plaintext::from(value.as_str()))
                        .expect("put");
                    assert_eq!(
                        store.get(&reference).expect("get").as_bytes(),
                        value.as_bytes(),
                        "写入后立即可读"
                    );
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("thread must not panic");
    }

    // 内存视图：72 条精确作用域记录都在。
    let mut in_memory = 0usize;
    for index in 0..6u8 {
        for round in 0..12u16 {
            let listed = store
                .list(&Scope::Env(format!("env-{index}-{round}")))
                .expect("list");
            assert_eq!(listed.len(), 1, "每条记录的精确作用域应可见");
            in_memory += listed.len();
        }
    }
    assert_eq!(in_memory, 6 * 12);

    // 磁盘：重开后同样 72 条，一条都不能被并发重写吞掉。
    let reopened =
        FileStore::with_clock(&path, PASSPHRASE, credential_ref::fixed_clock(0)).expect("reopen");
    let mut on_disk = 0usize;
    for index in 0..6u8 {
        for round in 0..12u16 {
            let target = format!("env-{index}-{round}");
            let listed = reopened.list(&Scope::Env(target.clone())).expect("list");
            assert_eq!(
                listed.len(),
                1,
                "记录 {target} 已写入但重开后丢失（并发重写吞掉了它）"
            );
            assert_eq!(
                reopened.get(&listed[0]).expect("get").as_bytes(),
                format!("tok-{index}-{round}").as_bytes()
            );
            on_disk += listed.len();
        }
    }
    assert_eq!(on_disk, 6 * 12, "落盘记录数必须与内存视图一致");
}

/// 并发「写 + 删」后，删除的记录在磁盘上确实不存在，其余仍在。
#[test]
fn concurrent_delete_does_not_swallow_other_records() {
    let dir = TempDir::new("race-delete");
    let path = dir.file("creds.bin");
    let clock = ManualClock::new(0);
    let store =
        Arc::new(FileStore::with_clock(&path, PASSPHRASE, clock.clock()).expect("open store"));

    let deleted: Vec<String> = (0..6u8)
        .flat_map(|index| [0u16, 4, 8].map(move |round| format!("env-{index}-{round}")))
        .collect();

    let threads: Vec<_> = (0..6u8)
        .map(|index| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                for round in 0..12u16 {
                    let target = format!("env-{index}-{round}");
                    let reference = CredentialRef::env(target.clone(), u64::MAX);
                    store
                        .put(&reference, &Plaintext::from(format!("tok-{index}-{round}")))
                        .expect("put");
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

    let reopened =
        FileStore::with_clock(&path, PASSPHRASE, credential_ref::fixed_clock(0)).expect("reopen");
    for target in &deleted {
        assert!(
            reopened
                .list(&Scope::Env(target.clone()))
                .expect("list")
                .is_empty(),
            "已删除记录 {target} 不应复活"
        );
    }

    let mut survivors = 0usize;
    for index in 0..6u8 {
        for round in 0..12u16 {
            if !reopened
                .list(&Scope::Env(format!("env-{index}-{round}")))
                .expect("list")
                .is_empty()
            {
                survivors += 1;
            }
        }
    }
    assert_eq!(survivors, 6 * 9, "删除只影响自身，其余 54 条必须完整落盘");
}
