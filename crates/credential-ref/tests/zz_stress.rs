//! 凭据存储并发持久化回归：放大 flush 的快照与 rename 窗口，核对重开后的记录。

mod support;

use std::sync::Arc;

use credential_ref::{CredentialRef, FileStore, Plaintext, Scope, SecretStore};
use support::{ManualClock, TempDir};

const PASSPHRASE: &str = "stress-pass";

/// 大库（多记录）让编码与写盘耗时更长，配合更多线程，放大过期快照窗口。
#[test]
fn stress_lost_update() {
    for attempt in 0..4 {
        let dir = TempDir::new(&format!("stress-{attempt}"));
        let path = dir.file("creds.bin");
        let clock = ManualClock::new(0);
        let store =
            Arc::new(FileStore::with_clock(&path, PASSPHRASE, clock.clock()).expect("open store"));

        // 预热：先写入大量记录，使每次整库重写变慢（rename 前的窗口变宽）。
        for warm in 0..400u32 {
            let reference = CredentialRef::env(format!("warm-{warm}"), u64::MAX);
            store
                .put(&reference, &Plaintext::from(format!("warm-value-{warm}")))
                .expect("warm put");
        }

        let threads: Vec<_> = (0..12u16)
            .map(|index| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    for round in 0..30u16 {
                        let target = format!("hot-{index}-{round}");
                        let reference = CredentialRef::env(target.clone(), u64::MAX);
                        store.put(&reference, &Plaintext::from("hot")).expect("put");
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("join");
        }

        let mut expected = 0usize;
        for index in 0..12u16 {
            for round in 0..30u16 {
                if !store
                    .list(&Scope::Env(format!("hot-{index}-{round}")))
                    .expect("list")
                    .is_empty()
                {
                    expected += 1;
                }
            }
        }

        let reopened =
            FileStore::with_clock(&path, PASSPHRASE, credential_ref::fixed_clock(0)).expect("re");
        let mut on_disk = 0usize;
        for index in 0..12u16 {
            for round in 0..30u16 {
                if !reopened
                    .list(&Scope::Env(format!("hot-{index}-{round}")))
                    .expect("list")
                    .is_empty()
                {
                    on_disk += 1;
                }
            }
        }
        println!("attempt {attempt}: 内存 {expected} / 磁盘 {on_disk}");
        assert_eq!(
            on_disk,
            expected,
            "丢失更新：磁盘比内存少 {} 条",
            expected.saturating_sub(on_disk)
        );
    }
}
