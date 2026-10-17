//! MemoryStore 语义测试：roundtrip、跨作用域不可见、过期、list 隔离、Debug 脱敏、并发。

mod support;

use std::sync::Arc;

use credential_ref::{CredentialRef, MemoryStore, Plaintext, Scope, SecretStore, StoreError};
use support::ManualClock;

const PLAINTEXT: &str = "sup3r-secret-token-DoNotLog";

fn store_at(now_ms: u64) -> (MemoryStore, ManualClock) {
    let clock = ManualClock::new(now_ms);
    (MemoryStore::with_clock(clock.clock()), clock)
}

#[test]
fn put_get_roundtrip_returns_same_plaintext() {
    let (store, _clock) = store_at(0);
    let reference = CredentialRef::env("env-1", u64::MAX);
    store
        .put(&reference, &Plaintext::from(PLAINTEXT))
        .expect("put succeeds");
    let got = store.get(&reference).expect("get succeeds");
    assert_eq!(got.as_bytes(), PLAINTEXT.as_bytes());
}

#[test]
fn put_overwrites_same_id_without_duplicating() {
    let (store, _clock) = store_at(0);
    let reference = CredentialRef::env("env-1", u64::MAX);
    store
        .put(&reference, &Plaintext::from("first"))
        .expect("put");
    store
        .put(&reference, &Plaintext::from("second"))
        .expect("reput");
    assert_eq!(store.len(), 1);
    assert_eq!(store.get(&reference).expect("get").as_bytes(), b"second");
}

#[test]
fn get_missing_reference_reports_not_found() {
    let (store, _clock) = store_at(0);
    let reference = CredentialRef::env("env-1", u64::MAX);
    let other = CredentialRef::env("env-1", u64::MAX);
    store
        .put(&reference, &Plaintext::from(PLAINTEXT))
        .expect("put");
    let err = store.get(&other).expect_err("unknown id must fail");
    assert!(matches!(err, StoreError::NotFound));
    support::assert_error_clean(&err, &[PLAINTEXT, &reference.id().as_uuid().to_string()]);
}

#[test]
fn expired_reference_get_returns_expired() {
    let (store, clock) = store_at(1_000);
    let reference = CredentialRef::session("sess-1", 2_000);
    store
        .put(&reference, &Plaintext::from(PLAINTEXT))
        .expect("put");
    // 未过期时正常。
    assert_eq!(
        store.get(&reference).expect("still valid").as_bytes(),
        PLAINTEXT.as_bytes()
    );
    clock.advance_to(2_000);
    let err = store.get(&reference).expect_err("expired must fail");
    assert!(matches!(err, StoreError::Expired), "got {err:?}");
    support::assert_error_clean(&err, &[PLAINTEXT]);
}

#[test]
fn cross_scope_get_and_delete_are_invisible() {
    let (store, _clock) = store_at(0);
    let reference = CredentialRef::env("shared-target", u64::MAX);
    store
        .put(&reference, &Plaintext::from(PLAINTEXT))
        .expect("put");

    // 同 target 字面量但不同类别：不可见。
    let as_session = CredentialRef::with_id(
        reference.id(),
        Scope::Session("shared-target".into()),
        u64::MAX,
    );
    let err = store.get(&as_session).expect_err("cross kind must fail");
    assert!(matches!(err, StoreError::ScopeMismatch));
    support::assert_error_clean(&err, &[PLAINTEXT, "shared-target"]);

    // 同类别不同 target：不可见。
    let other_env = CredentialRef::with_id(reference.id(), Scope::Env("other".into()), u64::MAX);
    assert!(matches!(
        store.get(&other_env),
        Err(StoreError::ScopeMismatch)
    ));

    // 跨作用域不得删除。
    assert!(matches!(
        store.delete(&as_session),
        Err(StoreError::ScopeMismatch)
    ));
    assert_eq!(
        store.len(),
        1,
        "cross-scope delete must not remove the record"
    );
    assert_eq!(
        store.get(&reference).expect("still readable").as_bytes(),
        PLAINTEXT.as_bytes()
    );
}

#[test]
fn list_only_shows_same_scope_unexpired_refs() {
    let (store, clock) = store_at(100);
    let env_a = CredentialRef::env("env-a", u64::MAX);
    let env_b = CredentialRef::env("env-a", 500);
    let session_b = CredentialRef::session("env-a", u64::MAX);
    let tenant_b = CredentialRef::tenant("env-a", u64::MAX);
    for reference in [&env_a, &env_b, &session_b, &tenant_b] {
        store
            .put(reference, &Plaintext::from(PLAINTEXT))
            .expect("put");
    }

    let listed = store.list(&Scope::Env("env-a".into())).expect("list");
    assert_eq!(listed.len(), 2, "same-kind same-target only");
    assert!(listed
        .iter()
        .all(|item| item.scope() == &Scope::Env("env-a".into())));

    clock.advance_to(500);
    let after = store
        .list(&Scope::Env("env-a".into()))
        .expect("list after expiry");
    assert_eq!(after.len(), 1, "expired record must not be listed");
    assert_eq!(after[0].id(), env_a.id());

    assert_eq!(
        store
            .list(&Scope::Session("env-a".into()))
            .expect("session list")
            .len(),
        1
    );
    assert_eq!(
        store
            .list(&Scope::Tenant("env-a".into()))
            .expect("tenant list")
            .len(),
        1
    );
    assert!(store
        .list(&Scope::Env("nope".into()))
        .expect("empty list")
        .is_empty());
}

#[test]
fn list_returns_no_plaintext() {
    let (store, _clock) = store_at(0);
    let reference = CredentialRef::env("env-a", u64::MAX);
    store
        .put(&reference, &Plaintext::from(PLAINTEXT))
        .expect("put");
    let listed = store.list(reference.scope()).expect("list");
    let rendered = format!("{listed:?}");
    assert!(
        !rendered.contains(PLAINTEXT),
        "list Debug leaks plaintext: {rendered}"
    );
}

#[test]
fn delete_removes_record_and_is_idempotent() {
    let (store, _clock) = store_at(0);
    let reference = CredentialRef::env("env-1", u64::MAX);
    store
        .put(&reference, &Plaintext::from(PLAINTEXT))
        .expect("put");
    assert!(store.delete(&reference).expect("delete"));
    assert!(matches!(store.get(&reference), Err(StoreError::NotFound)));
    assert!(!store.delete(&reference).expect("second delete is no-op"));
}

#[test]
fn put_rejects_invalid_reference_without_storing() {
    let (store, _clock) = store_at(0);
    let reference = CredentialRef::env("", u64::MAX);
    let err = store
        .put(&reference, &Plaintext::from(PLAINTEXT))
        .expect_err("empty target rejected");
    assert!(matches!(err, StoreError::InvalidReference));
    support::assert_error_clean(&err, &[PLAINTEXT]);
    assert!(store.is_empty());
}

#[test]
fn debug_output_never_contains_plaintext_or_targets() {
    let (store, _clock) = store_at(0);
    let reference = CredentialRef::env("env-debug-target", u64::MAX);
    store
        .put(&reference, &Plaintext::from(PLAINTEXT))
        .expect("put");
    let rendered = format!("{store:?}");
    assert!(
        !rendered.contains(PLAINTEXT),
        "store Debug leaks plaintext: {rendered}"
    );
    assert!(
        !rendered.contains("env-debug-target"),
        "store Debug leaks scope target: {rendered}"
    );
    assert!(
        !rendered.contains(&reference.id().as_uuid().to_string()),
        "store Debug leaks id"
    );
}

#[test]
fn expired_records_can_be_pruned() {
    let (store, clock) = store_at(0);
    let live = CredentialRef::env("env-1", u64::MAX);
    let dead = CredentialRef::env("env-1", 10);
    store.put(&live, &Plaintext::from("live")).expect("put");
    store.put(&dead, &Plaintext::from("dead")).expect("put");
    clock.advance_to(10);
    assert_eq!(
        store.retain_unexpired(),
        1,
        "exactly the expired record is pruned"
    );
    assert_eq!(store.len(), 1);
    assert!(store.stored_reference(&dead.id()).is_none());
    assert!(store.stored_reference(&live.id()).is_some());
}

#[test]
fn concurrent_reads_and_writes_do_not_panic() {
    // 8 线程并发写不同引用 + 并发读/列，最终条数一致且不 panic。
    let store = Arc::new(MemoryStore::with_clock(
        support::ManualClock::new(0).clock(),
    ));
    let threads: Vec<_> = (0..8u8)
        .map(|index| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                for round in 0..40u16 {
                    let reference = CredentialRef::env(format!("env-{index}-{round}"), u64::MAX);
                    store
                        .put(&reference, &Plaintext::from(format!("tok-{index}-{round}")))
                        .expect("put");
                    assert_eq!(
                        store.get(&reference).expect("get").as_bytes(),
                        format!("tok-{index}-{round}").as_bytes()
                    );
                    let _ = store
                        .list(&Scope::Env(format!("env-{index}")))
                        .expect("list");
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("thread must not panic");
    }
    assert_eq!(store.len(), 8 * 40);
}

#[test]
fn cloned_store_shares_the_same_table() {
    let (store, _clock) = store_at(0);
    let clone = store.clone();
    let reference = CredentialRef::tenant("tenant-1", u64::MAX);
    store
        .put(&reference, &Plaintext::from(PLAINTEXT))
        .expect("put");
    assert_eq!(
        clone.get(&reference).expect("clone sees write").as_bytes(),
        PLAINTEXT.as_bytes()
    );
    assert_eq!(clone.len(), 1);
}
