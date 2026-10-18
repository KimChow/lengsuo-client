//! 作用域隔离、过期、删除与覆盖语义（自原 file_store.rs 原样搬移）。

use crate::fixtures::*;
#[test]
fn expired_reference_is_rejected_on_read_and_list() {
    let dir = TempDir::new("expired");
    let path = dir.file("creds.bin");
    let (store, clock) = store_at(&path, 1_000);
    let reference = CredentialRef::session("sess-file", 2_000);
    store
        .put(&reference, &Plaintext::from(PLAINTEXT))
        .expect("put");
    assert_eq!(
        store.get(&reference).expect("still valid").as_bytes(),
        PLAINTEXT.as_bytes()
    );

    clock.advance_to(2_000);
    let err = store.get(&reference).expect_err("expired must fail");
    assert!(matches!(err, StoreError::Expired), "got {err:?}");
    assert_error_clean(&err, &[PLAINTEXT, "sess-file"]);
    assert!(store
        .list(&Scope::Session("sess-file.into()".into()))
        .is_ok());
    assert!(
        store
            .list(&Scope::Session("sess-file".into()))
            .expect("list")
            .is_empty(),
        "expired reference must not be listed"
    );

    // 过期记录不会被写回文件（下次落盘即淘汰），但内存视图仍是同一条语义。
    let survivor = put_env(&store, "env-survivor", "survivor-value");
    let bytes = read_bytes(&path);
    assert!(!windows_contains(&bytes, &2_000u64.to_le_bytes()));
    assert_eq!(
        store.get(&survivor).expect("survivor").as_bytes(),
        b"survivor-value"
    );
}

#[test]
fn cross_scope_is_invisible_and_cannot_delete() {
    let dir = TempDir::new("cross-scope");
    let path = dir.file("creds.bin");
    let (store, _clock) = store_at(&path, 0);
    let reference = put_env(&store, TARGET, PLAINTEXT);

    // 同 target 字面量、不同作用域类别：不可见、不可删。
    let as_session =
        CredentialRef::with_id(reference.id(), Scope::Session(TARGET.into()), u64::MAX);
    let err = store.get(&as_session).expect_err("cross kind must fail");
    assert!(matches!(err, StoreError::ScopeMismatch), "got {err:?}");
    assert_error_clean(&err, &[PLAINTEXT, TARGET]);
    assert!(matches!(
        store.delete(&as_session),
        Err(StoreError::ScopeMismatch)
    ));

    // 不同 target 同类别同样不可见。
    let other = CredentialRef::with_id(reference.id(), Scope::Env("env-other".into()), u64::MAX);
    assert!(matches!(store.get(&other), Err(StoreError::ScopeMismatch)));

    // 记录仍在，且仍可正常读取（拒绝不得有副作用）。
    assert_eq!(
        store.list(&Scope::Env(TARGET.into())).expect("list").len(),
        1
    );
    assert_eq!(
        store.get(&reference).expect("still readable").as_bytes(),
        PLAINTEXT.as_bytes()
    );
}

#[test]
fn delete_persists_and_is_idempotent() {
    let dir = TempDir::new("delete");
    let path = dir.file("creds.bin");
    let (store, _clock) = store_at(&path, 0);
    let reference = put_env(&store, TARGET, PLAINTEXT);
    assert!(store.delete(&reference).expect("delete"));
    assert!(matches!(store.get(&reference), Err(StoreError::NotFound)));
    assert!(!store.delete(&reference).expect("second delete is no-op"));

    // 删除必须落盘：重开后既读不到也列不到。
    let reopened =
        FileStore::with_clock(&path, PASSPHRASE, credential_ref::fixed_clock(0)).expect("reopen");
    assert!(matches!(
        reopened.get(&reference),
        Err(StoreError::NotFound)
    ));
    assert!(reopened
        .list(&Scope::Env(TARGET.into()))
        .expect("list")
        .is_empty());
    // 明文不会因删除残留在文件里。
    assert!(!file_contains(&path, PLAINTEXT.as_bytes()));
}

#[test]
fn overwrite_same_id_keeps_single_record_on_disk() {
    let dir = TempDir::new("upsert");
    let path = dir.file("creds.bin");
    let (store, _clock) = store_at(&path, 0);
    let reference = CredentialRef::env(TARGET, u64::MAX);
    store
        .put(&reference, &Plaintext::from("first"))
        .expect("put");
    store
        .put(&reference, &Plaintext::from("second"))
        .expect("reput");

    let reopened =
        FileStore::with_clock(&path, PASSPHRASE, credential_ref::fixed_clock(0)).expect("reopen");
    assert_eq!(
        reopened
            .list(&Scope::Env(TARGET.into()))
            .expect("list")
            .len(),
        1
    );
    assert_eq!(reopened.get(&reference).expect("get").as_bytes(), b"second");
    // 旧明文不得残留在文件里（整库原子重写，不追加）。
    let bytes = read_bytes(&path);
    assert!(!windows_contains(&bytes, b"first"));
}
