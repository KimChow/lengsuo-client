//! 基础读写回路与口令边界（自原 file_store.rs 原样搬移）。

use crate::fixtures::*;
#[test]
fn put_get_roundtrip_and_reopen_keeps_plaintext() {
    let dir = TempDir::new("roundtrip");
    let path = dir.file("creds.bin");
    let (store, _clock) = store_at(&path, 0);
    let reference = put_env(&store, TARGET, PLAINTEXT);

    assert_eq!(
        store.get(&reference).expect("get").as_bytes(),
        PLAINTEXT.as_bytes()
    );

    // 重新打开同一文件：引用元数据与明文都要完整回来。
    let reopened =
        FileStore::with_clock(&path, PASSPHRASE, credential_ref::fixed_clock(0)).expect("reopen");
    let got = reopened.get(&reference).expect("get after reopen");
    assert_eq!(got.as_bytes(), PLAINTEXT.as_bytes());
    assert_eq!(
        reopened
            .list(&Scope::Env(TARGET.into()))
            .expect("list")
            .len(),
        1
    );
}

#[test]
fn file_never_contains_plaintext_or_reference_metadata() {
    let dir = TempDir::new("no-leak");
    let path = dir.file("creds.bin");
    let (store, _clock) = store_at(&path, 0);
    let reference = put_env(&store, TARGET, PLAINTEXT);
    let bytes = read_bytes(&path);

    for needle in [
        PLAINTEXT.as_bytes(),
        TARGET.as_bytes(),
        PASSPHRASE.as_bytes(),
        reference.id().as_uuid().as_bytes(),
        &u64::MAX.to_le_bytes(),
    ] {
        assert!(
            !windows_contains(&bytes, needle),
            "file leaks {}",
            String::from_utf8_lossy(needle)
        );
    }
    // 反过来确认写入确实生效（不是空文件造成的“没有泄漏”）。
    assert!(bytes.len() > header_len(&bytes));
}

#[test]
fn wrong_passphrase_is_rejected_on_open() {
    let dir = TempDir::new("wrong-pass");
    let path = dir.file("creds.bin");
    {
        let (store, _clock) = store_at(&path, 0);
        put_env(&store, TARGET, PLAINTEXT);
    }
    let before = read_bytes(&path);
    let err = FileStore::open(&path, WRONG_PASSPHRASE).expect_err("wrong passphrase must fail");
    assert!(matches!(err, StoreError::WrongPassphrase), "got {err:?}");
    assert_error_clean(&err, &[PLAINTEXT, TARGET, PASSPHRASE, WRONG_PASSPHRASE]);
    // 失败的重开不得改写或清空原文件。
    assert_eq!(
        read_bytes(&path),
        before,
        "failed open must leave the file byte-identical"
    );

    // 正确口令仍能读回全部记录（证明失败是口令判定，不是库被破坏）。
    let untouched = FileStore::open(&path, PASSPHRASE).expect("right passphrase still works");
    let listed = untouched.list(&Scope::Env(TARGET.into())).expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(
        untouched.get(&listed[0]).expect("get").as_bytes(),
        PLAINTEXT.as_bytes()
    );
}

#[test]
fn empty_passphrase_is_rejected_and_not_treated_as_empty_store() {
    let dir = TempDir::new("empty-pass");
    let path = dir.file("creds.bin");
    {
        let (store, _clock) = store_at(&path, 0);
        put_env(&store, TARGET, PLAINTEXT);
    }
    let err = FileStore::open(&path, "").expect_err("empty passphrase must fail");
    assert!(matches!(err, StoreError::WrongPassphrase), "got {err:?}");
    assert_error_clean(&err, &[PLAINTEXT, TARGET]);
}
