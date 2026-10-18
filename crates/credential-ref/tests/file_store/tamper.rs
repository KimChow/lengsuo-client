//! 篡改与截断的 fail-closed 行为（自原 file_store.rs 原样搬移）。

use crate::fixtures::*;
use std::fs;
#[test]
fn tampered_record_byte_fails_authentication() {
    let dir = TempDir::new("tamper-record");
    let path = dir.file("creds.bin");
    {
        let (store, _clock) = store_at(&path, 0);
        put_env(&store, TARGET, PLAINTEXT);
    }
    let mut bytes = read_bytes(&path);
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    fs::write(&path, &bytes).expect("write tampered");

    let err = FileStore::open(&path, PASSPHRASE).expect_err("tampered record must fail");
    assert!(
        matches!(err, StoreError::RecordAuthentication),
        "got {err:?}"
    );
    assert_error_clean(&err, &[PLAINTEXT, TARGET, PASSPHRASE]);
}

#[test]
fn tampered_header_byte_breaks_record_binding() {
    let dir = TempDir::new("tamper-header");
    let path = dir.file("creds.bin");
    {
        let (store, _clock) = store_at(&path, 0);
        put_env(&store, TARGET, PLAINTEXT);
    }
    // 记录 AAD 绑定整个头部，改头部任一字节都无法通过认证。
    for offset in [8usize, 12, 16, 20, 24, 32, 39] {
        let mut bytes = read_bytes(&path);
        bytes[offset] ^= 0x01;
        fs::write(&path, &bytes).expect("write tampered header");
        let err =
            FileStore::open(&path, PASSPHRASE).expect_err("tampered header at {offset} must fail");
        assert!(
            matches!(
                err,
                StoreError::WrongPassphrase | StoreError::RecordAuthentication
            ),
            "offset {offset} gave {err:?}"
        );
        assert_error_clean(&err, &[PLAINTEXT, TARGET, PASSPHRASE]);
    }
}

#[test]
fn every_truncated_prefix_fails_closed() {
    let dir = TempDir::new("truncated");
    let path = dir.file("creds.bin");
    let reference = {
        let (store, _clock) = store_at(&path, 0);
        put_env(&store, TARGET, PLAINTEXT)
    };
    let full = read_bytes(&path);
    // 额外再写一条，确保截断点落在记录区内。
    {
        let store = FileStore::with_clock(&path, PASSPHRASE, credential_ref::fixed_clock(0))
            .expect("reopen");
        put_env(&store, "env-second", "second-value");
    }
    let multi = read_bytes(&path);

    for case in [&full, &multi] {
        for cut in 1..case.len() {
            fs::write(&path, &case[..cut]).expect("write truncated");
            let err =
                FileStore::open(&path, PASSPHRASE).expect_err("truncated file must never open");
            assert!(
                matches!(
                    err,
                    StoreError::MalformedContainer(_)
                        | StoreError::RecordAuthentication
                        | StoreError::WrongPassphrase
                        | StoreError::UnsupportedVersion { .. }
                ),
                "cut {cut} gave {err:?}"
            );
            assert_error_clean(&err, &[PLAINTEXT, TARGET, PASSPHRASE]);
        }
    }

    // 空文件也要 fail-closed（只有“文件不存在”才当作空库）。
    fs::write(&path, b"").expect("write empty");
    assert!(FileStore::open(&path, PASSPHRASE).is_err());
    // 尾部多余字节。
    fs::write(&path, [&multi[..], b"trailing-garbage".as_slice()].concat()).expect("append");
    assert!(FileStore::open(&path, PASSPHRASE).is_err());
    // 完好文件仍可读取（证明上面的失败源于截断而非环境）。
    fs::write(&path, &multi).expect("restore");
    let store = FileStore::open(&path, PASSPHRASE).expect("valid file opens");
    assert_eq!(
        store.get(&reference).expect("get").as_bytes(),
        PLAINTEXT.as_bytes()
    );
}
