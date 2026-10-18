//! 文件缺失/未知版本/KDF 头部可读性（自原 file_store.rs 原样搬移）。

use crate::fixtures::*;
use std::fs;
#[test]
fn missing_file_is_empty_store_but_unreadable_file_is_not() {
    let dir = TempDir::new("missing-vs-unreadable");
    let absent = dir.file("absent.bin");
    let store = FileStore::open(&absent, PASSPHRASE).expect("absent file is an empty store");
    assert!(store
        .list(&Scope::Env(TARGET.into()))
        .expect("list")
        .is_empty());

    // 目录冒充存储文件：IO 读取失败，绝不能被当成空库静默接受。
    let directory = dir.file("not-a-file.bin");
    fs::create_dir(&directory).expect("create dir");
    let err = FileStore::open(&directory, PASSPHRASE).expect_err("unreadable must fail closed");
    assert!(matches!(err, StoreError::Io(_)), "got {err:?}");
    assert_eq!(
        err.io_kind()
            .map(|kind| kind == std::io::ErrorKind::NotFound),
        Some(false)
    );
    assert_error_clean(&err, &[PLAINTEXT, TARGET, PASSPHRASE]);
    // 路径与系统消息不得出现在任何展示面上。
    let rendered = format!("{err} {err:?}");
    assert!(!rendered.contains(&directory.to_string_lossy().to_string()));
    assert!(!file_contains(&absent, PLAINTEXT.as_bytes()));
}

#[test]
fn unknown_schema_version_refuses_to_decrypt() {
    let dir = TempDir::new("version");
    let path = dir.file("creds.bin");
    {
        let (store, _clock) = store_at(&path, 0);
        put_env(&store, TARGET, PLAINTEXT);
    }
    // 规格演进：版本字段受 verifier AAD 认证绑定 ⇒ 篡改版本与其他头字节一致，
    // 报认证失败（认证一致的未识别版本被版本门拒绝，由 container 单测承载）。
    for declared in [0u32, 2, 42] {
        let mut bytes = read_bytes(&path);
        // magic 之后 4 字节即 schema_version（小端）。
        bytes[8..12].copy_from_slice(&declared.to_le_bytes());
        fs::write(&path, &bytes).expect("write version");
        let err = FileStore::open(&path, PASSPHRASE).expect_err("unknown version must fail");
        assert!(
            matches!(
                err,
                StoreError::WrongPassphrase | StoreError::RecordAuthentication
            ),
            "declared {declared} gave {err:?}"
        );
        assert_error_clean(&err, &[PLAINTEXT, TARGET, PASSPHRASE]);
    }
    // magic 不符同样是结构非法，且不尝试解密。
    let mut bytes = read_bytes(&path);
    bytes[0] ^= 0xFF;
    fs::write(&path, &bytes).expect("write magic");
    let err = FileStore::open(&path, PASSPHRASE).expect_err("bad magic must fail");
    assert!(
        matches!(err, StoreError::MalformedContainer(_)),
        "got {err:?}"
    );
}

#[test]
fn header_records_kdf_parameters_readable_back() {
    let dir = TempDir::new("kdf-header");
    let path = dir.file("creds.bin");
    {
        let (store, _clock) = store_at(&path, 0);
        put_env(&store, TARGET, PLAINTEXT);
        assert_eq!(store.kdf_params(), KdfParams::V0);
    }
    let bytes = read_bytes(&path);
    assert_eq!(&bytes[..8], b"LSCRED01");
    let u32_at = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    assert_eq!(u32_at(8), KdfParams::V0.schema_version);
    assert_eq!(u32_at(12), KdfParams::V0.iterations);
    assert_eq!(u32_at(16), KdfParams::V0.key_len);
    assert_eq!(
        KdfParams::V0.iterations,
        1,
        "v0 拉伸轮数为 1（内存硬化留待遗留项）"
    );
    assert_eq!(KdfParams::V0.key_len, 32, "AES-256-GCM 需 32 字节密钥");
}
