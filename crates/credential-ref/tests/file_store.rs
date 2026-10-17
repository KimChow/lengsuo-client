//! FileStore 硬规则测试：落盘往返、口令错误、篡改、截断、版本不识别、
//! 跨作用域不可见、过期、并发、文件内不含明文与元数据。
//!
//! 所有用例使用固定/可控时钟与测试专用假口令，不触碰真实凭据。

// 头部偏移常量与读取辅助是布局契约的完整记录，保留备用（与 tests/support 同规则）。
#![allow(dead_code)]

mod support;

use std::fs;
use std::sync::Arc;

use credential_ref::{
    CredentialRef, FileStore, KdfParams, Plaintext, Scope, SecretStore, StoreError,
};
use support::{assert_error_clean, file_contains, windows_contains, ManualClock, TempDir};

const PASSPHRASE: &str = "test-passphrase-DoNotLog";
const WRONG_PASSPHRASE: &str = "wrong-test-passphrase";
const PLAINTEXT: &str = "file-store-sup3r-token-DoNotLog";
const TARGET: &str = "env-file-target";

/// 新建带可控时钟的文件库（测试假口令，固定起始时刻）。
fn store_at(path: &std::path::Path, now_ms: u64) -> (FileStore, ManualClock) {
    let clock = ManualClock::new(now_ms);
    let store = FileStore::with_clock(path, PASSPHRASE, clock.clock()).expect("open store");
    (store, clock)
}

/// 写入一条环境作用域凭据并返回引用（`u64::MAX` 表示永不过期）。
fn put_env(store: &dyn SecretStore, target: &str, value: &str) -> CredentialRef {
    let reference = CredentialRef::env(target, u64::MAX);
    store
        .put(&reference, &Plaintext::from(value))
        .expect("put succeeds");
    reference
}

fn read_bytes(path: &std::path::Path) -> Vec<u8> {
    fs::read(path).expect("store file must exist")
}

/// 头部定长前缀：magic(8) + schema_version(4) + iterations(4) + key_len(4) + salt(16) = 36。
const PREFIX_LEN: usize = 36;
const OFFSET_SCHEMA_VERSION: usize = 8;
const OFFSET_ITERATIONS: usize = 12;
const OFFSET_KEY_LEN: usize = 16;
const OFFSET_SALT: usize = 20;
const OFFSET_VERIFIER_LEN: usize = 36;
const OFFSET_VERIFIER_BODY: usize = 40;

/// 头部字节长度：定长前缀 + verifier 长度域 + verifier（nonce+密文+tag）。
fn header_len(bytes: &[u8]) -> usize {
    let verifier_len = u32::from_le_bytes(
        bytes[OFFSET_VERIFIER_LEN..OFFSET_VERIFIER_LEN + 4]
            .try_into()
            .expect("verifier length field"),
    ) as usize;
    PREFIX_LEN + 4 + verifier_len
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 field"))
}

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

#[test]
fn reopen_and_auth_failure_do_not_write_stderr() {
    let exe = std::env::current_exe().expect("test executable");
    for name in [
        "put_get_roundtrip_and_reopen_keeps_plaintext",
        "wrong_passphrase_is_rejected_on_open",
    ] {
        let result = std::process::Command::new(&exe)
            .args(["--exact", name, "--nocapture"])
            .output()
            .expect("child test");
        assert!(result.status.success(), "child test failed");
        assert!(
            result.stderr.is_empty(),
            "credential operations must not emit diagnostics to stderr"
        );
    }
}
