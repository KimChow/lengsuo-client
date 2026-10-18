#![cfg(unix)]
//! Blob 引用路径授权外沿：只有 blobs 目录下的普通文件才可读/可列出。
//!
//! 背景（PC06 workspace 边界 / PC25 产物授权的行为参考）：有效 uuid 引用对应的
//! `{uuid}.bin` 可能被替换成指向 workspace 外的 symlink，修复前 `get` 会读出外部
//! 文件内容。本组测试用**真实** symlink/目录验证 `get`/`list` 拒绝越界引用，
//! `remove` 不沿 symlink 删到外部目标，同时保持普通引用兼容。
//! 不覆盖：硬链接、检查-使用竞态（TOCTOU）——见 docs/blob-path-status.md。

use std::fs;
use std::path::PathBuf;

use agent_core::blobs::BlobStore;
use agent_core::error::CoreError;

const OUTSIDE_ID: &str = "6b1c1e2a-7c0e-4a1d-9b7f-2a5f8b3c1d40";

fn blob_name(id: &str) -> String {
    format!("{id}.bin")
}

/// 测试夹具：外部真实文件 + store 目录，TempDir 由夹具持有并在 Drop 时清理。
struct Fixture {
    store: BlobStore,
    blobs_dir: PathBuf,
    external: PathBuf,
    _roots: (tempfile::TempDir, tempfile::TempDir),
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temp root");
        let external_root = tempfile::tempdir().expect("temp external");
        let blobs_dir = root.path().join("blobs");
        fs::create_dir_all(&blobs_dir).expect("create blobs dir");
        let external = external_root.path().join("secret.bin");
        fs::write(&external, b"external secret").expect("write external");
        Self {
            store: BlobStore::new(&blobs_dir),
            blobs_dir,
            external,
            _roots: (root, external_root),
        }
    }

    /// 把一个合法引用改写成指向外部文件的 symlink，返回该引用 id。
    fn symlink_ref_to_external(&self) -> String {
        let reference = self.store.put(b"placeholder").expect("put placeholder").0;
        let link = self.blobs_dir.join(blob_name(&reference));
        fs::remove_file(&link).expect("remove regular file");
        std::os::unix::fs::symlink(&self.external, &link).expect("create symlink reference");
        reference
    }
}

fn is_io_or_not_found(e: &CoreError) -> bool {
    matches!(e, CoreError::Io { .. } | CoreError::BlobNotFound(_))
}

#[test]
fn regular_reference_still_round_trips() {
    let fx = Fixture::new();
    let reference = fx.store.put(b"plain bytes").expect("put").0;
    assert_eq!(
        fx.store.get(&reference).expect("read regular"),
        b"plain bytes"
    );
    assert_eq!(fx.store.list(), vec![reference.clone()]);
    fx.store.remove(&reference).expect("remove regular");
    assert!(fx.store.list().is_empty(), "removed ref gone from list");
    assert!(fx.store.get(&reference).is_err(), "removed ref unreadable");
}

#[test]
fn get_rejects_symlink_reference_pointing_outside() {
    let fx = Fixture::new();
    let reference = fx.symlink_ref_to_external();
    let err = match fx.store.get(&reference) {
        Ok(bytes) => panic!("symlink reference must not be readable, got {bytes:?}"),
        Err(e) => e,
    };
    assert!(is_io_or_not_found(&err), "unexpected error: {err:?}");
    assert!(
        !format!("{err}").contains("external secret"),
        "error text must not echo external content"
    );
}

#[test]
fn list_omits_symlink_reference() {
    let fx = Fixture::new();
    let symlinked = fx.symlink_ref_to_external();
    let regular = fx.store.put(b"regular").expect("put regular").0;

    let listed = fx.store.list();
    assert!(!listed.contains(&symlinked), "symlink must not be listed");
    assert_eq!(
        listed,
        vec![regular.clone()],
        "only the regular file listed"
    );

    assert_eq!(fx.store.get(&regular).expect("read regular"), b"regular");
    assert!(
        fx.store.get(&symlinked).is_err(),
        "symlink read still rejected"
    );
}

#[test]
fn get_and_list_reject_non_regular_file() {
    let fx = Fixture::new();
    let reference = fx.store.put(b"x").expect("put").0;
    // 用目录冒充 `{uuid}.bin`：非普通文件，read 也会走到错误分支。
    let decoy = fx.blobs_dir.join(blob_name(&reference));
    fs::remove_file(&decoy).expect("remove file");
    fs::create_dir(&decoy).expect("create decoy dir");

    let err = match fx.store.get(&reference) {
        Ok(bytes) => panic!("directory reference must not be readable, got {bytes:?}"),
        Err(e) => e,
    };
    assert!(is_io_or_not_found(&err), "unexpected error: {err:?}");
    assert!(
        fx.store.list().is_empty(),
        "non-regular entries must not be listed: {:?}",
        fx.store.list()
    );
}

#[test]
fn get_and_list_reject_dangling_symlink_reference() {
    let fx = Fixture::new();
    let reference = fx.store.put(b"y").expect("put").0;
    let link = fx.blobs_dir.join(blob_name(&reference));
    fs::remove_file(&link).expect("remove regular file");
    std::os::unix::fs::symlink(&fx.external, &link).expect("create symlink");
    fs::remove_file(&fx.external).expect("drop target => dangling link");

    let err = match fx.store.get(&reference) {
        Ok(bytes) => panic!("dangling symlink must not be readable, got {bytes:?}"),
        Err(e) => e,
    };
    assert!(is_io_or_not_found(&err), "unexpected error: {err:?}");
    assert!(
        fx.store.list().is_empty(),
        "dangling symlink must not be listed: {:?}",
        fx.store.list()
    );
}

#[test]
fn remove_never_deletes_external_target_through_symlink() {
    let fx = Fixture::new();
    let reference = fx.symlink_ref_to_external();
    // POSIX unlink 不跟随 symlink：允许清理时只摘掉引用本身，外部目标必须存活。
    let result = fx.store.remove(&reference);
    assert!(
        result.is_ok() || is_io_or_not_found(&result.expect_err("remove rejected")),
        "remove must not fail with unrelated errors"
    );
    assert!(fx.external.exists(), "external target must survive remove");
    assert_eq!(
        fs::read(&fx.external).expect("reread external"),
        b"external secret"
    );
    assert!(fx.store.list().is_empty(), "list empty after cleanup");
}

#[test]
fn remove_rejects_regular_file_through_symlinked_blobs_dir() {
    // blobs 目录本身是 symlink 时，remove 的 unlink 会落到外部文件：必须整体拒绝。
    let root = tempfile::tempdir().expect("temp root");
    let real_dir = root.path().join("real");
    fs::create_dir_all(&real_dir).expect("create real dir");
    let outside_file = real_dir.join(blob_name(OUTSIDE_ID));
    fs::write(&outside_file, b"outside content").expect("write outside blob");

    let link_dir = root.path().join("blobs");
    std::os::unix::fs::symlink(&real_dir, &link_dir).expect("symlink dir");
    let store = BlobStore::new(&link_dir);

    let err = store
        .remove(OUTSIDE_ID)
        .expect_err("remove must be refused via symlinked dir");
    assert!(is_io_or_not_found(&err), "unexpected error: {err:?}");
    assert!(
        outside_file.exists(),
        "external blob must survive refused remove"
    );
}

#[test]
fn refuses_when_blobs_dir_itself_is_symlink() {
    // blobs 目录本身是 symlink：保守拒绝读、列、写（拒绝策略见状态文档）。
    let root = tempfile::tempdir().expect("temp root");
    let real_dir = root.path().join("real");
    fs::create_dir_all(&real_dir).expect("create real dir");
    fs::write(real_dir.join(blob_name(OUTSIDE_ID)), b"outside content")
        .expect("write outside blob");

    let link_dir = root.path().join("blobs");
    std::os::unix::fs::symlink(&real_dir, &link_dir).expect("symlink dir");
    let store = BlobStore::new(&link_dir);

    assert!(
        store.get(OUTSIDE_ID).is_err(),
        "symlinked blobs dir must not authorize reads"
    );
    assert!(
        store.list().is_empty(),
        "symlinked blobs dir must not be listed: {:?}",
        store.list()
    );
    assert!(
        store.put(b"new").is_err(),
        "symlinked blobs dir must not accept writes"
    );
    assert!(
        fs::read_dir(&real_dir)
            .expect("real dir still readable")
            .count()
            > 0,
        "guard must not destroy the external dir contents"
    );
}

#[test]
fn missing_reference_still_reports_not_found() {
    let fx = Fixture::new();
    assert!(matches!(
        fx.store.get(OUTSIDE_ID),
        Err(CoreError::BlobNotFound(_))
    ));
    assert!(matches!(
        fx.store.get("not-a-uuid"),
        Err(CoreError::BlobNotFound(_))
    ));
    // 目录不存在时同样按空处理，不隐式创建。
    let root = tempfile::tempdir().expect("temp root");
    let store = BlobStore::new(root.path().join("absent"));
    assert!(store.list().is_empty());
    assert!(matches!(
        store.get(OUTSIDE_ID),
        Err(CoreError::BlobNotFound(_))
    ));
}
