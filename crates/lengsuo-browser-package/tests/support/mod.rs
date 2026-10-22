//! Shared helpers for the extension-digest tests: loading the fixed vectors
//! and building throwaway directories.
//!
//! The crate has no `tempfile` dependency and this card may not add one, so
//! the temporary directories are built by hand: a unique name under
//! `std::env::temp_dir()`, removed when the value goes out of scope.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Distinguishes two temporary directories created in the same nanosecond.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// The fixed digest vectors shared with the extension repository.
pub fn vectors() -> serde_json::Value {
    let path = vector_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("vector file is valid JSON")
}

/// Path of the shared vector file.
pub fn vector_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/extension-digest-v1.json")
}

/// Decode hex into raw bytes.
pub fn hex_bytes(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap_or_else(|e| panic!("bad hex {text:?}: {e}"))
}

/// Decode 64 hex characters into 32 raw bytes.
pub fn hex32(text: &str) -> [u8; 32] {
    let bytes = hex_bytes(text);
    assert_eq!(
        bytes.len(),
        32,
        "expected a 32-byte digest, got {}",
        bytes.len()
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// A throwaway directory, removed when it goes out of scope.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create an empty temporary directory with a unique name.
    pub fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lengsuo-w5-{tag}-{}-{nanos}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path)
            .unwrap_or_else(|e| panic!("cannot create {}: {e}", path.display()));
        Self { path }
    }

    /// The directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write `contents` to `rel` inside the directory, creating parents.
    ///
    /// `rel` is a POSIX-style relative path.
    pub fn write(&self, rel: &str, contents: &[u8]) {
        let target = self.path.join(rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|e| panic!("cannot create {}: {e}", parent.display()));
        }
        std::fs::write(&target, contents)
            .unwrap_or_else(|e| panic!("cannot write {}: {e}", target.display()));
    }

    /// Create a symbolic link at `rel` pointing at `target`.
    #[cfg(unix)]
    pub fn symlink(&self, rel: &str, target: &str) {
        let link = self.path.join(rel);
        if let Some(parent) = link.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|e| panic!("cannot create {}: {e}", parent.display()));
        }
        std::os::unix::fs::symlink(target, &link)
            .unwrap_or_else(|e| panic!("cannot link {}: {e}", link.display()));
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
