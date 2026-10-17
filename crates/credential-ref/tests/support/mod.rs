//! 测试辅助：隔离临时目录、可控时钟、明文泄漏检查。
//!
//! 各集成测试目标只用到部分辅助，故整体允许 dead_code。
#![allow(dead_code)]

use std::error::Error as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use credential_ref::{StoreClock, StoreError};

/// 独占临时目录：`<tmp>/lengsuo-credential-ref-tests/<name>-<seq>`。
///
/// 无第三方依赖（不引入 tempfile），构造时清理同名残留，Drop 时删除整目录。
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir()
            .join("lengsuo-credential-ref-tests")
            .join(format!("{tag}-{pid}-{seq}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 可控毫秒时钟：测试可推进时间以触发过期。
pub struct ManualClock {
    now: Arc<AtomicU64>,
}

impl ManualClock {
    pub fn new(now_ms: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now_ms)),
        }
    }

    pub fn advance_to(&self, now_ms: u64) {
        self.now.store(now_ms, Ordering::Relaxed);
    }

    pub fn clock(&self) -> StoreClock {
        let now = Arc::clone(&self.now);
        Arc::new(move || now.load(Ordering::Relaxed))
    }
}

/// 文件字节里是否出现给定明文（用于断言密文不落明文）。
pub fn file_contains(path: &std::path::Path, needle: &[u8]) -> bool {
    match std::fs::read(path) {
        Ok(bytes) => windows_contains(&bytes, needle),
        Err(_) => false,
    }
}

pub fn windows_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// 错误信息脱敏检查：`Display`、`Debug`、source 链都不得包含给定子串。
pub fn assert_error_clean(err: &StoreError, needles: &[&str]) {
    let display = err.to_string();
    let debug = format!("{err:?}");
    let mut source_chain = String::new();
    let mut cursor = err.source();
    while let Some(current) = cursor {
        source_chain.push_str(&current.to_string());
        source_chain.push_str(" | ");
        cursor = current.source();
    }
    for needle in needles {
        assert!(
            !display.contains(needle),
            "Display leaks {needle:?}: {display}"
        );
        assert!(!debug.contains(needle), "Debug leaks {needle:?}: {debug}");
        assert!(
            !source_chain.contains(needle),
            "source chain leaks {needle:?}: {source_chain}"
        );
    }
}
