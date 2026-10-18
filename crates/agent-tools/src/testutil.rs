//! 测试支撑（仅 cfg(test) 编译）：临时目录封装。
//!
//! 供 crate 内各模块单测使用；产品代码不得引用。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// 进程内唯一、drop 时清理的临时目录。
pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// 在系统临时目录下创建唯一目录。
    pub fn new() -> Self {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("agent-tools-test-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&path).expect("创建测试临时目录");
        Self { path }
    }

    /// 目录路径。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
