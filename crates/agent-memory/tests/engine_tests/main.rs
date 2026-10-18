//! 卡 A 测试：记忆引擎核心（规格 §5 第 1/2/3/5 组 + §2 删除能力）。
//!
//! 只覆盖 `engine.rs` 的 `MemoryEngine` API；`daily.rs` 的追加/尾部/清除/路径安全
//! 在卡 B 的 `daily_tests.rs`（并行开发，本文件仅通过 compose 间接使用当日日志读取）。
//!
//! 时间口径：compose 的「当日」取本地时钟（规格 §1/§3），故涉及日志的用例先取
//! `today()` 再写入同一日期，不在断言里二次读时钟（跨零点才可能漂移，毫秒内不成立）。
//!
//! 本文件是拆分后的测试二进制入口：只放共享 fixtures/helpers，
//! 各主题用例在 `compose.rs` / `memory_switch.rs` / `capacity.rs` /
//! `identity.rs` / `clear.rs` 中按原顺序搬移。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use agent_memory::{
    Identity, MemoryEngine, MemoryError, MemoryPaths, NaiveDate, DEFAULT_AI_NAME, DEFAULT_USER_NAME,
};

mod capacity;
mod clear;
mod compose;
mod identity;
mod memory_switch;

/// 本地「今日」——与 compose 内部同一口径。
fn today() -> NaiveDate {
    chrono::Local::now().date_naive()
}

/// `d` 往前 `days` 天（用于「非当日不注入」断言）。
fn days_before(d: NaiveDate, days: u64) -> NaiveDate {
    d.checked_sub_days(chrono::Days::new(days))
        .expect("测试日期有效")
}

/// 极简临时目录（不新增 tempfile 依赖：本 crate `Cargo.toml` 冻结，`--locked` 依赖面不变）。
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lengsuo-agent-memory-engine-{pid}-{id}-{tag}",
            pid = std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("临时目录可创建");
        Self { path }
    }

    fn paths(&self) -> MemoryPaths {
        MemoryPaths::new(self.path.join("home"), self.path.join("ws"))
    }

    fn engine(&self, enabled: bool) -> MemoryEngine {
        MemoryEngine::new(self.paths(), enabled)
    }

    fn user_memory(&self) -> PathBuf {
        self.paths().user_memory_file()
    }

    fn project_memory(&self) -> PathBuf {
        self.paths().project_memory_file()
    }

    fn identity_dir(&self) -> PathBuf {
        self.paths().identity_dir()
    }

    /// 直接落盘（绕过写路径，构造「盘上已有内容」的前置状态）。
    fn put(&self, path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn read(&self, path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn default_identity() -> Identity {
    Identity {
        ai_name: DEFAULT_AI_NAME.into(),
        user_name: DEFAULT_USER_NAME.into(),
        soul: String::new(),
    }
}

/// 指定字符数的正文（3 字节/字符，可同时暴露「按字节计数」的错误实现）。
fn text_of_chars(len: usize) -> String {
    "记".repeat(len)
}

/// 断言错误为 `CapExceeded { cap, len }`（变体与两个数值一并核对，失败时打印实际值）。
fn assert_cap_err(err: MemoryError, cap: usize, len: usize) {
    assert!(
        matches!(err, MemoryError::CapExceeded { cap: c, len: l } if c == cap && l == len),
        "期望 CapExceeded{{cap={cap}, len={len}}}，实际 {err:?}"
    );
}

/// 断言 `Result` 为 `Err(MemoryError::Disabled)`。
fn assert_disabled(res: Result<(), MemoryError>, label: &str) {
    assert!(
        matches!(res, Err(MemoryError::Disabled)),
        "{label} 关闭时未返回 Disabled：{res:?}"
    );
}
