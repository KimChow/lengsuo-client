//! 卡 B 测试：当日日志与路径安全（规格 §5 第 4/6/7/8/9 组）。
//!
//! 只覆盖 `daily.rs` 的自由函数 API；`compose` 层面的三层聚合断言在卡 A 的
//! `engine_tests.rs`，本文件不依赖它（并行开发，互不阻塞）。
//!
//! 本文件是拆分后的测试二进制入口：只放共享 fixtures/helpers，
//! 各主题用例在 `basics.rs` / `path_safety.rs` / `capacity_and_io.rs` 中按原顺序搬移。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use agent_memory::{
    append_daily, clear_daily, read_daily_tail, MemoryError, MemoryPaths, NaiveDate,
};

mod basics;
mod capacity_and_io;
mod path_safety;

/// const 构造日期：测试内固定「当日」，不依赖真实时钟。
const fn ymd(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).expect("无效测试日期")
}

/// 固定「当日」，避免测试受真实时钟影响。
const TODAY: NaiveDate = ymd(2026, 10, 16);
const TOMORROW: NaiveDate = ymd(2026, 10, 17);
const OTHER_DAY: NaiveDate = ymd(2026, 10, 18);

/// 极简临时目录（不新增 tempfile 依赖，保持本 crate `--locked` 依赖面不变）。
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lengsuo-agent-memory-{}-{id}-{tag}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("临时目录可创建");
        Self { path }
    }

    fn workspace(&self) -> PathBuf {
        self.path.join("ws")
    }

    fn paths(&self) -> MemoryPaths {
        MemoryPaths::new(self.path.join("home"), self.workspace())
    }

    fn daily_file(&self, d: NaiveDate) -> PathBuf {
        self.paths().daily_file(d)
    }

    fn memory_dir(&self) -> PathBuf {
        self.workspace().join(".lengsuo").join("memory")
    }

    /// 当日文件的原始字节内容（断言落盘形态，含换行）。
    fn raw(&self, d: NaiveDate) -> String {
        fs::read_to_string(self.daily_file(d)).unwrap()
    }

    /// 尾部读取（unwrap 到 Result 外层，None 表示文件缺失）。
    fn tail(&self, d: NaiveDate, max_lines: usize) -> Option<String> {
        read_daily_tail(&self.paths(), d, max_lines).unwrap()
    }

    fn write_raw(&self, d: NaiveDate, content: &str) {
        fs::create_dir_all(self.memory_dir()).unwrap();
        fs::write(self.daily_file(d), content).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // 只读场景若中途 panic，权限可能还锁着；先放开再删，避免 /tmp 残留。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for dir in [self.memory_dir(), self.workspace()] {
                let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
            }
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// 逃逸场景统一断言：写 / 读 / 删三条入口都必须是 `PathEscape`（不留后门入口）。
#[cfg(unix)]
fn assert_all_paths_escape(tmp: &TempDir, scene: &str) {
    let results = [
        append_daily(&tmp.paths(), TODAY, "经逃逸路径写").map(|_| ()),
        read_daily_tail(&tmp.paths(), TODAY, 10).map(|_| ()),
        clear_daily(&tmp.paths(), TODAY),
    ];
    for result in results {
        assert!(
            matches!(result, Err(MemoryError::PathEscape)),
            "{scene}：读写删必须全部拒绝: {result:?}"
        );
    }
}

/// `ensure_within` 必须判为越界。
fn assert_ensure_escapes(base: &Path, candidate: &Path, scene: &str) {
    let result = MemoryPaths::ensure_within(base, candidate);
    assert!(
        matches!(result, Err(MemoryError::PathEscape)),
        "{scene}: {result:?}"
    );
}
