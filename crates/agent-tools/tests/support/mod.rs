//! 测试公共脚手架：隔离工作区 + 隔离回收站目录。
//!
//! 回收站通过 `XDG_DATA_HOME` 重定向到临时目录（`trash` 在 freedesktop 实现里
//! 优先读该变量），既能在 `~/.local/share/Trash` 之外验证落点，也不污染开发机真实回收站。

// 共享脚手架：各测试二进制按主题取用不同子集，未用项属预期，非真实死代码。
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tempfile::TempDir;

/// 每个用例一套临时目录：`ws/` 是工作区，`outside/` 模拟工作区外路径。
pub struct Sandbox {
    pub workspace: PathBuf,
    pub outside: PathBuf,
    _tmp: TempDir,
}

impl Sandbox {
    pub fn new() -> Self {
        let tmp = TempDir::new().expect("创建临时目录失败");
        let root = tmp.path().to_path_buf();
        let workspace = root.join("ws");
        let outside = root.join("outside");
        fs::create_dir_all(&workspace).expect("创建工作区失败");
        fs::create_dir_all(outside.join("nested")).expect("创建区外目录失败");
        Self {
            workspace,
            outside,
            _tmp: tmp,
        }
    }

    /// 工作区内绝对路径。
    pub fn ws(&self, rel: &str) -> PathBuf {
        self.workspace.join(rel)
    }

    /// 在工作区内写文件（父目录自动创建）。
    pub fn put(&self, rel: &str, content: &str) -> PathBuf {
        let path = self.ws(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("创建父目录失败");
        }
        fs::write(&path, content).expect("写入测试文件失败");
        path
    }

    pub fn get(&self, rel: &str) -> String {
        fs::read_to_string(self.ws(rel)).unwrap_or_default()
    }
}

/// 全测试进程共享的回收站根目录；只设置一次 `XDG_DATA_HOME`。
pub fn trash_home() -> &'static Path {
    static TRASH: OnceLock<PathBuf> = OnceLock::new();
    TRASH.get_or_init(|| {
        let dir = TempDir::new().expect("创建回收站临时目录失败").keep();
        // 测试进程内单点设置：trash 的 freedesktop 实现在删除时才读取该变量。
        std::env::set_var("XDG_DATA_HOME", &dir);
        dir.join("Trash")
    })
}

/// 回收站 `files/` 目录（freedesktop 布局）。顺带确保目录存在。
pub fn trash_files() -> PathBuf {
    let dir = trash_home().join("files");
    fs::create_dir_all(&dir).expect("创建回收站 files 目录失败");
    dir
}

/// 回收站 `info/*.trashinfo` 与 `files/` 中的条目总数。
pub fn trash_entry_count() -> usize {
    count_entries(&trash_files()) + count_entries(&trash_home().join("info"))
}

fn count_entries(dir: &Path) -> usize {
    match fs::read_dir(dir) {
        Ok(rd) => rd.flatten().count(),
        Err(_) => 0,
    }
}

/// 回收站里是否存在指定原始文件名的条目（`files/` 保留原名）。
pub fn trashed_named(name: &str) -> bool {
    is_present(&trash_files(), name)
}

fn is_present(dir: &Path, name: &str) -> bool {
    let Ok(rd) = fs::read_dir(dir) else {
        return false;
    };
    rd.flatten().any(|e| {
        let file = e.file_name().to_string_lossy().into_owned();
        file == name || file.strip_suffix(".trashinfo").is_some_and(|s| s == name)
    })
}
