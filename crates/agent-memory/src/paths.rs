//! 路径布局与越界防护（规格 §1/§2）。

use std::path::{Path, PathBuf};

use crate::error::MemoryError;

/// 记忆根路径：home = `~/.lengsuo`，workspace = 会话工作区。
#[derive(Debug, Clone)]
pub struct MemoryPaths {
    pub home: PathBuf,
    pub workspace: PathBuf,
}

impl MemoryPaths {
    pub fn new(home: impl Into<PathBuf>, workspace: impl Into<PathBuf>) -> Self {
        Self {
            home: home.into(),
            workspace: workspace.into(),
        }
    }

    /// 身份目录：`<home>/identity`。
    pub fn identity_dir(&self) -> PathBuf {
        self.home.join("identity")
    }

    /// 用户记忆文件：`<home>/memory/MEMORY.md`。
    pub fn user_memory_file(&self) -> PathBuf {
        self.home.join("memory").join("MEMORY.md")
    }

    /// 项目记忆目录：`<workspace>/.lengsuo/memory`。
    pub fn project_memory_dir(&self) -> PathBuf {
        self.workspace.join(".lengsuo").join("memory")
    }

    /// 项目记忆文件。
    pub fn project_memory_file(&self) -> PathBuf {
        self.project_memory_dir().join("MEMORY.md")
    }

    /// 当日日志文件：`<workspace>/.lengsuo/memory/YYYY-MM-DD.md`。
    pub fn daily_file(&self, date: chrono::NaiveDate) -> PathBuf {
        self.project_memory_dir().join(format!("{date}.md"))
    }

    /// 越界防护：`candidate` 必须落在 `base` 内（词法级校验；规格 §2）。
    pub fn ensure_within(base: &Path, candidate: &Path) -> Result<(), MemoryError> {
        let base_norm = normalize(base);
        let cand_norm = normalize(candidate);
        if cand_norm.starts_with(&base_norm) {
            Ok(())
        } else {
            Err(MemoryError::PathEscape)
        }
    }
}

/// 词法归一化：解析 `.`/`..` 段，不触盘（symlink 语义由调用方的 workspace 校验兜底）。
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}
