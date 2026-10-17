//! 路径布局与越界防护（规格 §1/§2）。
//!
//! 规格 §2 要求「workspace 校验 `canonicalize` 前缀，`..` 拒绝」：本模块的
//! `ensure_within` 是唯一实现点，记忆三层与身份层的读/写/删共用同一边界口径
//! （原先只有当日日志做了真实路径复核，其余层仅词法，symlink 可绕过）。

use std::fs;
use std::io::ErrorKind;
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

    /// 越界防护：`candidate` 必须落在授权根 `base` 内（规格 §2）。
    ///
    /// 两步判定：
    /// 1. **词法**：解析 `.`/`..` 后比前缀，拦下显式穿越，且在触盘前完成；
    /// 2. **真实路径复核**：取 `candidate` 祖先链中**最深存在实体**（按
    ///    `symlink_metadata`，含悬空 symlink）的 `canonicalize` 结果，要求仍落在
    ///    `canonicalize(base)` 内——拦下「词法合法、但经 symlink 逃到授权根外」的读/写/删。
    ///
    /// 局限（显式记录，不隐藏）：两步之间不做原子保证（TOCTOU）；`base` 自身若是
    /// symlink，其真实路径即为授权根（摆放方式，会话建立时的 workspace 授权由调用方兜底）。
    pub fn ensure_within(base: &Path, candidate: &Path) -> Result<(), MemoryError> {
        let base_norm = normalize(base);
        let cand_norm = normalize(candidate);
        if !within(&base_norm, &cand_norm) {
            return Err(MemoryError::PathEscape);
        }
        check_real_prefix(&base_norm, &cand_norm)
    }
}

/// 词法归一化：解析 `.`/`..` 段，不触盘。
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

/// 词法前缀判定（已归一化）。
fn within(base: &Path, candidate: &Path) -> bool {
    candidate.starts_with(base)
}

/// 真实路径复核：见 `ensure_within` 第 2 步。
fn check_real_prefix(base: &Path, target: &Path) -> Result<(), MemoryError> {
    let root = match fs::canonicalize(base) {
        Ok(root) => root,
        // 授权根尚不存在 ⇒ 其子树不可能有可逃逸的落盘实体，词法校验已足够。
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_err(base, e)),
    };
    for ancestor in target.ancestors() {
        // 越出授权根词法边界即停：不再用上层目录误判成逃逸。
        if !within(base, ancestor) {
            break;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(_) => {}
            // 尚未创建 ⇒ 继续向上层找；create_dir_all 只会在通过复核的真实目录内新建。
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(io_err(ancestor, e)),
        }
        let real = fs::canonicalize(ancestor).map_err(|e| match e.kind() {
            // 悬空 symlink 无法确认落点 ⇒ fail-closed 拒绝，不能让 create_dir_all 穿透建目录。
            ErrorKind::NotFound => MemoryError::PathEscape,
            _ => io_err(ancestor, e),
        })?;
        return if within(&root, &real) {
            Ok(())
        } else {
            Err(MemoryError::PathEscape)
        };
    }
    Ok(())
}

/// 统一 IO 错误包装：带路径，不带内容（规格 §2 隐私要求）。
fn io_err(path: &Path, source: std::io::Error) -> MemoryError {
    MemoryError::Io {
        path: path.to_path_buf(),
        source,
    }
}
