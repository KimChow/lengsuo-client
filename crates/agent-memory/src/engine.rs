//! 记忆引擎（规格 §3）：compose 只读聚合 + 显式写路径。
//!
//! 分层语义：
//! - 身份层（SOUL/USER/AI 名）恒可用，**不受跨会话记忆开关限制**（产品人格，非记忆）。
//! - 记忆三层（用户记忆 / 项目记忆 / 当日日志尾）受 `enabled` 控制：`compose` 只给
//!   `None`，写路径直接 `Err(Disabled)`；写闸门先于容量校验（开关关闭时不处理正文）。
//! - 读失败显式上抛（fail-closed：单层失败即整体 `Err`）；文件缺失表示「该层无内容」，
//!   不是错误（规格 §1）。
//! - 写路径顺序固定：闸门 → 越界 → 容量 → 落盘，且落盘只有一次 ⇒ 拒绝时不产生部分写入。
//! - 越界防护覆盖**全部**记忆路径（用户层/身份层以 `home` 为授权根，项目层以 `workspace`
//!   为授权根；规格 §2），读侧同样复核——否则 symlink 摆放可绕过写侧校验注入外部内容。

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use chrono::Local;

use crate::caps::{check_cap, CAP_PROJECT_MEMORY, CAP_USER_MEMORY};
use crate::daily::read_daily_tail;
use crate::error::MemoryError;
use crate::identity::{
    read_identity, write_ai_name, write_file, write_soul, write_user_name, Identity,
};
use crate::paths::MemoryPaths;

/// compose 注入的当日日志尾部行数上限（规格 §3：≤200 行）。
const DAILY_TAIL_LINES: usize = 200;

/// compose 产物（规格 §3）：恒含身份；记忆三层受开关控制。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBundle {
    pub identity: Identity,
    pub user_memory: Option<String>,
    pub project_memory: Option<String>,
    pub daily_tail: Option<String>,
}

/// 记忆引擎。`enabled=false` 时记忆三层整体停用（身份层不受限）。
pub struct MemoryEngine {
    pub(crate) paths: MemoryPaths,
    pub(crate) enabled: bool,
}

impl MemoryEngine {
    pub fn new(paths: MemoryPaths, enabled: bool) -> Self {
        Self { paths, enabled }
    }

    /// 聚合三层记忆 + 身份（只读）。任何一层读失败 ⇒ 整体 Err（fail-closed）。
    ///
    /// `daily_tail` 只取**当日**（本地日期，规格 §1/§3）文件的尾部；非当日文件不注入。
    pub fn compose(&self) -> Result<MemoryBundle, MemoryError> {
        // 身份层先读：不受开关限制，读失败同样显式上抛。
        let identity = read_identity(&self.paths)?;
        if !self.enabled {
            return Ok(MemoryBundle {
                identity,
                user_memory: None,
                project_memory: None,
                daily_tail: None,
            });
        }
        let user_memory = read_layer(&self.user_memory_file()?)?;
        let project_memory = read_layer(&self.project_memory_file()?)?;
        let today = Local::now().date_naive();
        let daily_tail = read_daily_tail(&self.paths, today, DAILY_TAIL_LINES)?;
        Ok(MemoryBundle {
            identity,
            user_memory,
            project_memory,
            daily_tail,
        })
    }

    /// 用户记忆覆写（≤4000 字符；disabled ⇒ Err(Disabled)）。
    pub fn set_user_memory(&self, text: &str) -> Result<(), MemoryError> {
        self.ensure_enabled()?;
        let file = self.user_memory_file()?;
        check_cap(CAP_USER_MEMORY, text)?;
        write_file(&file, text)
    }

    /// 项目记忆覆写（≤3000 字符；disabled ⇒ Err(Disabled)）。
    pub fn set_project_memory(&self, text: &str) -> Result<(), MemoryError> {
        self.ensure_enabled()?;
        let file = self.project_memory_file()?;
        check_cap(CAP_PROJECT_MEMORY, text)?;
        write_file(&file, text)
    }

    /// 身份读路径（规格 §3；不受开关限制，缺省名由 identity 模块兜底）。
    pub fn read_identity(&self) -> Result<Identity, MemoryError> {
        self.identity_dir()?;
        read_identity(&self.paths)
    }

    /// 身份写路径（不受开关限制）。
    pub fn set_soul(&self, text: &str) -> Result<(), MemoryError> {
        self.identity_dir()?;
        write_soul(&self.paths, text)
    }

    pub fn set_user_name(&self, name: &str) -> Result<(), MemoryError> {
        self.identity_dir()?;
        write_user_name(&self.paths, name)
    }

    pub fn set_ai_name(&self, name: &str) -> Result<(), MemoryError> {
        self.identity_dir()?;
        write_ai_name(&self.paths, name)
    }

    /// 清除用户记忆文件（规格 §2 查看/删除能力）。**不受开关限制**——关闭记忆后仍须
    /// 能删除历史残留（隐私优先于开关字面语义）；文件不存在视为已清空（幂等）。
    pub fn clear_user_memory(&self) -> Result<(), MemoryError> {
        remove_layer(&self.user_memory_file()?)
    }

    /// 清除项目记忆文件（同上；先过 workspace 越界防护）。
    pub fn clear_project_memory(&self) -> Result<(), MemoryError> {
        remove_layer(&self.project_memory_file()?)
    }

    /// 开关状态（测试与网关暴露用）。
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// 授权 workspace 内的项目记忆文件路径（规格 §2：项目层必须落在 workspace 内）。
    fn project_memory_file(&self) -> Result<PathBuf, MemoryError> {
        let file = self.paths.project_memory_file();
        MemoryPaths::ensure_within(&self.paths.workspace, &file)?;
        Ok(file)
    }

    /// 授权 home 内的用户记忆文件路径（规格 §1/§2：用户层固定主目录内）。
    fn user_memory_file(&self) -> Result<PathBuf, MemoryError> {
        let file = self.paths.user_memory_file();
        MemoryPaths::ensure_within(&self.paths.home, &file)?;
        Ok(file)
    }

    /// 授权 home 内的身份目录（规格 §2：与用户记忆层同一授权根）。
    fn identity_dir(&self) -> Result<PathBuf, MemoryError> {
        let dir = self.paths.identity_dir();
        MemoryPaths::ensure_within(&self.paths.home, &dir)?;
        Ok(dir)
    }

    /// 记忆三层写闸门：未开启即拒绝，且不触盘。
    fn ensure_enabled(&self) -> Result<(), MemoryError> {
        if self.enabled {
            Ok(())
        } else {
            Err(MemoryError::Disabled)
        }
    }
}

/// 单层记忆文件读取：存在 ⇒ `Some`，缺失 ⇒ `None`，其余 IO 错误上抛（不静默降级）。
///
/// 与 identity 模块同一读法（`NotFound` = 无内容，规格 §1）；区别在于此处要区分
/// 「文件不存在」（该层不注入）与「文件存在但为空」（注入空文本）。
fn read_layer(path: &Path) -> Result<Option<String>, MemoryError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(MemoryError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

/// 单层清除：`remove_file` 对不存在的路径报 NotFound ⇒ 视为已清空。
fn remove_layer(path: &Path) -> Result<(), MemoryError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(MemoryError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}
