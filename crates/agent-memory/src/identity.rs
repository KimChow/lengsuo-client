//! 身份层（规格 §1/§3）：SOUL（人格）+ USER（用户名）+ AI 名。
//!
//! 身份层不受「跨会话记忆开关」限制（产品人格，非记忆）。

use std::path::Path;

use crate::caps::CAP_SOUL;
use crate::error::MemoryError;
use crate::paths::MemoryPaths;

/// 身份三元组（compose 时恒填充，缺省值见常量）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub ai_name: String,
    pub user_name: String,
    pub soul: String,
}

pub const DEFAULT_AI_NAME: &str = "Lengsuo";
pub const DEFAULT_USER_NAME: &str = "user";

impl Default for Identity {
    fn default() -> Self {
        Self {
            ai_name: DEFAULT_AI_NAME.into(),
            user_name: DEFAULT_USER_NAME.into(),
            soul: String::new(),
        }
    }
}

/// 用户名/AI 名单文件名（内容即名字本身，一行）。
pub const USER_NAME_FILE: &str = "USER.md";
pub const AI_NAME_FILE: &str = "AI_NAME";
pub const SOUL_FILE: &str = "SOUL.md";

pub(crate) fn read_identity(paths: &MemoryPaths) -> Result<Identity, MemoryError> {
    let dir = paths.identity_dir();
    // 逐字段直接构造（缺省由各自的 default 兜底）：语义与旧写法一致，只是不再
    // 先 `Identity::default()` 再整体覆写（clippy::field_reassign_with_default）。
    Ok(Identity {
        user_name: read_trimmed_or_default(&dir.join(USER_NAME_FILE), DEFAULT_USER_NAME)?,
        ai_name: read_trimmed_or_default(&dir.join(AI_NAME_FILE), DEFAULT_AI_NAME)?,
        soul: read_or_empty(&dir.join(SOUL_FILE))?,
    })
}

pub(crate) fn write_soul(paths: &MemoryPaths, text: &str) -> Result<(), MemoryError> {
    crate::caps::check_cap(CAP_SOUL, text)?;
    write_file(&paths.identity_dir().join(SOUL_FILE), text)
}

pub(crate) fn write_user_name(paths: &MemoryPaths, name: &str) -> Result<(), MemoryError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(MemoryError::EmptyName);
    }
    write_file(&paths.identity_dir().join(USER_NAME_FILE), name)
}

pub(crate) fn write_ai_name(paths: &MemoryPaths, name: &str) -> Result<(), MemoryError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(MemoryError::EmptyName);
    }
    write_file(&paths.identity_dir().join(AI_NAME_FILE), name)
}

fn read_trimmed_or_default(path: &Path, default: &str) -> Result<String, MemoryError> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let t = s.trim();
            if t.is_empty() {
                Ok(default.into())
            } else {
                Ok(t.into())
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(default.into()),
        Err(e) => Err(MemoryError::Io {
            path: path.into(),
            source: e,
        }),
    }
}

fn read_or_empty(path: &Path) -> Result<String, MemoryError> {
    std::fs::read_to_string(path).or_else(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Ok(String::new()),
        other => Err(MemoryError::Io {
            path: path.into(),
            source: std::io::Error::new(other, "read"),
        }),
    })
}

pub(crate) fn write_file(path: &Path, text: &str) -> Result<(), MemoryError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| MemoryError::Io {
            path: parent.into(),
            source: e,
        })?;
    }
    std::fs::write(path, text).map_err(|e| MemoryError::Io {
        path: path.into(),
        source: e,
    })
}
