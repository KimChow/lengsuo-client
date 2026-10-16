//! 记忆引擎（规格 §3）：compose 只读聚合 + 显式写路径。
//!
//! **本文件的 compose / set_user_memory / set_project_memory 由实现卡完成**——
//! 类型与签名已冻结，未实现处均为 `todo!()`（TDD 先红）。

use crate::error::MemoryError;
use crate::identity::{read_identity, write_ai_name, write_soul, write_user_name, Identity};
use crate::paths::MemoryPaths;

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
    pub fn compose(&self) -> Result<MemoryBundle, MemoryError> {
        todo!("实现卡 A：按规格 §3/§5 完成")
    }

    /// 用户记忆覆写（≤4000 字符；disabled ⇒ Err(Disabled)）。
    pub fn set_user_memory(&self, text: &str) -> Result<(), MemoryError> {
        let _ = text;
        todo!("实现卡 A")
    }

    /// 项目记忆覆写（≤3000 字符；disabled ⇒ Err(Disabled)）。
    pub fn set_project_memory(&self, text: &str) -> Result<(), MemoryError> {
        let _ = text;
        todo!("实现卡 A")
    }

    /// 身份写路径（不受开关限制）。
    pub fn set_soul(&self, text: &str) -> Result<(), MemoryError> {
        write_soul(&self.paths, text)
    }

    pub fn set_user_name(&self, name: &str) -> Result<(), MemoryError> {
        write_user_name(&self.paths, name)
    }

    pub fn set_ai_name(&self, name: &str) -> Result<(), MemoryError> {
        write_ai_name(&self.paths, name)
    }

    /// 开关状态（测试与网关暴露用）。
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}
