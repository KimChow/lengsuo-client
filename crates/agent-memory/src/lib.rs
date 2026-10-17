//! 三层记忆系统（规格：MEMORY-SPEC.md v0）。
//!
//! 层级：身份（SOUL/USER/AI 名）→ 用户记忆（跨会话，默认关）→ 项目记忆 + 当日日志。
//! 隐私：跨会话层默认关闭；写路径由调用方负责脱敏；凭据绝不入内。

mod caps;
mod daily;
mod engine;
mod error;
mod identity;
mod paths;

pub use caps::{CAP_DAILY_LINE, CAP_PROJECT_MEMORY, CAP_SOUL, CAP_USER_MEMORY};
pub use daily::{append_daily, clear_daily, read_daily_tail};
pub use engine::{MemoryBundle, MemoryEngine};
pub use error::MemoryError;
pub use identity::{Identity, DEFAULT_AI_NAME, DEFAULT_USER_NAME};
pub use paths::MemoryPaths;

pub use chrono::NaiveDate;
