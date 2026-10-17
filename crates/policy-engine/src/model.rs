//! 规格 §1 数据模型：线格式字段名与枚举数值在此冻结。
//!
//! 约定：
//! - `mode` 与 `strategy_empty_default` 是**数值**枚举（1/2/3/4、1），
//!   未知数值直接报错，不回退默认变体（见 [`mode`] 模块）。
//! - 所有结构体 `deny_unknown_fields`：拼错或夹带字段视为配置错误，不静默忽略。
//! - 只有确实存在安全缺省的字段才给默认值（见各字段注释）；
//!   `url_pattern` / `is_accessible` / `targets` 必填，缺失即解析失败。
//!
//! 本目录按职责分片，类型一律从 `crate::model::*` 再导出，
//! 调用方不需要知道分片边界。

mod action;
mod mode;
mod policy;
mod rule;
mod target;
mod window;

pub use action::{Action, Actions};
pub use mode::{EmptyStrategyDefault, PolicyMode};
pub use policy::PolicySpec;
pub use rule::RuleItem;
pub use target::{TargetContext, Targets};
pub use window::{ActiveRange, ActiveRangeError};
