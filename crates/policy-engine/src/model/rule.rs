//! 规格 §1 数据模型分片：`rule`。
//!
//! 统一从 [`crate::model`] 再导出，字段名/数值契约见本目录各文件。
//! 规则项 `RuleItem`（规格 §1）。

use serde::{Deserialize, Serialize};

use crate::model::Actions;

/// 规则项（规格 §1 `RuleItem`）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleItem {
    /// 通配符 URL 模式，评估前由引擎编译。
    pub url_pattern: String,
    /// 该 URL 是否可访问（白名单规则 `true`，黑名单规则 `false`）。
    pub is_accessible: bool,
    /// 是否记录访问行为；与 `is_accessible` 相互独立。
    #[serde(default)]
    pub is_log: bool,
    /// 七个操作的开关。缺省为全 false（deny-by-default）。
    #[serde(default)]
    pub actions: Actions,
    /// `click_dom` 的选择器粒度；引擎只做字符串比对，不解析 DOM。
    #[serde(default)]
    pub dom_selectors: Vec<String>,
}

impl RuleItem {
    /// 白名单规则：可访问，只开放 `access`，不记录。
    #[must_use]
    pub fn allow(url_pattern: impl Into<String>) -> Self {
        Self {
            url_pattern: url_pattern.into(),
            is_accessible: true,
            is_log: false,
            actions: Actions::access_only(),
            dom_selectors: Vec::new(),
        }
    }

    /// 黑名单规则：不可访问，操作全拒。
    #[must_use]
    pub fn deny(url_pattern: impl Into<String>) -> Self {
        Self {
            url_pattern: url_pattern.into(),
            is_accessible: false,
            is_log: false,
            actions: Actions::none(),
            dom_selectors: Vec::new(),
        }
    }

    /// 允许全部七项操作的白名单规则。
    #[must_use]
    pub fn allow_all_actions(url_pattern: impl Into<String>) -> Self {
        Self {
            actions: Actions::all(),
            ..Self::allow(url_pattern)
        }
    }
}
