//! 规格 §1 数据模型分片：`policy`。
//!
//! 统一从 [`crate::model`] 再导出，字段名/数值契约见本目录各文件。
//! 策略定义 `PolicySpec`（规格 §1）。

use serde::{Deserialize, Serialize};

use crate::model::{
    ActiveRange, ActiveRangeError, EmptyStrategyDefault, PolicyMode, RuleItem, Targets,
};
/// 策略定义（规格 §1 `PolicySpec`）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySpec {
    /// 策略 ID。
    pub policy_id: String,
    /// 策略名称（仅用于 reason 展示，不参与判定）。
    pub name: String,
    /// 模式（数值冻结）。
    pub mode: PolicyMode,
    /// `rules` 为空时的兜底模式；缺省 Black（实证结论，规格 §1）。
    #[serde(default)]
    pub strategy_empty_default: EmptyStrategyDefault,
    /// 生效对象。
    pub targets: Targets,
    /// 规则列表（顺序即同精度下的优先级，规格 §2.4）。
    #[serde(default)]
    pub rules: Vec<RuleItem>,
    /// 生效时间窗；`None` 表示不限时段。
    #[serde(default)]
    pub active_range: Option<ActiveRange>,
}

impl PolicySpec {
    /// 按模式构造一条不含规则的策略（黑名单/特殊案例场景的常用起点）。
    #[must_use]
    pub fn new(
        policy_id: impl Into<String>,
        name: impl Into<String>,
        mode: PolicyMode,
        targets: Targets,
        rules: Vec<RuleItem>,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            name: name.into(),
            mode,
            strategy_empty_default: EmptyStrategyDefault::Black,
            targets,
            rules,
            active_range: None,
        }
    }

    /// 设置生效时间窗；反向区间返回错误而不是静默接受。
    pub fn with_active_range(
        mut self,
        start_ms: u64,
        end_ms: u64,
    ) -> Result<Self, ActiveRangeError> {
        self.active_range = Some(ActiveRange::checked_new(start_ms, end_ms)?);
        Ok(self)
    }

    /// 该策略是否完全没有规则。
    #[must_use]
    pub fn has_no_rules(&self) -> bool {
        self.rules.is_empty()
    }
}
