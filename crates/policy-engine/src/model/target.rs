//! 规格 §1 数据模型分片：`target`。
//!
//! 统一从 [`crate::model`] 再导出，字段名/数值契约见本目录各文件。
//! 生效对象：策略侧 `targets` 与请求侧上下文（规格 §1、§2.1）。

use serde::{Deserialize, Serialize};

/// 生效对象（四个维度并列，字段名冻结）。
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    /// 用户 ID 列表。
    pub user_ids: Vec<String>,
    /// 角色 ID 列表。
    pub role_ids: Vec<String>,
    /// 部门 ID 列表。
    pub dept_ids: Vec<String>,
    /// 账号 ID 列表。
    pub account_ids: Vec<String>,
}

impl Targets {
    /// 空生效对象：不匹配任何请求（评估层据此 fail-closed）。
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// 四个维度全空 ⇒ 该策略没有任何生效对象。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.user_ids.is_empty()
            && self.role_ids.is_empty()
            && self.dept_ids.is_empty()
            && self.account_ids.is_empty()
    }
}

/// 请求侧的生效对象上下文（谁在访问）。
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct TargetContext {
    /// 用户 ID。
    pub user_id: Option<String>,
    /// 角色 ID 集合（一个用户可有多个角色）。
    pub role_ids: Vec<String>,
    /// 部门 ID 集合。
    pub dept_ids: Vec<String>,
    /// 账号 ID（登录账号标识）。
    pub account_id: Option<String>,
}

impl TargetContext {
    /// 构造最小上下文；其余维度可用字段直接赋值补齐。
    #[must_use]
    pub fn new(user_id: impl Into<String>) -> Self {
        Self {
            user_id: Some(user_id.into()),
            ..Self::default()
        }
    }

    /// 追加角色。
    #[must_use]
    pub fn with_role(mut self, role_id: impl Into<String>) -> Self {
        self.role_ids.push(role_id.into());
        self
    }

    /// 追加部门。
    #[must_use]
    pub fn with_dept(mut self, dept_id: impl Into<String>) -> Self {
        self.dept_ids.push(dept_id.into());
        self
    }

    /// 设置账号 ID。
    #[must_use]
    pub fn with_account(mut self, account_id: impl Into<String>) -> Self {
        self.account_id = Some(account_id.into());
        self
    }
}
