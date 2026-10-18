//! 已安装技能的限制元数据（对照 参考端 PC09 §2.1：常驻只留元数据，正文按需加载）。
//!
//! 本模块只解析并表达「限制」，不做授权：一切判定以宿主传入的已授权工具集为
//! 上界，技能自报的内容永远不可能扩大宿主授权（AGENTS §6「工具权限由运行时强制
//! 检查，模型、网页、文档及工具结果不能扩大授权」）。
//!
//! front-matter 仍是 YAML 简式 `key: value`（不引入 YAML 依赖）。支持范围明确：
//! - `allowed-tools`：逗号分隔裸工具名，或 `[A, B]` 流式序列；值可带成对引号。
//!   工具参数级限定（如 `Bash(git add:*)`）、`A B` 空格分隔、`A # 注释`、方括号
//!   不配对等写法**不在支持范围**，按 fail-closed 降级为「不授权任何工具」。
//! - `disable-model-invocation` / `user-invocable` / `disabled`：只认字面
//!   `true`/`false`（区分大小写）；其它值按最保守方向处理并记入 `fail_closed_fields`。
//! - 未识别的 key 一律忽略（沿用既有语义），既不构成声明也不触发降级。

use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// 加载请求的来源：用户显式触发，或模型自助调用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationSource {
    /// 用户在技能菜单/命令里显式触发。
    User,
    /// 模型（宿主代理）自行决定调用。
    Model,
}

/// 一个技能的限制元数据（不含正文）。
///
/// 默认值 = 未声明任何限制：两个来源都可调用、不额外收窄工具、未禁用。
/// 「未声明」与「声明为空集」区别开（`declares_tools`），避免把未声明误当成
/// 「技能不允许任何工具」，也避免把声明为空误当成「不限制」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillPolicy {
    /// 是否显式声明了 `allowed-tools`（含声明为空值）。
    pub declares_tools: bool,
    /// 声明的裸工具名，去重升序；解析失败时为空（配合 `fail_closed_fields`）。
    pub declared_tools: Vec<String>,
    /// `disable-model-invocation: true` ⇒ 只允许用户显式触发。
    pub disable_model_invocation: bool,
    /// `user-invocable: false` ⇒ 不允许从用户菜单显式触发。
    pub user_invocable: bool,
    /// `disabled: true` ⇒ 技能自带禁用标记（不可见且不可加载）。
    pub disabled: bool,
    /// 无法可靠解析、已按最保守方向降级的字段名（升序）；空 ⇒ 全部可靠解析。
    pub fail_closed_fields: Vec<String>,
}

impl Default for SkillPolicy {
    fn default() -> Self {
        Self {
            declares_tools: false,
            declared_tools: Vec::new(),
            disable_model_invocation: false,
            user_invocable: true,
            disabled: false,
            fail_closed_fields: Vec::new(),
        }
    }
}

/// 限制字段名（同时用作 `fail_closed_fields` 的取值）。
const FIELD_ALLOWED_TOOLS: &str = "allowed-tools";
const FIELD_DISABLE_MODEL_INVOCATION: &str = "disable-model-invocation";
const FIELD_USER_INVOCABLE: &str = "user-invocable";
const FIELD_DISABLED: &str = "disabled";

impl SkillPolicy {
    /// 该来源是否允许调用本技能（只看调用来源门；禁用判定属 catalog）。
    pub fn allows(&self, source: InvocationSource) -> bool {
        match source {
            InvocationSource::Model => !self.disable_model_invocation,
            InvocationSource::User => self.user_invocable,
        }
    }

    /// 与宿主已授权工具集求交集，得到生效工具集（升序）。
    ///
    /// 结果永远是 `host` 的子集：技能只能收窄、不能扩大。未声明 `allowed-tools`
    /// ⇒ 不额外收窄，直接返回宿主授权；声明了（含解析失败降级）⇒ 取交集，
    /// 因此解析失败或声明为空时结果必为空集。
    pub fn effective_tools(&self, host: &BTreeSet<String>) -> Vec<String> {
        if !self.declares_tools {
            return host.iter().cloned().collect();
        }
        self.declared_tools
            .iter()
            .filter(|tool| host.contains(tool.as_str()))
            .cloned()
            .collect()
    }

    /// 从 front-matter 字段表提取限制元数据。
    pub(crate) fn from_fields(fields: &BTreeMap<String, String>) -> Self {
        let mut out = SkillPolicy::default();
        let mut degraded = BTreeSet::new();

        if let Some(value) = fields.get(FIELD_ALLOWED_TOOLS) {
            out.declares_tools = true;
            match parse_tool_list(value) {
                Some(tools) => out.declared_tools = tools,
                None => {
                    // 不可靠解析 ⇒ 降级为空声明：交集必为空，绝不视为不限制工具。
                    out.declared_tools = Vec::new();
                    degraded.insert(FIELD_ALLOWED_TOOLS);
                }
            }
        }

        // 布尔项：未出现即默认（不算降级）；可靠值直接采用；
        // 出现了但不可靠 ⇒ 取最保守方向并记录降级。
        out.disable_model_invocation =
            conservative_bool(fields, FIELD_DISABLE_MODEL_INVOCATION, false, &mut degraded);
        out.user_invocable = conservative_bool(fields, FIELD_USER_INVOCABLE, true, &mut degraded);
        out.disabled = conservative_bool(fields, FIELD_DISABLED, false, &mut degraded);

        out.fail_closed_fields = degraded.into_iter().map(String::from).collect();
        out
    }
}

/// 取布尔限制字段：`default` 为未声明时的默认值，不可靠值一律落到保守方向。
///
/// 保守方向 = 「更严」的一侧：`true` 默认值（如 `user-invocable`）不可靠时取
/// `false`，`false` 默认值（如 `disabled`）不可靠时取 `true`。
fn conservative_bool<'a>(
    fields: &BTreeMap<String, String>,
    key: &'a str,
    default: bool,
    degraded: &mut BTreeSet<&'a str>,
) -> bool {
    let Some(value) = fields.get(key) else {
        return default;
    };
    match parse_bool(Some(value)) {
        Some(parsed) => parsed,
        None => {
            degraded.insert(key);
            !default
        }
    }
}

/// 解析布尔值：只认字面 `true`/`false`（引号已由 front-matter 层去除）。
fn parse_bool(value: Option<&String>) -> Option<bool> {
    match value?.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// 解析 `allowed-tools` 值；`None` 表示无法可靠解析（调用方须 fail-closed）。
///
/// 空值 ⇒ `Some(vec![])`（显式声明不授权任何工具），与解析失败在语义上区分开。
fn parse_tool_list(value: &str) -> Option<Vec<String>> {
    let trimmed = value.trim();
    let body = if let Some(inner) = trimmed.strip_prefix('[') {
        // 流式序列必须方括号配对，否则是不可靠写法。
        inner.strip_suffix(']')?
    } else {
        if trimmed.contains(']') {
            return None;
        }
        trimmed
    };
    let mut out = BTreeSet::new();
    for item in body.split(',') {
        let item = item.trim();
        if item.is_empty() {
            // 尾随逗号/空项：少一个工具名不会扩大授权，跳过即可。
            continue;
        }
        // 只接受裸工具名：括号（参数级限定）、`#`、冒号、斜杠、空白等一律拒绝。
        if !item
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return None;
        }
        out.insert(item.to_string());
    }
    Some(out.into_iter().collect())
}
