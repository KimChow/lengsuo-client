//! 判定层的基础数据类型：决策、匹配器、规则、请求与判定结果。

use serde::{Deserialize, Serialize};

/// 一条策略的判定结果（三值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// 放行。
    Allow,
    /// 拒绝。
    Deny,
    /// 需人审（fail-closed 倾向：拿不准就问）。
    Ask,
}

/// 匹配模式类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Matcher {
    /// glob：`*`/`?` 段内匹配，独立段 `**` 跨段匹配（见 `matcher` 模块）。
    Glob,
    /// 前缀：目标串以 pattern 开头即命中（字面比较，无通配）。
    Prefix,
}

/// 一条规则 = 匹配模式 + 决策 + 可选理由。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// 匹配模式串（glob 或前缀，按 `matcher` 解释）。
    pub pattern: String,
    /// 匹配器类型；JSON 里字段名为 `match`。
    #[serde(rename = "match")]
    pub matcher: Matcher,
    /// 命中后的决策。
    pub decision: Decision,
    /// 给人看的理由；缺省时自动生成。
    #[serde(default)]
    pub reason: Option<String>,
}

impl Rule {
    /// 该规则是否命中目标串。
    pub fn matches(&self, target: &str) -> bool {
        crate::matcher::matches(self.matcher, &self.pattern, target)
    }

    /// 生效理由：自报优先，否则按模式与决策生成。
    fn effective_reason(&self) -> String {
        self.reason.clone().unwrap_or_else(|| {
            format!(
                "rule {} {:?} -> {:?}",
                self.pattern, self.matcher, self.decision
            )
        })
    }
}

/// 访问类别：与规则文件的三段（file/process/network）一一对应。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessKind {
    /// 文件访问。
    File,
    /// 进程/命令执行。
    Process,
    /// 网络访问。
    Network,
}

/// 一次工具调用的访问请求。
///
/// `target` 约定为归一化后的字符串（如相对家目录的 `.ssh/id_rsa`、
/// 域名 `example.com`、命令串 `rm -rf /tmp/x`）；归一化属执行层职责。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRequest {
    /// 访问类别。
    pub kind: AccessKind,
    /// 访问目标。
    pub target: String,
}

/// `assess` 的输出：决策 + 命中规则 + 理由。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// 生效决策。
    pub decision: Decision,
    /// 命中的规则（首个命中）；无命中为 `None`。
    pub matched_rule: Option<Rule>,
    /// 决策理由（自报或自动生成，恒非空）。
    pub reason: String,
}

impl Assessment {
    /// 由命中规则构造（Allow/Deny）。
    pub(crate) fn matched(rule: &Rule) -> Self {
        Self {
            decision: rule.decision,
            matched_rule: Some(rule.clone()),
            reason: rule.effective_reason(),
        }
    }

    /// 无命中时的 fail-closed 默认（Ask）。
    pub(crate) fn default_ask() -> Self {
        Self {
            decision: Decision::Ask,
            matched_rule: None,
            reason: "no rule matched; fail-closed default Ask".to_string(),
        }
    }
}
