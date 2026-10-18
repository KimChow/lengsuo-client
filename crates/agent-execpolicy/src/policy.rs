//! Policy：三段规则集合（file/process/network）+ 加载与默认安全基线。

use serde::{Deserialize, Serialize};

use crate::types::{AccessKind, Decision, Matcher, Rule};

/// 一组规则。逐条匹配、首个命中生效；无命中 Ask（fail-closed）。
///
/// 规则文件形态（照 参考端 tsbx_rules.json）：顶层 `file` / `process` / `network`
/// 三段，每段是 `Rule` 数组；缺段视为空数组。
///
/// `Default` = [`Policy::security_baseline`]（安全基线即默认策略）；
/// 需要「零规则」的策略显式用 [`Policy::empty`]。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// 文件访问规则段。
    #[serde(default)]
    pub file: Vec<Rule>,
    /// 进程执行规则段。
    #[serde(default)]
    pub process: Vec<Rule>,
    /// 网络访问规则段。
    #[serde(default)]
    pub network: Vec<Rule>,
}

impl Default for Policy {
    fn default() -> Self {
        Self::security_baseline()
    }
}

impl Policy {
    /// 零规则策略：任何请求都 Ask。
    pub fn empty() -> Self {
        Self {
            file: Vec::new(),
            process: Vec::new(),
            network: Vec::new(),
        }
    }

    /// 取某类别对应的规则段。
    pub fn rules_for(&self, kind: AccessKind) -> &[Rule] {
        match kind {
            AccessKind::File => &self.file,
            AccessKind::Process => &self.process,
            AccessKind::Network => &self.network,
        }
    }

    /// 从 tsbx 形态 JSON 文本加载（未知字段报错，fail-closed，不静默忽略拼写错误）。
    pub fn from_json_str(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }

    /// 序列化为 JSON 文本（与 `from_json_str` 往返一致）。
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// 默认安全基线（可被自定义策略整体替换）。
    ///
    /// - Deny 全操作（含读取）：`.ssh/**`、`.gnupg/**`；
    /// - Allow 包管理器缓存目录（家目录相对路径前缀）；
    /// - 其余无规则 ⇒ Ask。
    pub fn security_baseline() -> Self {
        let deny = |pattern: &str, reason: &str| Rule {
            pattern: pattern.to_string(),
            matcher: Matcher::Glob,
            decision: Decision::Deny,
            reason: Some(reason.to_string()),
        };
        let allow_cache = |pattern: &str| Rule {
            pattern: pattern.to_string(),
            matcher: Matcher::Prefix,
            decision: Decision::Allow,
            reason: Some("package manager cache".to_string()),
        };
        let file = vec![
            deny(".ssh/**", "ssh keys are off-limits"),
            deny(".gnupg/**", "gnupg keys are off-limits"),
            allow_cache(".cargo/"),
            allow_cache(".npm/"),
            allow_cache(".rustup/"),
            allow_cache(".cache/pip/"),
            allow_cache(".cache/go-build/"),
            allow_cache(".m2/"),
            allow_cache(".gradle/"),
            allow_cache(".nuget/"),
        ];
        Self {
            file,
            process: Vec::new(),
            network: Vec::new(),
        }
    }
}
