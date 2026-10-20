//! 转发服务的配置形态：监听地址、默认节点、路由规则与超时。
//!
//! 配置文件的两种形态（**都接受**）：
//!
//! 1. 旧形态（纯数组，向后兼容）：`[{...节点...}, ...]`。转发段可挂在**某一个**
//!    节点的 `forward` 字段上；多个节点给出**不一致**的转发段 ⇒ 配置加载阶段
//!    显式报错。
//! 2. 新形态（对象）：`{"nodes": [{...}], "forward": {...}}`。转发段写在顶层，
//!    不必挂在任何节点上。
//!
//! 两种形态都**不改变** dry-run 行为：没有转发段时 `load_nodes` 的结果与旧版
//! 完全一致。

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, NodeConfig};
use crate::route::{RouteError, RouteRule, RouteTable};

/// 缺省监听地址（仅回环）。参考的 freedom/代理监听同样默认不回公网。
pub const DEFAULT_LISTEN: &str = "127.0.0.1:1080";
/// 缺省超时（秒）。对齐参考 `policy.SessionDefault` 的
/// `ConnectionIdle = 300s`（`features/policy/policy.go`）。
pub const DEFAULT_TIMEOUT_SECS: u64 = 300;

fn default_listen() -> String {
    DEFAULT_LISTEN.to_owned()
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

/// 转发服务配置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardConfig {
    /// 本地监听地址（`host:port`）。端口 0 交给内核分配。
    #[serde(default = "default_listen")]
    pub listen: String,
    /// 默认节点名。缺省时**未命中任何规则的连接 fail-closed**（断开，不直连）。
    #[serde(default)]
    pub default_node: Option<String>,
    /// 路由规则（最具体优先；同 specificity 冲突 ⇒ 加载阶段报错）。
    #[serde(default)]
    pub rules: Vec<RouteRule>,
    /// 单次读写与单方向的空闲上限（秒）。
    #[serde(default = "default_timeout")]
    pub idle_timeout_secs: u64,
    /// 整条连接的生命周期上限（秒）。
    #[serde(default = "default_timeout")]
    pub session_timeout_secs: u64,
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            default_node: None,
            rules: Vec::new(),
            idle_timeout_secs: default_timeout(),
            session_timeout_secs: default_timeout(),
        }
    }
}

impl ForwardConfig {
    /// 空闲超时。
    #[must_use]
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }

    /// 整条连接的生命周期上限。
    #[must_use]
    pub fn session_timeout(&self) -> Duration {
        Duration::from_secs(self.session_timeout_secs)
    }

    /// 校验：监听地址非空、超时为正。
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen.trim().is_empty() {
            return Err(ConfigError::Forward("listen 不能为空".to_owned()));
        }
        if self.idle_timeout_secs == 0 {
            return Err(ConfigError::Forward(
                "idle_timeout_secs 必须大于零".to_owned(),
            ));
        }
        if self.session_timeout_secs == 0 {
            return Err(ConfigError::Forward(
                "session_timeout_secs 必须大于零".to_owned(),
            ));
        }
        Ok(())
    }

    /// 构造路由表并校验规则引用的节点都存在（**加载阶段**就报出来）。
    ///
    /// - 同键重复规则 ⇒ [`RouteError::Conflict`]；
    /// - 规则引用不存在的节点 ⇒ [`RouteError::UnknownNode`]；
    /// - 默认节点不存在 ⇒ [`RouteError::UnknownNode`]。
    pub fn route_table(&self, nodes: &[NodeConfig]) -> Result<RouteTable, ConfigError> {
        let names: BTreeSet<&str> = nodes.iter().map(|node| node.name.as_str()).collect();
        let table = RouteTable::new(self.rules.clone(), self.default_node.clone())?;
        for rule in table.rules() {
            if !names.contains(rule.node.as_str()) {
                return Err(RouteError::UnknownNode(rule.node.clone()).into());
            }
        }
        if let Some(default) = table.default_node() {
            if !names.contains(default) {
                return Err(RouteError::UnknownNode(default.to_owned()).into());
            }
        }
        Ok(table)
    }
}

/// 加载后的完整配置：节点列表 + 可选的转发段。
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub nodes: Vec<NodeConfig>,
    pub forward: Option<ForwardConfig>,
}

/// 配置文件的对象形态。
#[derive(Debug, Deserialize)]
struct ConfigFile {
    nodes: Vec<NodeConfig>,
    #[serde(default)]
    forward: Option<ForwardConfig>,
}

/// 加载配置（节点 + 转发段）。
///
/// 旧形态（数组）与新形态（对象）都接受；解析失败一律报错（fail-closed），
/// 绝不退化成「只有节点、没有转发段」的静默成功。
pub fn load_config(path: &Path) -> Result<LoadedConfig, ConfigError> {
    let raw = std::fs::read_to_string(path)?;
    // 先按对象形态试（对象形态的 JSON 以 `{` 开头，可先判第一个非空白字符）。
    let trimmed = raw.trim_start();
    if trimmed.starts_with('{') {
        let file: ConfigFile = serde_json::from_str(&raw)?;
        for node in &file.nodes {
            node.validate()?;
        }
        if let Some(forward) = &file.forward {
            forward.validate()?;
            // 引用校验放在路由表构造里，这里先确认节点名非空。
            forward.route_table(&file.nodes)?;
        }
        return Ok(LoadedConfig {
            nodes: file.nodes,
            forward: file.forward,
        });
    }
    let nodes: Vec<NodeConfig> = serde_json::from_str(&raw)?;
    for node in &nodes {
        node.validate()?;
    }
    let forward = collect_forward(&nodes)?;
    Ok(LoadedConfig { nodes, forward })
}

/// 从节点数组里收集转发段：多个节点给出**不一致**的转发段 ⇒ 显式报错。
fn collect_forward(nodes: &[NodeConfig]) -> Result<Option<ForwardConfig>, ConfigError> {
    let mut found: Option<ForwardConfig> = None;
    for node in nodes {
        let Some(forward) = &node.forward else {
            continue;
        };
        forward.validate()?;
        match &found {
            None => found = Some(forward.clone()),
            Some(existing) if existing == forward => {}
            Some(_) => {
                return Err(ConfigError::Forward(format!(
                    "节点 {} 的 forward 段与其他节点不一致（转发段只能有一个）",
                    node.name
                )))
            }
        }
    }
    Ok(found)
}
