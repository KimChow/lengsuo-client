//! 从 JSON 文件加载节点列表。

use std::path::Path;

use super::{ConfigError, NodeConfig};

/// 从 JSON 文件加载节点列表：顶层数组，逐个校验。
pub fn load_nodes(path: &Path) -> Result<Vec<NodeConfig>, ConfigError> {
    let raw = std::fs::read_to_string(path)?;
    let nodes: Vec<NodeConfig> = serde_json::from_str(&raw)?;
    for node in &nodes {
        node.validate()?;
    }
    Ok(nodes)
}
