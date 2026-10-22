//! 配置错误类型。

use crate::route::RouteError;

/// 配置错误：解析失败（serde）、结构非法（校验）或读取文件失败。
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("读取配置文件失败：{0}")]
    Io(#[from] std::io::Error),
    #[error("配置不是合法 JSON：{0}")]
    Parse(#[from] serde_json::Error),
    #[error("节点 {name} 配置非法：{reason}")]
    Invalid { name: String, reason: String },
    #[error("转发配置非法：{0}")]
    Forward(String),
    #[error("路由配置非法：{0}")]
    Route(#[from] RouteError),
}
