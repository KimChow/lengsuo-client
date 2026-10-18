//! `initialize`：协议版本协商、能力声明与参数/结果类型。

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;

use super::super::wire::shape;

/// `std::result::Result<T, crate::error::Error>` 简写。
type Result<T> = std::result::Result<T, Error>;

/// MCP stdio 客户端目前跟随的最新协议版本。
pub const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";

/// 本地支持的协议版本列表，按偏好从高到低。
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// `clientInfo` / `serverInfo`。`title` 为 2025-06-18 起的可选展示名。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Implementation {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub version: String,
}

/// 客户端能力声明。v0 一律为空（不声明 roots、sampling、elicitation），
/// 与「不处理服务端发起的请求」这条策略一致。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,
}

/// 服务端能力。字段全部可选：对端少写一个字段不应导致握手失败，未识别的
/// 扩展能力也不报错。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompts: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,
}

impl ServerCapabilities {
    /// 对端是否声明了 tools 面。
    #[must_use]
    pub fn has_tools(&self) -> bool {
        self.tools.is_some()
    }
}

/// `initialize` 请求参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitializeParams {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    #[serde(rename = "clientInfo")]
    pub client_info: Implementation,
}

/// `initialize` 响应结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion", default)]
    pub protocol_version: String,
    #[serde(default)]
    pub capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo", default)]
    pub server_info: Option<Implementation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

impl InitializeResult {
    /// 空结果（便于测试构造；正常路径由 [`Self::from_value_strict`] 产生）。
    #[must_use]
    pub fn empty() -> Self {
        Self {
            protocol_version: String::new(),
            capabilities: ServerCapabilities::default(),
            server_info: None,
            instructions: None,
        }
    }

    /// 从 `result` 值解码，缺失必需字段时返回带字段名的类型化错误
    /// （[`Error::InvalidInitializeResult`]），而不是 serde 的通用文本。
    ///
    /// # Errors
    /// [`Error::InvalidInitializeResult`]：`protocolVersion` / `serverInfo`
    /// 缺失或类型不对；[`Error::MalformedMessage`]：不是对象、或
    /// `capabilities` / `serverInfo` 形状不合法。
    pub fn from_value_strict(value: &Value) -> Result<Self> {
        let obj = value.as_object().ok_or_else(|| Error::MalformedMessage {
            reason: format!("initialize 结果不是 JSON 对象：{}", shape(value)),
        })?;
        let protocol_version = match obj.get("protocolVersion") {
            Some(Value::String(s)) => s.clone(),
            Some(_) => {
                return Err(Error::InvalidInitializeResult {
                    field: "protocolVersion",
                })
            }
            None => {
                return Err(Error::InvalidInitializeResult {
                    field: "protocolVersion",
                })
            }
        };
        let capabilities = match obj.get("capabilities") {
            None | Some(Value::Null) => ServerCapabilities::default(),
            Some(v) => serde_json::from_value(v.clone()).map_err(|e| Error::MalformedMessage {
                reason: format!("capabilities 不合法：{e}"),
            })?,
        };
        let server_info =
            match obj.get("serverInfo") {
                None | Some(Value::Null) => None,
                Some(v) => Some(serde_json::from_value(v.clone()).map_err(|e| {
                    Error::MalformedMessage {
                        reason: format!("serverInfo 不合法：{e}"),
                    }
                })?),
            };
        let server_info = server_info.ok_or(Error::InvalidInitializeResult {
            field: "serverInfo",
        })?;
        let instructions = obj
            .get("instructions")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(Self {
            protocol_version,
            capabilities,
            server_info: Some(server_info),
            instructions,
        })
    }

    /// 版本协商：对端返回的版本必须在本地支持列表内，否则
    /// [`Error::VersionMismatch`]（fail-closed，不降级继续跑）。
    ///
    /// # Errors
    /// [`Error::VersionMismatch`]。
    pub fn validate_against(&self, supported: &[String]) -> Result<()> {
        if supported.iter().any(|v| v == &self.protocol_version) {
            Ok(())
        } else {
            Err(Error::version_mismatch(
                self.protocol_version.clone(),
                supported.to_vec(),
            ))
        }
    }

    /// `serverInfo.name`（缺失时为空串）。
    #[must_use]
    pub fn server_name(&self) -> &str {
        self.server_info
            .as_ref()
            .map(|i| i.name.as_str())
            .unwrap_or("")
    }
}
