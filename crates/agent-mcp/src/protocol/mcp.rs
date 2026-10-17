//! MCP 协议面类型：initialize / tools / ping / progress。
//!
//! 只建模 v0 客户端实际用到的字段；未识别的扩展字段由 serde 忽略（不因对端
//! 多写字段而失败），缺失的必需字段则返回带字段名的类型化错误。

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;

/// `std::result::Result<T, crate::error::Error>` 简写。
type Result<T> = std::result::Result<T, Error>;

use super::wire::shape;

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

/// 工具定义（`tools/list` 条目）。`input_schema` 是 JSON Schema 对象，原样保留。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema", default)]
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
}

/// `tools/list` 结果。`nextCursor` 为 `null` 或空串时按「没有下一页」处理。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolsListResult {
    #[serde(default)]
    pub tools: Vec<Tool>,
    #[serde(
        rename = "nextCursor",
        default,
        deserialize_with = "deserialize_cursor",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
}

/// `null` 与缺失等价，都归一为 `None`（不同实现写法不一致）。
fn deserialize_cursor<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(<Option<String>>::deserialize(deserializer)?.filter(|s| !s.is_empty()))
}

impl ToolsListResult {
    /// 是否有下一页。
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }
}

/// `tools/call` 请求参数。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// 内容块。v0 建模 `text` / `image` / `audio`；其余类型（`resource_link`、
/// `resource` 及未来扩展）归为 [`ContentBlock::Unknown`]，不 panic、不丢帧。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotations: Option<Value>,
    },
    Image {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotations: Option<Value>,
    },
    Audio {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        annotations: Option<Value>,
    },
    #[serde(other)]
    Unknown,
}

impl ContentBlock {
    /// 文本内容（非文本块返回 `None`）。
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        match self {
            Self::Text { text, .. } => Some(text),
            _ => None,
        }
    }
}

/// `tools/call` 结果。`is_error == true` 是**工具层面的失败**（原因在
/// `content` 里），不是 JSON-RPC 错误，因此不映射为 [`Error::JsonRpc`]。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCallResult {
    #[serde(default, deserialize_with = "deserialize_blocks")]
    pub content: Vec<ContentBlock>,
    #[serde(rename = "isError", default)]
    pub is_error: bool,
    #[serde(
        rename = "structuredContent",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub structured_content: Option<Value>,
}

fn deserialize_blocks<'de, D>(deserializer: D) -> std::result::Result<Vec<ContentBlock>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(<Option<Vec<ContentBlock>>>::deserialize(deserializer)?.unwrap_or_default())
}

impl ToolCallResult {
    /// 拼接所有文本块（工具失败时这就是错误说明）。
    #[must_use]
    pub fn combined_text(&self) -> String {
        self.content
            .iter()
            .filter_map(ContentBlock::text)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// `notifications/progress` 参数（v0 只解析字段，不做进度状态机）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgressParams {
    #[serde(rename = "progressToken")]
    pub progress_token: Value,
    pub progress: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn initialize_result_strict_requires_version_and_server_info() {
        let e = InitializeResult::from_value_strict(&json!({"capabilities": {}})).unwrap_err();
        assert!(matches!(
            e,
            Error::InvalidInitializeResult {
                field: "protocolVersion"
            }
        ));
        let e2 = InitializeResult::from_value_strict(&json!({"protocolVersion": "2025-06-18"}))
            .unwrap_err();
        assert!(matches!(
            e2,
            Error::InvalidInitializeResult {
                field: "serverInfo"
            }
        ));
        let e3 = InitializeResult::from_value_strict(&json!("nope")).unwrap_err();
        assert!(matches!(e3, Error::MalformedMessage { .. }));
        let e4 = InitializeResult::from_value_strict(&json!({
            "protocolVersion": 1, "serverInfo": {"name":"s","version":"1"}
        }))
        .unwrap_err();
        assert!(matches!(
            e4,
            Error::InvalidInitializeResult {
                field: "protocolVersion"
            }
        ));
    }

    #[test]
    fn initialize_result_tolerates_missing_capabilities_and_unknown_fields() {
        let r = InitializeResult::from_value_strict(&json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "fixture", "version": "0", "extra": 1},
            "futureField": {"a": 1}
        }))
        .unwrap();
        assert_eq!(r.protocol_version, "2024-11-05");
        assert_eq!(r.server_name(), "fixture");
        assert!(!r.capabilities.has_tools());
        assert!(r.instructions.is_none());
    }

    #[test]
    fn version_negation_rejects_unsupported() {
        let r = InitializeResult {
            protocol_version: "1999-01-01".to_string(),
            capabilities: ServerCapabilities::default(),
            server_info: Some(Implementation {
                name: "s".into(),
                title: None,
                version: "1".into(),
            }),
            instructions: None,
        };
        let supported = SUPPORTED_PROTOCOL_VERSIONS
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>();
        let e = r.validate_against(&supported).unwrap_err();
        assert!(matches!(e, Error::VersionMismatch(_)), "{e}");
        assert!(r.validate_against(&["1999-01-01".to_string()]).is_ok());
    }

    #[test]
    fn tools_list_cursor_null_and_empty_are_no_next_page() {
        for raw in [
            json!({"tools": [], "nextCursor": Value::Null}),
            json!({"tools": [], "nextCursor": ""}),
            json!({"tools": []}),
        ] {
            let r: ToolsListResult = serde_json::from_value(raw).unwrap();
            assert!(!r.has_more());
        }
        let r: ToolsListResult =
            serde_json::from_value(json!({"tools": [{"name": "t"}], "nextCursor": "c1"})).unwrap();
        assert!(r.has_more());
        assert_eq!(r.tools[0].name, "t");
        assert_eq!(r.tools[0].input_schema, Value::Null);
    }

    #[test]
    fn tool_call_result_handles_missing_and_unknown_content() {
        let r: ToolCallResult = serde_json::from_value(json!({})).unwrap();
        assert!(r.content.is_empty());
        assert!(!r.is_error);
        assert_eq!(r.combined_text(), "");
        let r2: ToolCallResult = serde_json::from_value(json!({
            "content": [
                {"type": "text", "text": "a"},
                {"type": "resource_link", "name": "x", "uri": "u", "mimeType": "text/plain"},
                {"type": "text", "text": "b"}
            ],
            "isError": true
        }))
        .unwrap();
        assert!(r2.is_error);
        assert_eq!(r2.content.len(), 3);
        assert!(matches!(r2.content[1], ContentBlock::Unknown));
        assert_eq!(r2.combined_text(), "a\nb");
    }

    #[test]
    fn initialize_params_encode_camel_case() {
        let p = InitializeParams {
            protocol_version: LATEST_PROTOCOL_VERSION.to_string(),
            capabilities: ClientCapabilities::default(),
            client_info: Implementation {
                name: "c".into(),
                title: Some("Client".into()),
                version: "1".into(),
            },
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains("\"protocolVersion\":\"2025-06-18\""), "{s}");
        assert!(
            s.contains("\"clientInfo\":{\"name\":\"c\",\"title\":\"Client\",\"version\":\"1\"}"),
            "{s}"
        );
        // 默认能力为空时仍写出 capabilities（规范必需字段）。
        assert!(s.contains("\"capabilities\":{}"), "{s}");
    }

    #[test]
    fn progress_params_roundtrip() {
        let p: ProgressParams = serde_json::from_value(json!({
            "progressToken": "t1", "progress": 1.0, "total": 4.0, "message": "half"
        }))
        .unwrap();
        assert_eq!(p.progress, 1.0);
        assert_eq!(p.message.as_deref(), Some("half"));
        let minimal: ProgressParams =
            serde_json::from_value(json!({"progressToken": 3, "progress": 2.0})).unwrap();
        assert!(minimal.total.is_none() && minimal.message.is_none());
    }
}
