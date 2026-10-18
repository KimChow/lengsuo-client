//! 工具面：工具定义、列表分页与调用结果。

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
