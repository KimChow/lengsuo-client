//! 协议面方法：`tools/list`（含 cursor 翻页）与 `tools/call`。

use serde_json::Value;

use crate::error::Error;
use crate::protocol::{ToolCallResult, ToolsListResult};

use super::McpClient;

impl McpClient {
    /// `tools/list`。
    ///
    /// # Errors
    /// 同 [`Self::request`]，另加结果反序列化失败 → [`Error::MalformedMessage`]。
    pub async fn list_tools(&self) -> Result<ToolsListResult, Error> {
        self.list_tools_with(None).await
    }

    /// 带 cursor 的 `tools/list`（翻页）。
    pub async fn list_tools_with(&self, cursor: Option<&str>) -> Result<ToolsListResult, Error> {
        let params = match cursor {
            Some(c) => serde_json::json!({ "cursor": c }),
            None => serde_json::json!({}),
        };
        let value = self.request("tools/list", Some(params)).await?;
        serde_json::from_value(value).map_err(|e| Error::MalformedMessage {
            reason: format!("tools/list 结果不合法：{e}"),
        })
    }

    /// `tools/call`。工具层面的失败走 `result.isError`（不是 JSON-RPC error），
    /// 因此以 [`ToolCallResult`] 返回，不映射为错误。
    ///
    /// # Errors
    /// 同 [`Self::request`]，另加结果反序列化失败 → [`Error::MalformedMessage`]。
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Option<Value>,
    ) -> Result<ToolCallResult, Error> {
        let params = serde_json::json!({
            "name": name,
            "arguments": arguments.unwrap_or_else(|| Value::Object(serde_json::Map::new())),
        });
        let value = self.request("tools/call", Some(params)).await?;
        serde_json::from_value(value).map_err(|e| Error::MalformedMessage {
            reason: format!("tools/call 结果不合法：{e}"),
        })
    }
}
