//! 通用请求面：任意方法请求、通知发送与 `ping`。

use serde_json::Value;

use crate::error::Error;

use super::McpClient;

impl McpClient {
    /// 发送任意方法请求（协议面之上的逃生口：扩展方法与测试夹具用）。
    ///
    /// `params` 为 `None` 时按规范省略该字段。id 由会话分配。
    ///
    /// # Errors
    /// 超时、poisoned、传输中断、帧损坏或对端 JSON-RPC error。
    pub async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, Error> {
        // 超时取会话默认值（由 ClientConfig::session_config 从 request_timeout 灌入），
        // 客户端不另存一份，避免两条路径上的超时配置分叉。
        self.session
            .request(method, params, Some(self.session.default_timeout()))
            .await
    }

    /// 发送通知（无 id、无响应）。
    ///
    /// # Errors
    /// 写侧失败或连接不可用。
    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), Error> {
        self.session.notify(method, params).await
    }

    /// `ping`：空 `params`，成功即 `Ok(())`。
    ///
    /// # Errors
    /// 同 [`Self::request`]。
    pub async fn ping(&self) -> Result<(), Error> {
        self.request("ping", None).await?;
        Ok(())
    }
}
