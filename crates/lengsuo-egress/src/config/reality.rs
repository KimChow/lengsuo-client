//! REALITY 客户端配置段。

use std::fmt;

use serde::{Deserialize, Serialize};

use super::redacted;

/// REALITY 客户端配置（node 侧形态）。
///
/// 字段语义与参考 `realitySettings` 的客户端子集一致：
/// `server_name`（SNI）/ `public_key`（base64 raw-url）/ `short_id`（十六进制）/
/// `fingerprint`（uTLS 指纹名）/ `password`（`public_key` 的别名，非空即覆盖它）。
///
/// **本结构不做形态校验**：base64 解码、hex 解码、指纹查表全部由协议 crate 的
/// `RealityConfig::from_settings` 负责（fail-closed），这里只做「反序列化 +
/// 脱敏 Debug + 协议范围校验」，避免在 node 侧复制一份实现。
///
/// 凭据（`public_key` / `short_id` / `password`）不进 Debug 输出。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRealitySettings {
    /// SNI。缺省取 `tls.server_name`，再缺省取 `endpoint.host`（见
    /// `outbound_vless_reality::server_name`）。
    #[serde(default)]
    pub server_name: Option<String>,
    /// 服务端 REALITY 公钥（base64 raw-url，解码后须恰好 32 字节）。
    #[serde(default)]
    pub public_key: String,
    /// 短 ID（十六进制文本，最多 16 个字符 = 8 字节）。
    #[serde(default)]
    pub short_id: String,
    /// uTLS 指纹名。缺省由协议 crate 归一为 chrome。
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// `password`：参考里非空即覆盖 `public_key`。
    #[serde(default)]
    pub password: Option<String>,
}

impl fmt::Debug for NodeRealitySettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 凭据全文不得进入任何日志/Debug 输出（与 AuthConfig 同惯例）。
        f.debug_struct("NodeRealitySettings")
            .field("server_name", &self.server_name)
            .field("public_key", &redacted(&self.public_key))
            .field("short_id", &redacted(&self.short_id))
            .field("fingerprint", &self.fingerprint)
            .field(
                "password",
                &redacted(self.password.as_deref().unwrap_or("")),
            )
            .finish()
    }
}
