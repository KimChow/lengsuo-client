//! 单个出口节点配置结构。

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{
    AuthConfig, Endpoint, NodeEncryptionSettings, NodeMuxSettings, NodeRealitySettings,
    NodeVisionSettings, NodeXelSettings, Protocol, TlsConfig,
};
use crate::forward_config::ForwardConfig;

/// 单个出口节点配置。
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub protocol: Protocol,
    pub endpoint: Endpoint,
    /// dry-run 握手目标：trojan 请求头必须携带目标地址，但 dry-run 不转发
    /// 业务载荷。缺省 `127.0.0.1:9`（discard）。对真实远端 dry-run trojan 时
    /// 应配置一个可拨通地址：trojan 没有认证成功的正向确认（参考 client.go
    /// 不读任何响应），服务端“认证拒绝”与“拨号失败”同样表现为关闭连接，
    /// 只有目标可拨通时“观察窗内未被关闭”才能作为认证完成的证据。
    #[serde(default)]
    pub probe_target: Option<Endpoint>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    pub auth: AuthConfig,
    /// shadowsocks / ss2022 的加密方式（如 `aes-128-gcm`、`2022-blake3-aes-128-gcm`）。
    /// 其他协议忽略。缺省由 crate 默认决定，但本卡要求显式给出以便校验。
    #[serde(default)]
    pub method: Option<String>,
    /// REALITY 客户端配置（**仅 vless**）：缺省即「不走 REALITY」，既有 JSON
    /// 配置行为完全不变。
    ///
    /// 给了但 `protocol` 不是 `vless` ⇒ 配置加载阶段**显式报错**
    /// （fail-closed，不静默忽略该配置段）。
    #[serde(default)]
    pub reality: Option<NodeRealitySettings>,
    /// VLESS **Vision 流量层**配置（**仅 vless**）：缺省即「不走流量层」，
    /// 既有 JSON 配置行为逐字节不变。
    ///
    /// 给了但 `protocol` 不是 `vless` ⇒ 配置加载阶段**显式报错**
    /// （fail-closed，不静默忽略该配置段）。
    ///
    /// 结构与校验见 [`crate::config_vision::NodeVisionSettings`]。
    #[serde(default)]
    pub vision: Option<NodeVisionSettings>,
    /// VLESS **记录层**（AEAD）配置（**仅 vless**）：缺省即「不走记录层」。
    ///
    /// 与 `vision` 是**两个独立开关**（参考的 `flow` 与 `encryption` 是两个不同
    /// 的特性）；给了但 `protocol` 不是 `vless` ⇒ 配置加载阶段**显式报错**。
    ///
    /// 结构与校验见 [`crate::config_vision::NodeEncryptionSettings`]。
    #[serde(default)]
    pub encryption: Option<NodeEncryptionSettings>,
    /// VLESS **XEL 记录层**配置（**仅 vless**）：缺省即「不走 XEL 记录层」，
    /// 既有 JSON 配置行为逐字节不变。
    ///
    /// 与 `encryption`（Vision 记录层）**不得同时给出**（二者都作用于 VLESS
    /// 记录层）：配置加载阶段**显式报错**（fail-closed）。
    ///
    /// 结构与校验见 [`crate::config_xel::NodeXelSettings`]。
    #[serde(default)]
    pub xel: Option<NodeXelSettings>,
    /// VLESS **Mux 承载**配置（**仅 vless**）：缺省即「不走 mux 承载」，
    /// 既有 JSON 配置行为逐字节不变。
    ///
    /// 结构与校验见 [`crate::config_mux::NodeMuxSettings`]。
    #[serde(default)]
    pub mux: Option<NodeMuxSettings>,
    /// 转发服务配置（监听地址 / 默认节点 / 路由规则 / 超时）。
    ///
    /// **缺省即无转发服务**：dry-run 行为与旧版完全一致（既有测试不退化）。
    /// 多个节点给出**不一致**的转发段 ⇒ 配置加载阶段显式报错（转发段全局唯一）。
    /// 形态详见 `crate::forward_config` 的模块注释。
    #[serde(default)]
    pub forward: Option<ForwardConfig>,
}

impl fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 凭据经 AuthConfig / NodeRealitySettings 的脱敏 Debug；其余字段无敏感内容。
        f.debug_struct("NodeConfig")
            .field("name", &self.name)
            .field("protocol", &self.protocol)
            .field("endpoint", &self.endpoint)
            .field("probe_target", &self.probe_target)
            .field("tls", &self.tls)
            .field("auth", &self.auth)
            .field("method", &self.method)
            .field("reality", &self.reality)
            .field("vision", &self.vision)
            .field("encryption", &self.encryption)
            .field("xel", &self.xel)
            .field("mux", &self.mux)
            .finish()
    }
}
