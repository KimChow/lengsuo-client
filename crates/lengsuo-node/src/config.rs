//! 出口节点配置：加载、校验与脱敏 Debug。
//!
//! 第一版范围：trojan 与 anytls 两个协议（互通证据最全），其余协议在本卡
//! 不注册（解析即拒绝），待后续卡接入。配置文件是 JSON 数组，每个元素一个
//! `NodeConfig`：
//!
//! ```json
//! [
//!   {
//!     "name": "node-a",
//!     "protocol": "trojan",
//!     "endpoint": { "host": "127.0.0.1", "port": 8443 },
//!     "tls": { "server_name": "example.com", "insecure": false },
//!     "auth": { "password": "secret" }
//!   }
//! ]
//! ```
//!
//! `auth` 与 TLS 私钥类字段不得进入日志：`NodeConfig` 的 Debug 输出对凭据
//! 脱敏（见下方手写 impl）， serde 反序列化保留原文但只存在内存中。

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// 配置错误：解析失败（serde）、结构非法（校验）或读取文件失败。
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("读取配置文件失败：{0}")]
    Io(#[from] std::io::Error),
    #[error("配置不是合法 JSON：{0}")]
    Parse(#[from] serde_json::Error),
    #[error("节点 {name} 配置非法：{reason}")]
    Invalid { name: String, reason: String },
}

/// 支持的出口协议。未注册的协议在解析层即拒绝，避免静默落到错误实现。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Trojan,
    AnyTls,
}

/// 目标端点。host 可为 IP 或域名；port 0 由校验拒绝。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

/// TLS 设置。`server_name` 缺省用 endpoint.host；`ca_pem` 是 PEM 文本信任锚
/// （测试/自签场景，对应 Xray `certificates[].usage=verify`），缺省为空即拒建
/// 连接——第一版不加载系统根，避免测试外环境静默信任公共 CA。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsConfig {
    pub server_name: Option<String>,
    pub ca_pem: Option<String>,
    /// 跳过证书校验（仅测试）。显式 opt-in，默认 false；与 `ca_pem` 互斥。
    #[serde(default)]
    pub insecure: bool,
}

/// 认证凭据。trojan（SHA224 哈希头部）与 anytls（SHA256 认证块）第一版都
/// 只有密码；两协议各自的摘要算法由协议 crate 负责，本结构只存原文。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthConfig {
    pub password: String,
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 密码全文不得进入任何日志/Debug 输出。
        f.write_str("AuthConfig { password: <redacted> }")
    }
}

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
    pub tls: Option<TlsConfig>,
    pub auth: AuthConfig,
}

impl fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 凭据经 AuthConfig 的脱敏 Debug；其余字段无敏感内容。
        f.debug_struct("NodeConfig")
            .field("name", &self.name)
            .field("protocol", &self.protocol)
            .field("endpoint", &self.endpoint)
            .field("tls", &self.tls)
            .field("auth", &self.auth)
            .finish()
    }
}

impl NodeConfig {
    /// 校验单个节点配置的完整性；失败带节点名与原因。
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |reason: &str| ConfigError::Invalid {
            name: self.name.clone(),
            reason: reason.to_string(),
        };
        if self.name.trim().is_empty() {
            return Err(invalid("name 不能为空"));
        }
        if self.endpoint.host.trim().is_empty() {
            return Err(invalid("endpoint.host 不能为空"));
        }
        if self.endpoint.port == 0 {
            return Err(invalid("endpoint.port 不能为 0"));
        }
        if self.auth.password.is_empty() {
            return Err(invalid("auth.password 不能为空"));
        }
        if let Some(probe) = &self.probe_target {
            if probe.host.trim().is_empty() {
                return Err(invalid("probe_target.host 不能为空"));
            }
            if probe.port == 0 {
                return Err(invalid("probe_target.port 不能为 0"));
            }
        }
        if let Some(tls) = &self.tls {
            if tls.insecure && tls.ca_pem.is_some() {
                return Err(invalid("tls.insecure 与 tls.ca_pem 不能同时设置"));
            }
            if let Some(name) = tls.server_name.as_deref() {
                if name.trim().is_empty() {
                    return Err(invalid("tls.server_name 不能为空"));
                }
            }
        }
        Ok(())
    }
}

/// 从 JSON 文件加载节点列表：顶层数组，逐个校验。
pub fn load_nodes(path: &Path) -> Result<Vec<NodeConfig>, ConfigError> {
    let raw = std::fs::read_to_string(path)?;
    let nodes: Vec<NodeConfig> = serde_json::from_str(&raw)?;
    for node in &nodes {
        node.validate()?;
    }
    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_json(protocol: &str) -> String {
        format!(
            r#"[{{
                "name": "n1",
                "protocol": "{protocol}",
                "endpoint": {{ "host": "127.0.0.1", "port": 8443 }},
                "tls": {{ "insecure": true }},
                "auth": {{ "password": "pw" }}
            }}]"#
        )
    }

    #[test]
    fn parse_trojan_and_anytls() {
        for protocol in ["trojan", "anytls"] {
            let nodes: Vec<NodeConfig> =
                serde_json::from_str(&node_json(protocol)).expect("合法配置应可解析");
            assert_eq!(nodes.len(), 1);
            nodes[0].validate().expect("合法配置应通过校验");
        }
    }

    #[test]
    fn unknown_protocol_rejected() {
        let raw = node_json("vmess");
        assert!(serde_json::from_str::<Vec<NodeConfig>>(&raw).is_err());
    }

    #[test]
    fn debug_redacts_password() {
        let nodes: Vec<NodeConfig> = serde_json::from_str(&node_json("trojan")).unwrap();
        let text = format!("{:?}", nodes[0]);
        assert!(!text.contains("pw"), "Debug 输出不得包含密码原文：{text}");
        assert!(text.contains("<redacted>"));
    }

    #[test]
    fn validation_rejects_empty_and_zero_port() {
        let mut nodes: Vec<NodeConfig> = serde_json::from_str(&node_json("trojan")).unwrap();
        nodes[0].endpoint.port = 0;
        assert!(nodes[0].validate().is_err());

        let mut nodes: Vec<NodeConfig> = serde_json::from_str(&node_json("anytls")).unwrap();
        nodes[0].auth.password = String::new();
        assert!(nodes[0].validate().is_err());
    }
}
