//! 出口节点配置：加载、校验与脱敏 Debug。
//!
//! 本卡范围：八种出口协议全部注册（trojan / anytls / vless / vmess /
//! shadowsocks / ss2022 / hysteria / wireguard）。协议语义一律复用本仓对应
//! crate，本模块只做「配置 → 校验 → 交给 outbound」。
//!
//! 配置文件是 JSON 数组，每个元素一个 `NodeConfig`：
//!
//! ```json
//! [
//!   {
//!     "name": "node-a",
//!     "protocol": "trojan",
//!     "endpoint": { "host": "127.0.0.1", "port": 8443 },
//!     "tls": { "server_name": "example.com", "ca_pem": "..." },
//!     "auth": { "password": "secret" }
//!   }
//! ]
//! ```
//!
//! 所有凭据字段（`auth.*`、`secret_key`、`public_key`、`private_key`）都不得
//! 进入日志：`NodeConfig` 的 Debug 输出对凭据脱敏（见下方手写 impl），
//! serde 反序列化保留原文但只存在内存中。校验失败一律 fail-closed，报错只带
//! 节点名与字段名/长度，不带口令原文或其摘要。

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::forward::ForwardConfig;
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

/// 支持的出口协议。八种全部注册；未注册的协议在解析层即拒绝，
/// 避免静默落到错误实现。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Trojan,
    /// 线上名 `anytls`；枚举名避开 `Tls` 后缀歧义（对齐已有实现）。
    #[serde(rename = "anytls")]
    AnyTls,
    Vless,
    Vmess,
    Shadowsocks,
    Ss2022,
    Hysteria,
    Wireguard,
}

impl Protocol {
    /// 该协议是否要求 `tls` 配置块（缺省且必需时校验失败）。
    ///
    /// - trojan / anytls / vless / vmess / hysteria：参考实现的出站都跑在 TLS
    ///   之上（hysteria 是 QUIC/TLS1.3）；本卡不提供「明文降级」路径。
    /// - shadowsocks / ss2022 / wireguard：协议自带加密或握手，不经 TLS。
    #[must_use]
    pub const fn requires_tls(self) -> bool {
        matches!(
            self,
            Protocol::Trojan
                | Protocol::AnyTls
                | Protocol::Vless
                | Protocol::Vmess
                | Protocol::Hysteria
        )
    }

    /// 该协议是否使用 `auth.password` 之外的密钥材料。
    #[must_use]
    pub const fn uses_secret_fields(self) -> bool {
        matches!(
            self,
            Protocol::Shadowsocks | Protocol::Ss2022 | Protocol::Wireguard
        )
    }
}

/// 目标端点。host 可为 IP 或域名；port 0 由校验拒绝。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

/// TLS 设置。`server_name` 缺省用 endpoint.host；`ca_pem` 是 PEM 文本信任锚
/// （测试/自签场景，对应 Xray `certificates[].usage=verify`），缺省为空即拒建
/// 连接——本卡不加载系统根，避免测试外环境静默信任公共 CA。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsConfig {
    pub server_name: Option<String>,
    pub ca_pem: Option<String>,
    /// 跳过证书校验（仅测试）。显式 opt-in，默认 false；与 `ca_pem` 互斥。
    #[serde(default)]
    pub insecure: bool,
}

/// 认证凭据。trojan（SHA224 哈希头部）、anytls（SHA256 认证块）、vless（UUID）、
/// vmess（UUID）、hysteria（auth 串）都只有密码；shadowsocks / ss2022 用
/// `secret_key`（口令或 base64 PSK），wireguard 用一对静态密钥。
/// 摘要算法由协议 crate 负责，本结构只存原文。
///
/// 字段全部脱敏；`Serialize` 仍可原样写回（用于转储配置），`Deserialize`
/// 只接受 JSON 文本。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthConfig {
    /// 口令/密码/UUID/auth 串。trojan/anytls/vless/vmess/hysteria 使用。
    #[serde(default)]
    pub password: String,
    /// shadowsocks / ss2022 的口令或 base64 PSK。避开口令字段命名混淆。
    #[serde(default)]
    pub secret_key: Option<String>,
    /// WireGuard 本端静态私钥（base64，32 字节）。
    #[serde(default)]
    pub private_key: Option<String>,
    /// WireGuard 对端静态公钥（base64，32 字节）。
    #[serde(default)]
    pub public_key: Option<String>,
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 凭据全文不得进入任何日志/Debug 输出；只报告「是否给出」。
        f.debug_struct("AuthConfig")
            .field("password", &redacted(&self.password))
            .field(
                "secret_key",
                &redacted(self.secret_key.as_deref().unwrap_or("")),
            )
            .field(
                "private_key",
                &redacted(self.private_key.as_deref().unwrap_or("")),
            )
            .field(
                "public_key",
                &redacted(self.public_key.as_deref().unwrap_or("")),
            )
            .finish()
    }
}

/// 脱敏占位：非空即输出 `<redacted>`，空串输出 `<empty>`（长度也不泄漏）。
fn redacted(value: &str) -> &'static str {
    if value.is_empty() {
        "<empty>"
    } else {
        "<redacted>"
    }
}

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
    /// 转发服务配置（监听地址 / 默认节点 / 路由规则 / 超时）。
    ///
    /// **缺省即无转发服务**：dry-run 行为与旧版完全一致（既有测试不退化）。
    /// 多个节点给出**不一致**的转发段 ⇒ 配置加载阶段显式报错（转发段全局唯一）。
    /// 形态详见 `crate::forward::config` 的模块注释。
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
            .finish()
    }
}

impl NodeConfig {
    /// 校验单个节点配置的完整性；失败带节点名与原因（不含凭据原文）。
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
        self.validate_reality(&invalid)?;
        self.validate_credentials(&invalid)?;
        Ok(())
    }

    /// REALITY 配置段的协议范围校验（fail-closed）。
    ///
    /// 只判「该段能否出现在这个协议上」：**形态**校验（base64 / hex / 指纹）
    /// 交给协议 crate 的 `RealityConfig::from_settings`，避免在 node 侧复制实现。
    ///
    /// - `protocol != vless` 却带 `reality` ⇒ 显式报错（不静默忽略）。
    /// - `protocol == vless` 且带 `reality` ⇒ 公钥与口令**至少给一个**
    ///   （两者都空时协议 crate 会 fail-closed，这里提前给出更贴近配置的报错）。
    fn validate_reality(&self, invalid: &impl Fn(&str) -> ConfigError) -> Result<(), ConfigError> {
        let Some(reality) = &self.reality else {
            return Ok(());
        };
        if self.protocol != Protocol::Vless {
            return Err(invalid("reality 配置段只允许用于 vless 协议"));
        }
        if reality.public_key.trim().is_empty()
            && reality
                .password
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(invalid("reality.public_key 与 reality.password 至少给一个"));
        }
        if let Some(name) = reality.server_name.as_deref() {
            if name.trim().is_empty() {
                return Err(invalid("reality.server_name 不能为空"));
            }
        }
        Ok(())
    }

    /// 按协议的凭据要求逐项校验（fail-closed，报错不含凭据原文）。
    fn validate_credentials(
        &self,
        invalid: &impl Fn(&str) -> ConfigError,
    ) -> Result<(), ConfigError> {
        // 需要口令的协议：password 非空。
        if !self.protocol.uses_secret_fields() && self.auth.password.is_empty() {
            return Err(invalid("auth.password 不能为空"));
        }
        match self.protocol {
            Protocol::Trojan | Protocol::AnyTls | Protocol::Hysteria => {}
            Protocol::Vless | Protocol::Vmess => {
                // 参考的 ID 是 16 字节 UUID；这里只校验形态，具体解析在 outbound。
                if !is_uuid(self.auth.password.trim()) {
                    return Err(invalid("auth.password 必须是 16 字节 UUID 文本"));
                }
            }
            Protocol::Shadowsocks | Protocol::Ss2022 => {
                if self
                    .auth
                    .secret_key
                    .as_deref()
                    .is_none_or(|key| key.is_empty())
                {
                    return Err(invalid("auth.secret_key 不能为空"));
                }
                if self.method.as_deref().is_none_or(|m| m.trim().is_empty()) {
                    return Err(invalid("method 不能为空（shadowsocks/ss2022 需要）"));
                }
            }
            Protocol::Wireguard => {
                if self
                    .auth
                    .private_key
                    .as_deref()
                    .is_none_or(|k| k.trim().is_empty())
                {
                    return Err(invalid("auth.private_key 不能为空"));
                }
                if self
                    .auth
                    .public_key
                    .as_deref()
                    .is_none_or(|k| k.trim().is_empty())
                {
                    return Err(invalid("auth.public_key 不能为空"));
                }
            }
        }
        Ok(())
    }
}

/// UUID 文本形态检查：`8-4-4-4-12` 十六进制，大小写不敏感。
/// 只做形态检查，不做版本位判断（由协议 crate 的 ID 派生决定）。
fn is_uuid(text: &str) -> bool {
    let mut groups = text.split('-');
    let Some(shape) = [8, 4, 4, 4, 12]
        .iter()
        .map(|_| groups.next())
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    if groups.next().is_some() {
        return false;
    }
    shape
        .iter()
        .zip([8, 4, 4, 4, 12])
        .all(|(group, want)| group.len() == want && group.bytes().all(|b| b.is_ascii_hexdigit()))
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
    /// 测试专用：线上小写名（与 serde 重命名保持一致）。
    impl Protocol {
        /// 线上小写名（测试与诊断用，与 serde 重命名保持一致）。
        #[must_use]
        pub fn to_string_value(self) -> &'static str {
            match self {
                Protocol::Trojan => "trojan",
                Protocol::AnyTls => "anytls",
                Protocol::Vless => "vless",
                Protocol::Vmess => "vmess",
                Protocol::Shadowsocks => "shadowsocks",
                Protocol::Ss2022 => "ss2022",
                Protocol::Hysteria => "hysteria",
                Protocol::Wireguard => "wireguard",
            }
        }
    }
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
    fn parse_all_eight_protocols() {
        for protocol in [
            "trojan",
            "anytls",
            "vless",
            "vmess",
            "shadowsocks",
            "ss2022",
            "hysteria",
            "wireguard",
        ] {
            let nodes: Vec<NodeConfig> =
                serde_json::from_str(&node_json(protocol)).unwrap_or_else(|e| {
                    panic!("{protocol} 应可解析：{e}");
                });
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].protocol.to_string_value(), protocol);
        }
    }

    #[test]
    fn unknown_protocol_rejected() {
        let raw = node_json("trojan-go");
        assert!(serde_json::from_str::<Vec<NodeConfig>>(&raw).is_err());
    }

    #[test]
    fn debug_redacts_every_credential() {
        let raw = r#"[{
            "name": "n1",
            "protocol": "wireguard",
            "endpoint": { "host": "127.0.0.1", "port": 51820 },
            "auth": {
                "private_key": "cHJpdmF0ZS1rZXktbWF0ZXJpYWw=",
                "public_key": "cHVibGljLWtleS1tYXRlcmlhbA==",
                "secret_key": "shadowsocks-secret",
                "password": "vmess-uuid-text"
            },
            "method": "chacha20-poly1305"
        }]"#;
        let nodes: Vec<NodeConfig> = serde_json::from_str(raw).unwrap();
        let text = format!("{:?}", nodes[0]);
        for leak in [
            "cHJpdmF0ZS1rZXktbWF0ZXJpYWw=",
            "cHVibGljLWtleS1tYXRlcmlhbA==",
            "shadowsocks-secret",
            "vmess-uuid-text",
        ] {
            assert!(!text.contains(leak), "Debug 输出不得包含凭据：{text}");
        }
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

    #[test]
    fn protocol_specific_requirements_fail_closed() {
        // vless/vmess 需要 UUID 形态。
        let mut nodes: Vec<NodeConfig> = serde_json::from_str(&node_json("vless")).unwrap();
        assert!(nodes[0].validate().is_err(), "非 UUID 口令必须被拒");
        nodes[0].auth.password = "11111111-1111-1111-1111-111111111111".into();
        assert!(nodes[0].validate().is_ok());

        // shadowsocks 需要 secret_key + method。
        let mut nodes: Vec<NodeConfig> = serde_json::from_str(&node_json("shadowsocks")).unwrap();
        assert!(nodes[0].validate().is_err(), "缺 secret_key 必须被拒");
        nodes[0].auth.secret_key = Some("test-secret".into());
        assert!(nodes[0].validate().is_err(), "缺 method 必须被拒");
        nodes[0].method = Some("aes-128-gcm".into());
        assert!(nodes[0].validate().is_ok());

        // wireguard 需要一对静态密钥。
        let mut nodes: Vec<NodeConfig> = serde_json::from_str(&node_json("wireguard")).unwrap();
        assert!(nodes[0].validate().is_err(), "缺密钥对必须被拒");
        nodes[0].auth.private_key = Some("k".repeat(43) + "=");
        nodes[0].auth.public_key = Some("k".repeat(43) + "=");
        assert!(nodes[0].validate().is_ok());
    }
}
