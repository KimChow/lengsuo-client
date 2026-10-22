//! 端点、TLS 与凭据结构。

use std::fmt;

use serde::{Deserialize, Serialize};

use super::redacted;

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
