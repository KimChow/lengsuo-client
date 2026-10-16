//! 客户端配置与分流规则。
//!
//! 规则语义、字段与限制条件全部对齐 ss-server 侧的
//! `https://api.github.com/users/jev/src/config.rs`，
//! 差异只在**动作集合**：客户端没有 listen 语义，只有
//! `direct` / `proxy`，以及每规则的带宽上限。

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::{Error, Result};

/// 规则动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// 直连目标，不经过出口代理。
    Direct,
    /// 经 ss-outbound 发往出口代理服务器。
    Proxy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundConfig {
    pub ss_url: String,
    pub udp: bool,
    pub mux: MuxConfig,
    pub connect_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxConfig {
    pub enabled: bool,
    pub max_connections: usize,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self { enabled: false, max_connections: 8 }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsConfig {
    /// direct 规则用的 resolver。空表示用系统默认。
    pub direct: Vec<IpAddr>,
    /// proxy 规则用的 resolver。
    pub proxy: Vec<IpAddr>,
    /// true 时直连解析走系统 DNS 且不检查返回地址（信任系统）。
    pub direct_use_system: bool,
}

/// 目的地约束。`None` 表示该维度不限制；列表为空表示**匹配任意**。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Match {
    pub network: Vec<String>,
    pub domain_mode: Option<String>,
    pub domain: Vec<String>,
    pub ip: Vec<String>,
    pub port: Vec<PortRange>,
    pub process: Vec<String>,
    pub protocol: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

fn parse_port_spec(raw: &str) -> Result<PortRange> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::config("empty port matcher"));
    }
    let fail = || Error::config(format!("invalid port matcher `{raw}`"));
    if let Some((a, b)) = trimmed.split_once('-') {
        if a.is_empty() {
            let end = b.parse::<u16>().map_err(|_| fail())?;
            return Ok(PortRange { start: 1, end });
        }
        if b.is_empty() {
            let start = a.parse::<u16>().map_err(|_| fail())?;
            return Ok(PortRange { start, end: u16::MAX });
        }
        let start = a.parse::<u16>().map_err(|_| fail())?;
        let end = b.parse::<u16>().map_err(|_| fail())?;
        if start > end {
            return Err(fail());
        }
        return Ok(PortRange { start, end });
    }
    if trimmed.contains(':') {
        return Err(Error::config(format!(
            "port matcher `{raw}` must not contain `:`; IPv6 port belongs to the address matcher"
        )));
    }
    let single = trimmed.parse::<u16>().map_err(|_| fail())?;
    Ok(PortRange { start: single, end: single })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub action: Action,
    pub match_: Match,
    /// 该规则的总下行带宽上限，0 表示不限制。
    pub max_download_kbps: u32,
    /// 单连接下行上限，0 表示不限制。
    pub per_conn_download_kbps: u32,
    /// 该规则允许的最大并发连接数，0 表示不限制。
    pub max_concurrent: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    pub outbound: OutboundConfig,
    pub dns: DnsConfig,
    pub rules: Vec<Rule>,
    /// 无规则命中时的动作。默认 proxy。
    pub fallback: Action,
    /// 未显式约束的目的地 IP 是否允许直连（防私网/特殊地址泄漏）。
    pub direct_allow_private: bool,
    pub geoip_dir: Option<PathBuf>,
    pub geosite_dir: Option<PathBuf>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            outbound: OutboundConfig {
                ss_url: String::new(),
                udp: false,
                mux: MuxConfig::default(),
                connect_timeout_ms: 5_000,
            },
            dns: DnsConfig::default(),
            rules: Vec::new(),
            fallback: Action::Proxy,
            direct_allow_private: true,
            geoip_dir: None,
            geosite_dir: None,
        }
    }
}

// ---------------------------------------------------------------- 原始 TOML

#[derive(Debug, Deserialize)]
struct RawConfig {
    outbound: RawOutbound,
    #[serde(default)]
    dns: RawDns,
    #[serde(default)]
    rules: Vec<RawRule>,
    #[serde(default)]
    fallback: Option<String>,
    #[serde(default)]
    direct_allow_private: Option<bool>,
    #[serde(default)]
    geoip_dir: Option<String>,
    #[serde(default)]
    geosite_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawOutbound {
    ss_url: String,
    #[serde(default)]
    udp: Option<bool>,
    #[serde(default)]
    mux: Option<RawMux>,
    #[serde(default)]
    connect_timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RawMux {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    max_connections: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RawDns {
    #[serde(default)]
    direct: Vec<String>,
    #[serde(default)]
    proxy: Vec<String>,
    #[serde(default)]
    direct_use_system: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    name: String,
    action: String,
    #[serde(default, rename = "match")]
    match_: BTreeMap<String, toml::Value>,
    #[serde(default)]
    max_download_kbps: Option<u32>,
    #[serde(default)]
    per_conn_download_kbps: Option<u32>,
    #[serde(default)]
    max_concurrent: Option<usize>,
}

fn string_list(value: Option<&toml::Value>, field: &str) -> Result<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    match value {
        toml::Value::String(single) => Ok(vec![single.clone()]),
        toml::Value::Array(items) => items
            .iter()
            .map(|item| match item {
                toml::Value::String(text) => Ok(text.clone()),
                _ => Err(Error::config(format!("`{field}` must be a string array"))),
            })
            .collect(),
        _ => Err(Error::config(format!(
            "`{field}` must be a string or string array"
        ))),
    }
}

impl RawConfig {
    fn into_config(self) -> Result<ClientConfig> {
        let raw = self;
        let mut rules = Vec::with_capacity(raw.rules.len());
        for rule in raw.rules {
            rules.push(RawRule::build(rule)?);
        }
        let fallback = match raw.fallback.as_deref().unwrap_or("proxy") {
            "direct" => Action::Direct,
            "proxy" => Action::Proxy,
            other => {
                return Err(Error::config(format!(
                    "fallback must be `direct` or `proxy`, got `{other}`"
                )))
            }
        };
        Ok(ClientConfig {
            outbound: OutboundConfig {
                ss_url: raw.outbound.ss_url,
                udp: raw.outbound.udp.unwrap_or(false),
                mux: match raw.outbound.mux {
                    Some(mux) => MuxConfig {
                        enabled: mux.enabled.unwrap_or(false),
                        max_connections: mux.max_connections.unwrap_or(8),
                    },
                    None => MuxConfig::default(),
                },
                connect_timeout_ms: raw.outbound.connect_timeout_ms.unwrap_or(5_000),
            },
            dns: DnsConfig {
                direct: parse_ips(&raw.dns.direct)?,
                proxy: parse_ips(&raw.dns.proxy)?,
                direct_use_system: raw.dns.direct_use_system.unwrap_or(true),
            },
            rules,
            fallback,
            direct_allow_private: raw.direct_allow_private.unwrap_or(true),
            geoip_dir: raw.geoip_dir.map(PathBuf::from),
            geosite_dir: raw.geosite_dir.map(PathBuf::from),
        })
    }
}

fn parse_ips(items: &[String]) -> Result<Vec<IpAddr>> {
    items
        .iter()
        .map(|item| {
            item.parse::<IpAddr>()
                .map_err(|_| Error::config(format!("invalid resolver address `{item}`")))
        })
        .collect()
}

impl RawRule {
    fn build(self) -> Result<Rule> {
        let name = self.name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err(Error::config("rule name must not be empty"));
        }
        let action = match self.action.as_str() {
            "direct" => Action::Direct,
            "proxy" => Action::Proxy,
            other => {
                return Err(Error::config(format!(
                    "rule `{name}` action must be `direct` or `proxy`, got `{other}`"
                )))
            }
        };
        let fields = &self.match_;
        for key in fields.keys() {
            if !matches!(
                key.as_str(),
                "network"
                    | "domain"
                    | "domain_mode"
                    | "ip"
                    | "port"
                    | "process"
                    | "protocol"
            ) {
                return Err(Error::config(format!(
                    "rule `{name}` has unknown match field `{key}`"
                )));
            }
        }
        let domain_mode = match fields
            .get("domain_mode")
            .and_then(|value| value.as_str())
        {
            None => None,
            Some(mode @ ("plain" | "any" | "mapping" | "keyword")) => Some(mode.to_owned()),
            Some(mode) => {
                return Err(Error::config(format!(
                    "rule `{name}` domain_mode must be plain, any, mapping or keyword, got `{mode}`"
                )))
            }
        };
        let match_ = Match {
            network: normalized_networks(
                string_list(fields.get("network"), "network")?,
                &name,
            )?,
            domain_mode,
            domain: string_list(fields.get("domain"), "domain")?
                .into_iter()
                .map(|item| item.trim().to_ascii_lowercase())
                .collect(),
            ip: string_list(fields.get("ip"), "ip")?,
            port: string_list(fields.get("port"), "port")?
                .iter()
                .map(|spec| parse_port_spec(spec))
                .collect::<Result<Vec<_>>>()?,
            process: string_list(fields.get("process"), "process")?
                .into_iter()
                .map(|item| item.trim().to_ascii_lowercase())
                .collect(),
            protocol: normalized_protocols(
                string_list(fields.get("protocol"), "protocol")?,
                &name,
            )?,
        };
        Ok(Rule {
            name,
            action,
            match_,
            max_download_kbps: self.max_download_kbps.unwrap_or(0),
            per_conn_download_kbps: self.per_conn_download_kbps.unwrap_or(0),
            max_concurrent: self.max_concurrent.unwrap_or(0),
        })
    }
}

fn normalized_networks(values: Vec<String>, rule: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for value in values {
        match value.trim().to_ascii_lowercase().as_str() {
            "" => {}
            other @ ("tcp" | "udp") => out.push(other.to_owned()),
            other => {
                return Err(Error::config(format!(
                    "rule `{rule}` network must be tcp or udp, got `{other}`"
                )))
            }
        }
    }
    Ok(out)
}

fn normalized_protocols(values: Vec<String>, rule: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for value in values {
        match value.trim().to_ascii_lowercase().as_str() {
            "" => {}
            other @ ("http" | "https" | "tls" | "quic" | "socks5" | "ssh" | "ftp") => {
                out.push(other.to_owned())
            }
            other => {
                return Err(Error::config(format!(
                    "rule `{rule}` protocol must be http, https, tls, quic, socks5, ssh or ftp, got `{other}`"
                )))
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- 加载

pub fn load_config(path: &str) -> Result<ClientConfig> {
    if path.trim().is_empty() {
        return Err(Error::config("config path must not be empty"));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::config(format!("read config `{path}`: {e}")))?;
    load_config_str(&text)
}

pub fn load_config_str(text: &str) -> Result<ClientConfig> {
    let raw: RawConfig =
        toml::from_str(text).map_err(|e| Error::config(format!("parse config: {e}")))?;
    let config = raw.into_config()?;
    validate(&config)?;
    Ok(config)
}

fn validate(config: &ClientConfig) -> Result<()> {
    if config.outbound.ss_url.trim().is_empty() {
        return Err(Error::config("outbound.ss_url must not be empty"));
    }
    let mut names = std::collections::HashSet::new();
    for rule in &config.rules {
        if !names.insert(rule.name.clone()) {
            return Err(Error::config(format!("duplicate rule name `{}`", rule.name)));
        }
        if rule.action == Action::Direct && config.dns.direct.is_empty() && !config.dns.direct_use_system
        {
            return Err(Error::config(format!(
                "rule `{}` is direct but dns.direct is empty and dns.direct_use_system is false",
                rule.name
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsupported_action_and_colon_port() {
        let bad = r#"
[outbound]
ss_url = "ss://AEAD_CHACHA20_POLY1305:pw@1.2.3.4:8388"
[[rules]]
name = "x"
action = "block"
match = { port = ["[::1]:443"] }
"#;
        assert!(load_config_str(bad).is_err());
    }

    #[test]
    fn port_range_rejects_reversed_bounds() {
        assert!(parse_port_spec("900-80").is_err());
        assert_eq!(parse_port_spec("80").unwrap(), PortRange { start: 80, end: 80 });
        assert_eq!(
            parse_port_spec("20000-").unwrap(),
            PortRange { start: 20_000, end: u16::MAX }
        );
    }

    #[test]
    fn loads_rules_with_bandwidth_limits() {
        let text = r#"
[outbound]
ss_url = "ss://AEAD_CHACHA20_POLY1305:pw@1.2.3.4:8388"
mux = { enabled = true, max_connections = 4 }

[dns]
direct = ["223.5.5.5"]

fallback = "proxy"

[[rules]]
name = "lan"
action = "direct"
match = { network = ["tcp", "udp"], ip = ["192.168.0.0/16"] }

[[rules]]
name = "video"
action = "proxy"
match = { domain_mode = "mapping", domain = ["geosite:youtube"], port = ["443"] }
max_download_kbps = 20000
per_conn_download_kbps = 4000
max_concurrent = 32
"#;
        let config = load_config_str(text).unwrap();
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.rules[0].name, "lan");
        assert_eq!(config.rules[0].action, Action::Direct);
        assert_eq!(config.rules[1].max_download_kbps, 20_000);
        assert_eq!(config.rules[1].per_conn_download_kbps, 4_000);
        assert_eq!(config.rules[1].max_concurrent, 32);
        assert!(config.outbound.mux.enabled);
        assert_eq!(config.outbound.mux.max_connections, 4);
        assert_eq!(config.fallback, Action::Proxy);
    }
}
