//! 客户端配置的数据模型：结构、默认值与**只依赖 std** 的校验。
//!
//! 本文件刻意**不引入任何新依赖**：`serde` / `toml` 都不在 `ss-client` 的
//! 依赖表里，而 `Cargo.toml` 由基建卡独占（见 `docs/ss-client-config-activate.md`
//! 偏离清单 D1）。因此反序列化在 `config/toml.rs` + `config/load.rs` 里手写，
//! 而本文件只承载**与文件格式无关**的结构与校验。

use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use crate::error::{ConfigError, Error, Result};

/// 规则动作。客户端**只允许** `direct` / `proxy`，其它值一律拒绝（fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// 直连目标，不经过出口代理。
    Direct,
    /// 经 ss-outbound 发往出口代理服务器。
    Proxy,
}

impl Action {
    /// 配置里的字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Proxy => "proxy",
        }
    }

    /// 解析动作字面量。非 `direct` / `proxy` 一律拒绝（fail-closed）。
    pub(crate) fn parse(field: &'static str, raw: &str) -> Result<Self> {
        match raw {
            "direct" => Ok(Self::Direct),
            "proxy" => Ok(Self::Proxy),
            other => Err(ConfigError::UnsupportedAction {
                field,
                value: other.to_owned(),
            }
            .into()),
        }
    }
}

/// 出口（出站代理）配置。
///
/// `ss_url` 内含凭据，因此 [`Debug`] 走**手写实现**脱敏（见 [`RedactedUrl`]）。
#[derive(Clone, PartialEq, Eq)]
pub struct OutboundConfig {
    /// 出口 URL（**凭据在此**，Debug 已脱敏）。历史字段名 `ss_url`；ec2 起
    /// 接受八协议 scheme——`ss://` 之外的七个见 `crate::outbound::endpoint`。
    pub ss_url: String,
    /// 是否启用 UDP 转发。
    pub udp: bool,
    /// 多路复用设置。
    pub mux: MuxConfig,
    /// 建立到出口代理的连接超时（毫秒）。
    pub connect_timeout_ms: u64,
}

impl fmt::Debug for OutboundConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundConfig")
            .field("ss_url", &RedactedUrl(&self.ss_url))
            .field("udp", &self.udp)
            .field("mux", &self.mux)
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .finish()
    }
}

/// 出口 URL 的脱敏视图：只保留 scheme / 加密名与主机，**凭据一律替换成 `***`**。
///
/// 对齐 `crates/lengsuo-node/src/config.rs` 的凭据脱敏约定（Debug 不得带凭据原文）。
struct RedactedUrl<'a>(&'a str);

impl fmt::Debug for RedactedUrl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some((scheme, rest)) = self.0.split_once("://") else {
            return f.write_str("***");
        };
        // 备注（`#` 之后）不含凭据也不含主机，直接丢弃。
        let rest = rest.split('#').next().unwrap_or("");
        // 用**最后一个** `@` 切分：口令里出现裸 `@` 时也不会把主机切错。
        let Some((_secret, host_part)) = rest.rsplit_once('@') else {
            return write!(f, "{scheme}://***");
        };
        if scheme != "ss" {
            // 其余 scheme：userinfo 整段打码（UUID / 口令 / 密钥对都在这里）。
            return write!(f, "{scheme}://***@{host_part}");
        }
        let Some((method, _)) = rest.split_once(':') else {
            return f.write_str("ss://***");
        };
        write!(f, "ss://{method}:***@{host_part}")
    }
}

/// 多路复用设置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxConfig {
    pub enabled: bool,
    pub max_connections: usize,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_connections: 8,
        }
    }
}

/// DNS 设置。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsConfig {
    /// direct 规则用的 resolver。空表示用系统默认。
    pub direct: Vec<IpAddr>,
    /// proxy 规则用的 resolver。
    pub proxy: Vec<IpAddr>,
    /// true 时直连解析走系统 DNS 且不检查返回地址（信任系统）。
    pub direct_use_system: bool,
}

/// 目的地约束。
///
/// **列表型维度**（network / domain / ip / port / process / protocol）：
/// 列表为空表示该维度**不限制**（匹配任意）。
///
/// **模式型字段** `domain_mode`：`None` 表示未指定模式，此时域名列表按
/// `plain`（整串相等）处理 —— **不是**「忽略域名列表」，否则一份漏写模式的
/// 配置会静默放行一切流量（fail-open）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Match {
    /// 网络层：`tcp` / `udp`。
    pub network: Vec<String>,
    /// 域名匹配模式：`plain` / `keyword` / `mapping` / `any`。
    pub domain_mode: Option<String>,
    /// 域名列表。
    pub domain: Vec<String>,
    /// 目标 IP（CIDR 或单 IP）。
    pub ip: Vec<String>,
    /// 目标端口区间。
    pub port: Vec<PortRange>,
    /// 进程名。
    pub process: Vec<String>,
    /// 应用层协议。
    pub protocol: Vec<String>,
}

/// 端口区间（闭区间）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /// 端口是否落在区间内。
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

/// 一条分流规则。
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

/// 客户端配置。
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
            dns: DnsConfig {
                direct_use_system: true,
                ..DnsConfig::default()
            },
            rules: Vec::new(),
            fallback: Action::Proxy,
            direct_allow_private: true,
            geoip_dir: None,
            geosite_dir: None,
        }
    }
}

// ---------------------------------------------------------------- 校验辅助

fn invalid(field: &'static str, reason: impl Into<String>) -> Error {
    ConfigError::Invalid {
        field,
        reason: reason.into(),
    }
    .into()
}

fn port_error(reason: impl Into<String>) -> Error {
    invalid("match.port", reason)
}

/// 解析端口匹配串：`443`、`8000-9000`、`-443`（1..443）、`8000-`（8000..65535）。
///
/// **端口 0 一律拒绝**：0 不是合法目标端口，原实现会放过它，这里收紧（fail-closed）。
pub(crate) fn parse_port_spec(raw: &str) -> Result<PortRange> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(port_error("empty port matcher"));
    }
    if trimmed.contains(':') {
        return Err(port_error(format!(
            "port matcher `{trimmed}` must not contain `:`; IPv6 port belongs to the address matcher"
        )));
    }
    if let Some((a, b)) = trimmed.split_once('-') {
        let (start, end) = if a.is_empty() {
            (1_u16, parse_port(b)?)
        } else if b.is_empty() {
            (parse_port(a)?, u16::MAX)
        } else {
            let start = parse_port(a)?;
            let end = parse_port(b)?;
            if start > end {
                return Err(port_error(format!("reversed port range `{trimmed}`")));
            }
            (start, end)
        };
        if start == 0 || end == 0 {
            return Err(port_error("port 0 is not a valid target port"));
        }
        return Ok(PortRange { start, end });
    }
    let single = parse_port(trimmed)?;
    if single == 0 {
        return Err(port_error("port 0 is not a valid target port"));
    }
    Ok(PortRange {
        start: single,
        end: single,
    })
}

fn parse_port(raw: &str) -> Result<u16> {
    let trimmed = raw.trim();
    trimmed
        .parse::<u16>()
        .map_err(|_| port_error(format!("invalid port `{trimmed}`")))
}

/// 解析 resolver 地址列表。非法地址一律拒绝（fail-closed）。
pub(crate) fn parse_ips(items: &[String]) -> Result<Vec<IpAddr>> {
    items
        .iter()
        .map(|item| {
            item.trim()
                .parse::<IpAddr>()
                .map_err(|_| invalid("dns", format!("invalid resolver address `{item}`")))
        })
        .collect()
}

/// 网络层取值归一化：只允许 `tcp` / `udp`。
pub(crate) fn normalized_networks(values: Vec<String>, rule: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for value in values {
        match value.trim().to_ascii_lowercase().as_str() {
            "" => {}
            other @ ("tcp" | "udp") => out.push(other.to_owned()),
            other => {
                return Err(invalid(
                    "match.network",
                    format!("rule `{rule}` network must be tcp or udp, got `{other}`"),
                ))
            }
        }
    }
    Ok(out)
}

/// 应用层协议取值归一化：只允许已知的一组。
pub(crate) fn normalized_protocols(values: Vec<String>, rule: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for value in values {
        match value.trim().to_ascii_lowercase().as_str() {
            "" => {}
            other @ ("http" | "https" | "tls" | "quic" | "socks5" | "ssh" | "ftp") => {
                out.push(other.to_owned())
            }
            other => {
                return Err(invalid(
                    "match.protocol",
                    format!(
                        "rule `{rule}` protocol must be http, https, tls, quic, socks5, ssh or ftp, got `{other}`"
                    ),
                ))
            }
        }
    }
    Ok(out)
}

/// 域名模式白名单：`plain` / `keyword` / `mapping` / `any`。
///
/// 语义见 `config/matcher.rs`。
pub(crate) const DOMAIN_MODES: [&str; 4] = ["plain", "keyword", "mapping", "any"];

/// 规则 `match` 段允许出现的字段名。
pub(crate) const MATCH_FIELDS: [&str; 7] = [
    "network",
    "domain",
    "domain_mode",
    "ip",
    "port",
    "process",
    "protocol",
];
