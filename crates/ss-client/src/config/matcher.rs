//! 规则匹配（配置层）。
//!
//! 语义对齐仓内 `policy.rs`（同族实现，见 `crates/ss-client/src/policy.rs`）：
//! **首条命中**、三态结论（`Matched` / `NotMatched` / `Undecided`）、
//! 命中不了的规则不阻断后续规则、无命中走 `fallback`。
//!
//! 与 `policy.rs` 的分工：本模块只实现**配置里声明过的维度**
//! （network / domain / ip / port / process / protocol），
//! **不含** geoip / geosite 数据库与两趟解析 —— 那些需要 `geoip_dir` /
//! `geosite_dir` 里的数据文件，属策略引擎职责。故本模块对
//! `geosite:` / `geoip:` 前缀的域名条目返回 [`MatchOutcome::Undecided`]：
//! **不确定就不决定**，绝不假装匹配成功。

use std::net::IpAddr;

use crate::config::types::{Action, ClientConfig, Match};
use crate::error::{ConfigError, Error, Result};

/// 匹配结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchOutcome {
    /// 命中。
    Matched,
    /// 不命中。
    NotMatched,
    /// **无法判定**：目标信息不全（如地址未解析）或需要策略引擎的 geo 库。
    Undecided,
}

/// 待判定的目标。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Target<'a> {
    /// 目标域名（未解析时为 `None`）。
    pub domain: Option<&'a str>,
    /// 目标 IP（未解析时为 `None`）。
    pub ip: Option<IpAddr>,
    /// 目标端口。
    pub port: u16,
    /// 网络层：`tcp` / `udp`。
    pub network: Option<&'a str>,
    /// 进程名。
    pub process: Option<&'a str>,
    /// 应用层协议。
    pub protocol: Option<&'a str>,
}

/// 匹配结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// 结论：动作。
    pub action: Action,
    /// 命中的规则名；`None` 表示走 `fallback`。
    pub rule: Option<String>,
    /// 结论尚未确定：需要先用**安全** resolver 解析地址后重试。
    pub needs_resolution: bool,
}

impl ClientConfig {
    /// 首条命中；无命中走 [`ClientConfig::fallback`]。
    ///
    /// 无法判定的规则（`Undecided`）**不**决定结论，只让
    /// [`Decision::needs_resolution`] 置位。
    #[must_use]
    pub fn decide(&self, target: &Target<'_>) -> Decision {
        for rule in &self.rules {
            match rule.match_.matches(target) {
                MatchOutcome::Matched => {
                    return Decision {
                        action: rule.action,
                        rule: Some(rule.name.clone()),
                        needs_resolution: false,
                    };
                }
                MatchOutcome::NotMatched | MatchOutcome::Undecided => {}
            }
        }
        Decision {
            action: self.fallback,
            rule: None,
            needs_resolution: self
                .rules
                .iter()
                .any(|rule| rule.match_.is_address_dependent() && target.ip.is_none()),
        }
    }
}

impl Match {
    /// 该维度是否依赖目标 IP（未解析时结论无法确定）。
    #[must_use]
    pub fn is_address_dependent(&self) -> bool {
        !self.ip.is_empty()
    }

    /// 逐维度判定。**所有**维度都要满足；空列表表示该维度不限制。
    #[must_use]
    pub fn matches(&self, target: &Target<'_>) -> MatchOutcome {
        if !self.network.is_empty() {
            let Some(actual) = target.network else {
                return MatchOutcome::Undecided;
            };
            if !self
                .network
                .iter()
                .any(|expected| expected.eq_ignore_ascii_case(actual))
            {
                return MatchOutcome::NotMatched;
            }
        }
        if !self.protocol.is_empty() {
            let Some(actual) = target.protocol else {
                return MatchOutcome::Undecided;
            };
            if !self
                .protocol
                .iter()
                .any(|expected| expected.eq_ignore_ascii_case(actual))
            {
                return MatchOutcome::NotMatched;
            }
        }
        if !self.process.is_empty() {
            let Some(actual) = target.process else {
                return MatchOutcome::Undecided;
            };
            if !self
                .process
                .iter()
                .any(|expected| expected.eq_ignore_ascii_case(actual))
            {
                return MatchOutcome::NotMatched;
            }
        }
        if !self.port.is_empty() && !self.port.iter().any(|range| range.contains(target.port)) {
            return MatchOutcome::NotMatched;
        }
        if !self.ip.is_empty() {
            let Some(addr) = target.ip else {
                return MatchOutcome::Undecided;
            };
            let mut hit = false;
            for spec in &self.ip {
                let Ok(cidr) = Cidr::parse(spec) else {
                    return MatchOutcome::Undecided;
                };
                if cidr.contains(&addr) {
                    hit = true;
                    break;
                }
            }
            if !hit {
                return MatchOutcome::NotMatched;
            }
        }
        if !self.domain.is_empty() {
            return self.match_domain(target.domain);
        }
        MatchOutcome::Matched
    }

    /// 域名维度判定。
    ///
    /// `domain_mode` 语义（见 `docs/ss-client-config-activate.md` 偏离清单 D3）：
    /// - `plain`：整串相等（忽略大小写与末尾点）；
    /// - `keyword`：子串包含；
    /// - `mapping`：后缀（域名本身或其子域）；
    /// - `any`：该维度不限制。
    ///
    /// 未给 `domain_mode` 时按 `plain` 处理（**不忽略**非空域名列表，
    /// 否则会静默放行一切流量）。
    fn match_domain(&self, domain: Option<&str>) -> MatchOutcome {
        let Some(domain) = domain else {
            return MatchOutcome::Undecided;
        };
        let mode = self.domain_mode.as_deref().unwrap_or("plain");
        if mode == "any" {
            return MatchOutcome::Matched;
        }
        let domain = normalize_domain(domain);
        for pattern in &self.domain {
            // geo 数据库条目要策略引擎才能判定 ⇒ 不决定。
            if pattern.starts_with("geosite:") || pattern.starts_with("geoip:") {
                return MatchOutcome::Undecided;
            }
            let pattern = normalize_domain(pattern);
            let hit = match mode {
                "plain" => domain == pattern,
                "keyword" => domain.contains(&pattern),
                "mapping" => {
                    domain == pattern
                        || domain
                            .strip_suffix(&pattern)
                            .is_some_and(|head| head.ends_with('.'))
                }
                _ => false,
            };
            if hit {
                return MatchOutcome::Matched;
            }
        }
        MatchOutcome::NotMatched
    }
}

/// 域名归一化：小写、去掉末尾的点（DNS 大小写不敏感、尾点等价于根）。
fn normalize_domain(domain: &str) -> String {
    let lowered = domain.trim().to_ascii_lowercase();
    lowered
        .strip_suffix('.')
        .unwrap_or(lowered.as_str())
        .to_owned()
}

/// CIDR 网段（IPv4 / IPv6）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// 解析 CIDR 或单个 IP。**主机位非零一律拒绝**（fail-closed）。
    pub(crate) fn parse(spec: &str) -> Result<Self> {
        let trimmed = spec.trim();
        let (addr_text, prefix_text) = match trimmed.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (trimmed, None),
        };
        let addr: IpAddr = addr_text.trim().parse().map_err(|_| invalid_ip(spec))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_text {
            Some(text) => {
                let value: u8 = text.trim().parse().map_err(|_| invalid_ip(spec))?;
                if value > max {
                    return Err(invalid_ip(spec));
                }
                value
            }
            None => max,
        };
        if masked(addr, prefix) != addr {
            return Err(ConfigError::Invalid {
                field: "match.ip",
                reason: format!("`{spec}` has host bits set; write the network address"),
            }
            .into());
        }
        Ok(Self { addr, prefix })
    }

    /// 目标地址是否落在网段内。
    pub(crate) fn contains(&self, addr: &IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(net), IpAddr::V4(target)) => {
                mask_v4(net, self.prefix) == mask_v4(*target, self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(target)) => {
                mask_v6(net, self.prefix) == mask_v6(*target, self.prefix)
            }
            _ => false,
        }
    }
}

fn invalid_ip(spec: &str) -> Error {
    ConfigError::Invalid {
        field: "match.ip",
        reason: format!("`{spec}` is not a valid IP or CIDR"),
    }
    .into()
}

/// 按前缀长度归一化地址（主机位清零）。
fn masked(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => IpAddr::V4(mask_v4(v4, prefix)),
        IpAddr::V6(v6) => IpAddr::V6(mask_v6(v6, prefix)),
    }
}

fn mask_v4(addr: std::net::Ipv4Addr, prefix: u8) -> std::net::Ipv4Addr {
    let bits = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    std::net::Ipv4Addr::from(bits & mask)
}

fn mask_v6(addr: std::net::Ipv6Addr, prefix: u8) -> std::net::Ipv6Addr {
    let bits = u128::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    std::net::Ipv6Addr::from(bits & mask)
}
