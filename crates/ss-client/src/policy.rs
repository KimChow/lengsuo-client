//! 客户端策略引擎。
//!
//! 匹配语义（matcher 种类、域名模式推断、通配符、geo 集合、归一化、
//! 最长前缀 CIDR、首条命中）与 ss-server 的
//! `https://api.github.com/users/jev/src/config.rs`，
//! 完全对齐 —— 唯一区别是动作为 `direct` / `proxy`。
//!
//! 客户端多一个约束：命中可能需要目标 IP（`ip` / `network` 维度）。
//! 在拿到地址之前不能擅自用直连 resolver 去解析，否则会泄漏 DNS。
//! `evaluate` 因此分两趟：第一趟只用已知的域名/端口/进程判断；
//! 若结论依赖地址则返回 `needs_resolution`，由调用方用**安全**的
//! resolver 解析后再走第二趟。

use std::net::IpAddr;

use serde::Deserialize;

use crate::config::{Action, ClientConfig, Match, Rule};
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub sni: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub address: Option<IpAddr>,
    pub resolved: bool,
    pub port: u16,
    pub protocol: Option<&'a str>,
    pub network: Option<&'a str>,
    pub process_name: Option<&'a str>,
}

/// 策略结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    /// 命中的规则名；None 表示走 fallback。
    pub rule: Option<String>,
    /// 结论尚未确定：需要先用安全 resolver 解析地址后重试。
    pub needs_resolution: bool,
}

impl Decision {
    pub fn rule_name(&self) -> &str {
        self.rule.as_deref().unwrap_or("fallback")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainMode {
    Plain,
    Any,
    Mapping,
    Keyword,
}

#[derive(Debug, Clone)]
enum Matcher {
    Network(String),
    Domain(DomainMode, String),
    IpCidr(u32, u128, u8),
    Process(String),
    Protocol(String),
    PortRange { start: u16, end: u16 },
    GeoSite(String),
    GeoIp(String),
}

pub struct Policy {
    entries: Vec<CompiledRule>,
    fallback: Action,
    geoip: GeoIpDb,
    geosite: GeoSiteDb,
}

struct CompiledRule {
    name: String,
    action: Action,
    matchers: Vec<Matcher>,
    max_download_kbps: u32,
    per_conn_download_kbps: u32,
    max_concurrent: usize,
}

#[derive(Debug, Deserialize)]
struct GeoIpFile {
    rules: Vec<GeoIpRule>,
}

#[derive(Debug, Deserialize)]
struct GeoIpRule {
    prefix: String,
}

#[derive(Debug, Deserialize)]
struct GeoSiteFile {
    domain: Vec<GeoSiteEntry>,
}

#[derive(Debug, Deserialize)]
struct GeoSiteEntry {
    #[serde(rename = "type")]
    kind: String,
    domain: String,
}

#[derive(Default)]
pub struct GeoIpDb {
    networks: Vec<(u32, u128, u8)>,
}

#[derive(Default)]
pub struct GeoSiteDb {
    domain_sets: BTreeMapShim,
}

/// 用 `BTreeMap<String, Vec<(DomainMode, String)>>`，但保持结构体命名可读。
pub type BTreeMapShim = std::collections::BTreeMap<String, Vec<(DomainMode, String)>>;

impl GeoIpDb {
    fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("read geoip `{path}`: {e}")))?;
        let file: GeoIpFile =
            serde_json::from_str(&text).map_err(|e| Error::config(format!("geoip json: {e}")))?;
        let mut networks = Vec::with_capacity(file.rules.len());
        for entry in file.rules {
            networks.push(parse_cidr(&entry.prefix)?);
        }
        networks.sort_by_key(|(version, _addr, length)| (
            *version,
            std::cmp::Reverse(*length),
        ));
        Ok(Self { networks })
    }

    fn matches(&self, addr: IpAddr, code: &str) -> bool {
        let Ok(value) = std::fs::read_to_string("") // placeholder never used
            .map(|_| ())
            .map(|()| ())
            .map(|_: ()| ()) else { return false };
    }
}

#[derive(Clone, Copy)]
enum IpBits {
    V4(u32),
    V6(u128),
}

fn to_bits(addr: IpAddr) -> IpBits {
    match addr {
        IpAddr::V4(v4) => IpBits::V4(u32::from(v4)),
        IpAddr::V6(v6) => IpBits::V6(u128::from(v6)),
    }
}

impl Policy {
    pub fn from_config(config: &ClientConfig) -> Result<Self> {
        let mut geoip_networks = Vec::new();
        let mut geosite_sets = BTreeMapShim::new();
        if let Some(dir) = &config.geoip_dir {
            let path = dir.join("geoip.json");
            let text = std::fs::read_to_string(&path).map_err(|e| {
                Error::config(format!("read geoip `{}`: {e}", path.display()))
            })?;
            let file: GeoIpFile = serde_json::from_str(&text)
                .map_err(|e| Error::config(format!("geoip json: {e}")))?;
            for entry in file.rules {
                geoip_networks.push(parse_cidr(&entry.prefix)?);
            }
        }
        if let Some(dir) = &config.geosite_dir {
            let path = dir.join("geosite.json");
            let text = std::fs::read_to_string(&path).map_err(|e| {
                Error::config(format!("read geosite `{}`: {e}", path.display()))
            })?;
            let file: GeoSiteFile = serde_json::from_str(&text)
                .map_err(|e| Error::config(format!("geosite json: {e}")))?;
            for entry in file.domain {
                let item = match entry.kind.as_str() {
                    "keyword" => (DomainMode::Keyword, entry.domain),
                    "domain" => (DomainMode::Plain, entry.domain),
                    "full" => (DomainMode::Mapping, entry.domain),
                    _ => {
                        return Err(Error::config(format!(
                            "unsupported geosite type `{}`",
                            entry.kind
                        )))
                    }
                };
                geosite_sets
                    .entry(entry_domain_key(&item.1))
                    .or_insert_with(Vec::new)
                    .push(item);
            }
        }
        geoip_networks.sort_by_key(|(version, _addr, length)| (*version, std::cmp::Reverse(*length)));
        let mut entries = Vec::with_capacity(config.rules.len());
        for rule in &config.rules {
            entries.push(compile_rule(rule, &geoip_networks, &geosite_sets)?);
        }
        Ok(Self {
            entries,
            fallback: config.fallback,
            geoip: GeoIpDb { networks: geoip_networks },
            geosite: geosite_sets,
        })
    }

    /// 首条命中。两趟语义见模块注释。
    pub fn decide(&self, req: &Request<'_>) -> Decision {
        for (index, rule) in self.entries.iter().enumerate() {
            let outcome = rule.matches(req, &self.geoip, &self.geosite);
            if outcome == MatchOutcome::Undecided {
                continue;
            }
            if outcome == MatchOutcome::Matched {
                return Decision {
                    action: rule.action,
                    rule: Some(rule.name.clone()),
                    needs_resolution: false,
                };
            }
            // NotMatched 继续下一条；但若后面的规则可能依赖地址，
            // 需要在返回 fallback 前告知调用方。
            debug_assert_eq!(outcome, MatchOutcome::NotMatched);
            let _ = index;
        }
        let needs = self
            .entries
            .iter()
            .any(|rule| rule.address_dependent() && !req.resolved);
        Decision {
            action: self.fallback,
            rule: None,
            needs_resolution: needs,
        }
    }
}

fn entry_domain_key(domain: &str) -> String {
    domain.to_ascii_lowercase()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchOutcome {
    Matched,
    NotMatched,
    Undecided,
}

impl CompiledRule {
    fn address_dependent(&self) -> bool {
        self.matchers.iter().any(|matcher| {
            matches!(matcher, Matcher::IpCidr(..) | Matcher::GeoIp(_))
        })
    }

    fn matches(&self, req: &Request<'_>, geoip: &[Network], geosite: &BTreeMapShim) -> MatchOutcome {
        for matcher in &self.matchers {
            match matcher {
                Matcher::Network(expected) => {
                    let Some(actual) = req.network else { return MatchOutcome::Undecided };
                    if !eq_ci(actual, expected) {
                        return MatchOutcome::NotMatched;
                    }
                }
                Matcher::Domain(mode, expected) => {
                    let Some(domain) = req.hostname.or(req.sni) else {
                        return MatchOutcome::Undecided;
                    };
                    if !domain_matches(mode, expected, normalize_domain(domain)) {
                        return MatchOutcome::NotMatched;
                    }
                }
                Matcher::GeoSite(code) => {
                    let Some(domain) = req.hostname.or(req.sni) else {
                        return MatchOutcome::Undecided;
                    };
                    let Some(items) = geosite.get(&code.to_ascii_lowercase()) else {
                        return MatchOutcome::Undecided;
                    };
                    let domain = normalize_domain(domain);
                    if !items
                        .iter()
                        .any(|(mode, expected)| domain_matches(mode, expected, domain))
                    {
                        return MatchOutcome::NotMatched;
                    }
                }
                Matcher::IpCidr(..) | Matcher::GeoIp(..) => {
                    let Some(addr) = req.address else { return MatchOutcome::Undecided };
                    if !ip_matches(matcher, addr, geoip) {
                        return MatchOutcome::NotMatched;
                    }
                }
                Matcher::Process(expected) => {
                    let Some(actual) = req.process_name else { return MatchOutcome::Undecided };
                    if !process_matches(expected, actual) {
                        return MatchOutcome::NotMatched;
                    }
                }
                Matcher::Protocol(expected) => {
                    let Some(actual) = req.protocol else { return MatchOutcome::Undecided };
                    if !eq_ci(actual, expected) {
                        return MatchOutcome::NotMatched;
                    }
                }
                Matcher::PortRange { start, end } => {
                    if req.port < *start || req.port > *end {
                        return MatchOutcome::NotMatched;
                    }
                }
            }
        }
        MatchOutcome::Matched
    }
}
