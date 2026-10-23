//! 按目标地址选节点：规则形态、specificity 排序与冲突检测。
//!
//! 规则形态（与任务书一致）：`RouteRule { domain_suffix: Option<String>,
//! cidr: Option<IpNet>, node: String }`。`domain_suffix` 与 `cidr` **互斥**：
//! 一条规则必须且只能指定其中之一，否则配置加载阶段就报错（fail-closed）。
//!
//! specificity（**最具体优先**）：
//!
//! | 层级 | 命中条件 | magnitude |
//! | --- | --- | --- |
//! | 3 精确域名 | 目标域名与规则后缀**完全相等** | 后缀长度 |
//! | 2 域名后缀 | 目标域名以 `.` + 后缀结尾（子域） | 后缀长度 |
//! | 1 CIDR | 目标 IP 落在网段内 | 前缀长度（越长越具体） |
//! | 0 默认节点 | 无任何规则命中 | 0 |
//!
//! 同一层级内 magnitude 大者更具体（更长的后缀 / 更长的前缀）。
//! **同 specificity 多条命中且指向不同节点 ⇒ 显式报错**（不静默取第一条）。
//!
//! 域名比较一律小写化并去掉末尾的点（DNS 大小写不敏感、尾点等价于根）。
//! 域名规则只匹配域名目标，CIDR 规则只匹配 IP 目标（不做「IP 反查域名」）。
//!
//! 偏离：`IpNet` 是本模块自带的最小实现（`addr/prefix`），不是 `ipnet` crate
//! ——`Cargo.toml` 由基建卡独占，本卡不得新增依赖（见 `docs/node-status.md`
//! 偏离清单）。

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ss_core::target::TargetAddr;

/// 路由相关错误。全部 fail-closed：调用方必须断开连接，**不得**回落到直连。
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("路由规则非法：{0}")]
    Invalid(String),
    #[error("路由规则冲突：{0}")]
    Conflict(String),
    #[error("没有匹配的路由规则，且未配置默认节点")]
    NoRoute,
    #[error("路由引用了不存在的节点：{0}")]
    UnknownNode(String),
}

/// CIDR 网段。构造时把地址按掩码**规范化**（`10.0.0.1/8` ≡ `10.0.0.0/8`），
/// 使重复键检测不受书写差异影响。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// 构造网段；前缀长度越界（IPv4 > 32、IPv6 > 128）即拒绝。
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, RouteError> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(RouteError::Invalid(format!(
                "CIDR 前缀长度 {prefix} 越界（该地址族上限 {max}）"
            )));
        }
        Ok(Self {
            addr: mask_addr(addr, prefix),
            prefix,
        })
    }

    /// 网段地址（已按掩码规范化）。
    #[must_use]
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// 前缀长度。
    #[must_use]
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// 目标 IP 是否落在本网段内。地址族不同一律不匹配（不做 v4-in-v6 映射）。
    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, *ip) {
            (IpAddr::V4(net), IpAddr::V4(target)) => {
                let mask = v4_mask(self.prefix);
                (u32::from(net) & mask) == (u32::from(target) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(target)) => {
                let mask = v6_mask(self.prefix);
                (u128::from(net) & mask) == (u128::from(target) & mask)
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for IpNet {
    type Err = RouteError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = text
            .split_once('/')
            .ok_or_else(|| RouteError::Invalid(format!("CIDR 缺少前缀长度：{text}")))?;
        let addr: IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| RouteError::Invalid(format!("CIDR 地址非法：{addr}")))?;
        let prefix: u8 = prefix
            .trim()
            .parse()
            .map_err(|_| RouteError::Invalid(format!("CIDR 前缀长度非法：{prefix}")))?;
        Self::new(addr, prefix)
    }
}

impl Serialize for IpNet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for IpNet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_str(&text).map_err(serde::de::Error::custom)
    }
}

/// IPv4 掩码。
fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// IPv6 掩码。
fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// 把地址按掩码规范化。
fn mask_addr(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => IpAddr::V4(std::net::Ipv4Addr::from(u32::from(v4) & v4_mask(prefix))),
        IpAddr::V6(v6) => IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & v6_mask(prefix))),
    }
}

/// 匹配的具体程度。`tier` 为主序（精确域名 > 后缀 > CIDR），`magnitude` 为次序
/// （更长的后缀 / 更长的前缀更具体）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Specificity {
    pub tier: u8,
    pub magnitude: u32,
}

impl Specificity {
    /// 精确域名层。
    pub const EXACT_DOMAIN: u8 = 3;
    /// 域名后缀层。
    pub const DOMAIN_SUFFIX: u8 = 2;
    /// CIDR 层。
    pub const CIDR: u8 = 1;
    /// 默认节点层（不参与规则竞争）。
    pub const DEFAULT: u8 = 0;

    #[must_use]
    pub const fn new(tier: u8, magnitude: u32) -> Self {
        Self { tier, magnitude }
    }
}

/// 一条路由规则。`domain_suffix` 与 `cidr` 互斥（构造 [`RouteTable`] 时校验）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRule {
    /// 域名后缀（或精确域名）。命中条件见模块注释的 specificity 表。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_suffix: Option<String>,
    /// IP 网段。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<IpNet>,
    /// 命中后使用的节点名（必须存在于节点列表中）。
    pub node: String,
}

/// 规范化域名：小写 + 去掉末尾的点。
fn normalize_domain(text: &str) -> String {
    let lowered = text.trim().to_ascii_lowercase();
    lowered.strip_suffix('.').unwrap_or(&lowered).to_owned()
}

/// 目标域名与规则后缀的匹配结果。
///
/// - `Exact`：域名与后缀完全相等。
/// - `Suffix`：域名以「标签边界 + 后缀」结尾（`a.example.com` 命中 `example.com`，
///   而 `notexample.com` **不**命中 `example.com`）。
/// - `None`：不命中。
fn match_domain(host: &str, suffix: &str) -> Option<bool> {
    let host = normalize_domain(host);
    let suffix = normalize_domain(suffix);
    if host == suffix {
        return Some(true);
    }
    if host.len() > suffix.len()
        && host.ends_with(&suffix)
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    {
        return Some(false);
    }
    None
}

/// 选中的路由。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// 选中的节点名。
    pub node: String,
    /// 命中规则的具体程度；默认节点为 tier 0。
    pub specificity: Specificity,
}

/// 路由表：规则集合 + 默认节点。
#[derive(Debug, Clone)]
pub struct RouteTable {
    rules: Vec<RouteRule>,
    default_node: Option<String>,
}

impl RouteTable {
    /// 构造路由表。**静态冲突在此显式报错**（配置加载阶段）：
    /// - 规则必须且只能指定 `domain_suffix` 或 `cidr` 之一；
    /// - 同键规则（同后缀或同网段）重复出现 ⇒ 冲突（即便指向同一节点也报错，
    ///   避免「谁生效」依赖书写顺序）。
    pub fn new(rules: Vec<RouteRule>, default_node: Option<String>) -> Result<Self, RouteError> {
        let mut seen_domains: Vec<(String, String)> = Vec::with_capacity(rules.len());
        let mut seen_cidrs: Vec<(IpNet, String)> = Vec::with_capacity(rules.len());
        for rule in &rules {
            if rule.node.trim().is_empty() {
                return Err(RouteError::Invalid("规则的 node 不能为空".to_owned()));
            }
            match (&rule.domain_suffix, &rule.cidr) {
                (Some(suffix), None) => {
                    let key = normalize_domain(suffix);
                    if key.is_empty() {
                        return Err(RouteError::Invalid("domain_suffix 不能为空".to_owned()));
                    }
                    if let Some((_, other)) = seen_domains.iter().find(|(k, _)| *k == key) {
                        return Err(RouteError::Conflict(format!(
                            "域名后缀 {key} 出现多条规则（{other} 与 {}）",
                            rule.node
                        )));
                    }
                    seen_domains.push((key, rule.node.clone()));
                }
                (None, Some(net)) => {
                    if let Some((_, other)) = seen_cidrs.iter().find(|(k, _)| k == net) {
                        return Err(RouteError::Conflict(format!(
                            "网段 {net} 出现多条规则（{other} 与 {}）",
                            rule.node
                        )));
                    }
                    seen_cidrs.push((net.clone(), rule.node.clone()));
                }
                (Some(_), Some(_)) => {
                    return Err(RouteError::Invalid(
                        "domain_suffix 与 cidr 互斥，一条规则只能指定其一".to_owned(),
                    ))
                }
                (None, None) => {
                    return Err(RouteError::Invalid(
                        "规则必须指定 domain_suffix 或 cidr 之一".to_owned(),
                    ))
                }
            }
        }
        if let Some(node) = &default_node {
            if node.trim().is_empty() {
                return Err(RouteError::Invalid("default_node 不能为空".to_owned()));
            }
        }
        Ok(Self {
            rules,
            default_node,
        })
    }

    /// 规则集合（只读）。
    #[must_use]
    pub fn rules(&self) -> &[RouteRule] {
        &self.rules
    }

    /// 默认节点名。
    #[must_use]
    pub fn default_node(&self) -> Option<&str> {
        self.default_node.as_deref()
    }

    /// 按目标地址选节点。
    ///
    /// 最具体优先；同 specificity 多条命中且指向不同节点 ⇒ [`RouteError::Conflict`]
    /// （不静默取第一条）。无规则命中时用默认节点；**默认节点也不存在 ⇒
    /// [`RouteError::NoRoute`]**（调用方必须 fail-closed 断开，不得直连）。
    pub fn select(&self, target: &TargetAddr) -> Result<Selection, RouteError> {
        let mut best: Option<(Specificity, &RouteRule)> = None;
        let mut conflict: Option<String> = None;
        for rule in &self.rules {
            let Some(specificity) = rule.match_target(target) else {
                continue;
            };
            match best {
                None => best = Some((specificity, rule)),
                Some((current, current_rule)) => {
                    if specificity > current {
                        best = Some((specificity, rule));
                        conflict = None;
                    } else if specificity == current && rule.node != current_rule.node {
                        conflict = Some(format!(
                            "同 specificity（tier={} magnitude={}）命中节点 {} 与 {}",
                            specificity.tier, specificity.magnitude, current_rule.node, rule.node
                        ));
                    }
                }
            }
        }
        if let Some(reason) = conflict {
            return Err(RouteError::Conflict(reason));
        }
        if let Some((specificity, rule)) = best {
            return Ok(Selection {
                node: rule.node.clone(),
                specificity,
            });
        }
        match &self.default_node {
            Some(node) => Ok(Selection {
                node: node.clone(),
                specificity: Specificity::new(Specificity::DEFAULT, 0),
            }),
            None => Err(RouteError::NoRoute),
        }
    }
}

impl RouteRule {
    /// 规则对目标地址的命中结果（`None` = 不命中）。
    #[must_use]
    pub fn match_target(&self, target: &TargetAddr) -> Option<Specificity> {
        match (&self.domain_suffix, &self.cidr) {
            (Some(suffix), None) => {
                let host = match target {
                    TargetAddr::Domain(host, _) => host.as_str(),
                    _ => return None,
                };
                let exact = match_domain(host, suffix)?;
                let tier = if exact {
                    Specificity::EXACT_DOMAIN
                } else {
                    Specificity::DOMAIN_SUFFIX
                };
                Some(Specificity::new(
                    tier,
                    normalize_domain(suffix).len() as u32,
                ))
            }
            (None, Some(net)) => {
                let ip = match target {
                    TargetAddr::V4(octets, _) => IpAddr::from(*octets),
                    TargetAddr::V6(octets, _) => IpAddr::from(*octets),
                    TargetAddr::Domain(_, _) => return None,
                };
                net.contains(&ip)
                    .then(|| Specificity::new(Specificity::CIDR, u32::from(net.prefix())))
            }
            // 非法形态在 `RouteTable::new` 已被拒；这里保守当作不命中。
            _ => None,
        }
    }
}
