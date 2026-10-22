//! 配置加载：TOML → [`ClientConfig`]，含全部校验。
//!
//! 语义对齐参考实现 `crates/ss-client/src/config.rs`（原 504 行死代码）：
//! 同样的字段、同样的默认值、同样的 `direct` / `proxy` 动作集合，
//! 外加**收紧**的部分（见 `docs/ss-client-config-activate.md` 偏离清单）。

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use crate::config::matcher::Cidr;
use crate::config::ss_url::validate_ss_url;
use crate::config::toml::{self, Value};
use crate::config::types::{
    normalized_networks, normalized_protocols, parse_ips, parse_port_spec, Action, ClientConfig,
    DnsConfig, Match, MuxConfig, OutboundConfig, Rule, DOMAIN_MODES, MATCH_FIELDS,
};
use crate::error::{ConfigError, Error, Result};

/// 从文件加载配置。
pub fn load_config(path: &str) -> Result<ClientConfig> {
    if path.trim().is_empty() {
        return Err(ConfigError::Invalid {
            field: "config.path",
            reason: "config path must not be empty".to_owned(),
        }
        .into());
    }
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })?;
    let root = toml::parse(&text).map_err(|err| ConfigError::ParseFile {
        path: path.to_owned(),
        reason: err.to_string(),
    })?;
    let config = from_table(&root)?;
    validate(&config)?;
    Ok(config)
}

/// 从内存文本加载配置。
pub fn load_config_str(text: &str) -> Result<ClientConfig> {
    let root = toml::parse(text).map_err(|err| ConfigError::Parse {
        reason: err.to_string(),
    })?;
    let config = from_table(&root)?;
    validate(&config)?;
    Ok(config)
}

/// 顶层表 → 客户端配置。
fn from_table(root: &BTreeMap<String, Value>) -> Result<ClientConfig> {
    let outbound = build_outbound(root.get("outbound"))?;
    let dns = build_dns(root.get("dns"))?;
    let rules = build_rules(root.get("rules"))?;
    let fallback = match root.get("fallback") {
        None => Action::Proxy,
        Some(value) => Action::parse("fallback", value.str_field("fallback")?)?,
    };
    let direct_allow_private = match root.get("direct_allow_private") {
        None => true,
        Some(value) => value.bool_field("direct_allow_private")?,
    };
    Ok(ClientConfig {
        outbound,
        dns,
        rules,
        fallback,
        direct_allow_private,
        geoip_dir: opt_path(root.get("geoip_dir"), "geoip_dir")?,
        geosite_dir: opt_path(root.get("geosite_dir"), "geosite_dir")?,
    })
}

/// `[outbound]` 段。`ss_url` 是**必填项**（缺失即 `Err`，不兜底）。
fn build_outbound(value: Option<&Value>) -> Result<OutboundConfig> {
    let Some(value) = value else {
        return Err(ConfigError::Missing("outbound").into());
    };
    let table = value.table_field("outbound")?;
    let ss_url = match table.get("ss_url") {
        None => return Err(ConfigError::Missing("outbound.ss_url").into()),
        Some(value) => value.str_field("outbound.ss_url")?.to_owned(),
    };
    let udp = match table.get("udp") {
        None => false,
        Some(value) => value.bool_field("outbound.udp")?,
    };
    let mux = build_mux(table.get("mux"))?;
    let connect_timeout_ms = match table.get("connect_timeout_ms") {
        None => 5_000,
        Some(value) => {
            let ms = value.int_field("outbound.connect_timeout_ms")?;
            if ms < 0 {
                return Err(invalid(
                    "outbound.connect_timeout_ms",
                    "must not be negative",
                ));
            }
            ms as u64
        }
    };
    Ok(OutboundConfig {
        ss_url,
        udp,
        mux,
        connect_timeout_ms,
    })
}

/// `[outbound.mux]` 段。
fn build_mux(value: Option<&Value>) -> Result<MuxConfig> {
    let Some(value) = value else {
        return Ok(MuxConfig::default());
    };
    let table = value.table_field("outbound.mux")?;
    let enabled = match table.get("enabled") {
        None => false,
        Some(value) => value.bool_field("outbound.mux.enabled")?,
    };
    let max_connections = match table.get("max_connections") {
        None => 8,
        Some(value) => {
            let n = value.int_field("outbound.mux.max_connections")?;
            if n < 0 {
                return Err(invalid(
                    "outbound.mux.max_connections",
                    "must not be negative",
                ));
            }
            n as usize
        }
    };
    Ok(MuxConfig {
        enabled,
        max_connections,
    })
}

/// `[dns]` 段（整段可省）。
fn build_dns(value: Option<&Value>) -> Result<DnsConfig> {
    let Some(value) = value else {
        return Ok(DnsConfig {
            direct_use_system: true,
            ..DnsConfig::default()
        });
    };
    let table = value.table_field("dns")?;
    let direct = parse_ips(&toml::string_list(table.get("direct"), "dns.direct")?)?;
    let proxy = parse_ips(&toml::string_list(table.get("proxy"), "dns.proxy")?)?;
    let direct_use_system = match table.get("direct_use_system") {
        None => true,
        Some(value) => value.bool_field("dns.direct_use_system")?,
    };
    Ok(DnsConfig {
        direct,
        proxy,
        direct_use_system,
    })
}

/// `rules` 段：规则数组。
fn build_rules(value: Option<&Value>) -> Result<Vec<Rule>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let items = value.array_field("rules")?;
    let mut rules = Vec::with_capacity(items.len());
    for item in items {
        rules.push(build_rule(item)?);
    }
    Ok(rules)
}

/// 单条规则。
fn build_rule(value: &Value) -> Result<Rule> {
    let table = value.table_field("rules")?;
    let name_raw = match table.get("name") {
        None => return Err(ConfigError::Missing("rules.name").into()),
        Some(value) => value.str_field("rules.name")?,
    };
    let name = name_raw.trim().to_ascii_lowercase();
    if name.is_empty() {
        return Err(invalid("rules.name", "rule name must not be empty"));
    }
    let action_raw = match table.get("action") {
        None => return Err(ConfigError::Missing("rules.action").into()),
        Some(value) => value.str_field("rules.action")?,
    };
    let action = Action::parse("rules.action", action_raw)?;
    let empty = BTreeMap::new();
    let fields = match table.get("match") {
        None => &empty,
        Some(value) => value.table_field("rules.match")?,
    };
    // `match` 段是白名单：出现未知字段即拒绝（fail-closed）。
    for key in fields.keys() {
        if !MATCH_FIELDS.contains(&key.as_str()) {
            return Err(invalid(
                "rules.match",
                &format!("rule `{name}` has unknown match field `{key}`"),
            ));
        }
    }
    let domain_mode = match fields.get("domain_mode") {
        None => None,
        Some(value) => {
            let mode = value.str_field("rules.match.domain_mode")?;
            if !DOMAIN_MODES.contains(&mode) {
                return Err(invalid(
                    "rules.match.domain_mode",
                    &format!(
                        "rule `{name}` domain_mode must be plain, keyword, mapping or any, got `{mode}`"
                    ),
                ));
            }
            Some(mode.to_owned())
        }
    };
    let match_ = Match {
        network: normalized_networks(
            toml::string_list(fields.get("network"), "rules.match.network")?,
            &name,
        )?,
        domain_mode,
        domain: toml::string_list(fields.get("domain"), "rules.match.domain")?
            .into_iter()
            .map(|item| item.trim().to_ascii_lowercase())
            .collect(),
        ip: toml::string_list(fields.get("ip"), "rules.match.ip")?,
        port: toml::string_list(fields.get("port"), "rules.match.port")?
            .iter()
            .map(|spec| parse_port_spec(spec))
            .collect::<Result<Vec<_>>>()?,
        process: toml::string_list(fields.get("process"), "rules.match.process")?
            .into_iter()
            .map(|item| item.trim().to_ascii_lowercase())
            .collect(),
        protocol: normalized_protocols(
            toml::string_list(fields.get("protocol"), "rules.match.protocol")?,
            &name,
        )?,
    };
    // IP 约束必须是合法 IP / CIDR（主机位非零即拒绝）。
    for spec in &match_.ip {
        Cidr::parse(spec)?;
    }
    Ok(Rule {
        name,
        action,
        match_,
        max_download_kbps: opt_u32(table, "max_download_kbps")?,
        per_conn_download_kbps: opt_u32(table, "per_conn_download_kbps")?,
        max_concurrent: opt_usize(table, "max_concurrent")?,
    })
}

/// 带宽上限：0 表示不限制；取值上限是类型本身（`u32` / `usize`），
/// 超出即 `Err`（不做静默截断）。
fn opt_u32(table: &BTreeMap<String, Value>, field: &'static str) -> Result<u32> {
    match table.get(field) {
        None => Ok(0),
        Some(value) => {
            let n = value.int_field(field)?;
            u32::try_from(n).map_err(|_| invalid(field, "must be in 0..=4294967295"))
        }
    }
}

/// 并发上限：0 表示不限制。
fn opt_usize(table: &BTreeMap<String, Value>, field: &'static str) -> Result<usize> {
    match table.get(field) {
        None => Ok(0),
        Some(value) => {
            let n = value.int_field(field)?;
            usize::try_from(n).map_err(|_| invalid(field, "must not be negative"))
        }
    }
}

/// 目录路径（可省）。
fn opt_path(value: Option<&Value>, field: &'static str) -> Result<Option<PathBuf>> {
    match value {
        None => Ok(None),
        Some(value) => Ok(Some(PathBuf::from(value.str_field(field)?))),
    }
}

/// 整体校验：跨字段的一致性。
fn validate(config: &ClientConfig) -> Result<()> {
    validate_ss_url(&config.outbound.ss_url)?;
    let mut names = HashSet::new();
    for rule in &config.rules {
        if !names.insert(rule.name.clone()) {
            return Err(ConfigError::DuplicateRule(rule.name.clone()).into());
        }
        if rule.action == Action::Direct
            && config.dns.direct.is_empty()
            && !config.dns.direct_use_system
        {
            return Err(invalid(
                "rules.action",
                &format!(
                    "rule `{}` is direct but dns.direct is empty and dns.direct_use_system is false",
                    rule.name
                ),
            ));
        }
    }
    Ok(())
}

/// 形状错误：只说字段与形状，不回显取值。
fn invalid(field: &'static str, reason: &str) -> Error {
    ConfigError::Invalid {
        field,
        reason: reason.to_owned(),
    }
    .into()
}
