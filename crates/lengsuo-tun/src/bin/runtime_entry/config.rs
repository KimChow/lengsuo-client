//! 配置形态、校验与命令行解析。
//!
//! **先校验再碰平台**：本模块只做纯内存的解析与校验，不打开任何设备、不读系统
//! 状态。任何非法输入都返回 [`ConfigError`]，绝不静默套用默认值——缺字段就是缺字段。
//!
//! 与参考实现的对照：Xray 的 `infra/conf/tun.go` 对空名字/空 MTU **静默补默认值**
//! （`xray0` / `1500`）。本入口刻意**不**这样：缺 `device_name` 或 `mtu` 一律
//! `ConfigError::Missing`，理由是本入口的调用方（测试、脚本、运维）需要知道配置
//! 到底写了什么，静默补值会让「没配」和「配了默认值」在排障时无法区分。
//! 逐条差异见分文档的「偏离清单」。

use std::net::IpAddr;

use lengsuo_tun::route::RouteDestination;
use lengsuo_tun::tcp::connector::RouteTable;

/// 默认收包超时（毫秒）。与 `ingress::IngressLimits::default` 的超时同口径。
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 10;
/// 默认出口会话表容量。与 `tcp::listener::Config::default` 的会话容量同口径。
pub const DEFAULT_SESSION_CAPACITY: usize = 1024;
/// 默认会话 TTL（毫秒）。
pub const DEFAULT_SESSION_TTL_MS: u64 = 60_000;
/// 设备名最大长度：Linux `IFNAMSIZ` 为 16，减去结尾的 NUL 即 15 个字符。
pub const MAX_DEVICE_NAME_LEN: usize = 15;
/// 最小 MTU：取 IPv6 路径 MTU 下限（`mtu::MIN_PATH_MTU_V6`），低于它连 IPv6 都发不出。
pub const MIN_MTU: u16 = 1280;
/// 最大 MTU：与 `device::DeviceConfig::MAX_MTU` 对齐（IPv4 总长字段的上界）。
pub const MAX_MTU: u16 = u16::MAX;

/// 入口配置的失败原因。全部 fail-closed：出错即中止，不降级。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// 缺少必填项。`field` 是稳定的字段名（供上层定位，不含任何凭据）。
    #[error("缺少必填项：{field}")]
    Missing { field: &'static str },
    /// MTU 越界。
    #[error("MTU {value} 非法：必须在 {min}..={max} 之间")]
    InvalidMtu { value: u16, min: u16, max: u16 },
    /// 路由前缀非法：长度越界或带主机位（不做静默归一化）。
    #[error("路由前缀非法：{prefix}/{prefix_len}")]
    InvalidRoutePrefix { prefix: IpAddr, prefix_len: u8 },
    /// 出接口索引为 0。
    #[error("出接口索引 {value} 非法：0 不是合法出接口")]
    InvalidInterfaceIndex { value: u32 },
    /// 路由前缀与源地址不在同一地址族。
    ///
    /// 字段名刻意**不叫** `source`：`thiserror` 会把名为 `source` 的字段当成
    /// 错误来源，而 `IpAddr` 不是 `std::error::Error`。
    #[error("路由前缀 {prefix:?} 与源地址 {source_address:?} 不同族")]
    RouteFamilyMismatch {
        prefix: IpAddr,
        source_address: IpAddr,
    },
    /// 命令行参数非法（不是 `key=value`、未知键、数值无法解析等）。
    #[error("命令行参数非法：{detail}")]
    InvalidArgument { detail: String },
    /// 路由表构造失败（理论上不会发生：入表前已逐条校验）。
    #[error("路由表构造失败：{detail}")]
    RouteTable { detail: String },
}

/// 一条出接口路由规则：前缀 → 出接口索引 + 源地址。
///
/// 字段与 `tcp::connector::RouteEntry` 同构，但**不依赖**它：本模块是配置的解析层，
/// 路由表的插入由 `RuntimeConfig::route_table` 完成。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRule {
    /// 目标前缀的网络地址（必须已归一化，主机位为零）。
    pub prefix: IpAddr,
    /// 前缀长度。
    pub prefix_len: u8,
    /// 出接口索引（0 非法）。
    pub interface_index: u32,
    /// 该路由使用的源地址。
    pub source: IpAddr,
}

impl RouteRule {
    /// 校验单条规则。任何一条不合法都让整份配置失败。
    pub fn validate(&self) -> Result<(), ConfigError> {
        // 前缀规范形式：带主机位一律拒绝（复用 route 模块的校验，不另写一份）。
        RouteDestination::prefix(self.prefix, self.prefix_len).map_err(|_| {
            ConfigError::InvalidRoutePrefix {
                prefix: self.prefix,
                prefix_len: self.prefix_len,
            }
        })?;
        if self.interface_index == 0 {
            return Err(ConfigError::InvalidInterfaceIndex {
                value: self.interface_index,
            });
        }
        if self.prefix.is_ipv4() != self.source.is_ipv4() {
            return Err(ConfigError::RouteFamilyMismatch {
                prefix: self.prefix,
                source_address: self.source,
            });
        }
        Ok(())
    }
}

/// 未校验的原始配置：命令行解析的产物，字段全部可选。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawConfig {
    /// TUN 设备名（必填）。
    pub device_name: Option<String>,
    /// 接口 MTU（必填）。
    pub mtu: Option<u16>,
    /// 出接口路由规则。
    pub routes: Vec<RouteRule>,
    /// 收包超时（毫秒）。
    pub read_timeout_ms: Option<u64>,
    /// 出口会话表容量。
    pub session_capacity: Option<usize>,
    /// 会话 TTL（毫秒）。
    pub session_ttl_ms: Option<u64>,
    /// 收包预算：收到这么多报文后停机（0 表示不限）。
    pub max_packets: Option<u64>,
    /// 步数预算：最多执行这么多步（0 表示不限）。
    pub max_steps: Option<u64>,
    /// 演示接线的环境号。
    pub environment: Option<u64>,
    /// 演示接线的设备号。
    pub device_id: Option<u64>,
    /// 演示接线的代次。
    pub epoch: Option<u64>,
}

impl RawConfig {
    /// 校验并转成 [`RuntimeConfig`]。任何一条不合法都返回 [`ConfigError`]。
    pub fn into_config(self) -> Result<RuntimeConfig, ConfigError> {
        let device_name = self
            .device_name
            .ok_or(ConfigError::Missing { field: "设备名" })?;
        if device_name.is_empty() || device_name.len() > MAX_DEVICE_NAME_LEN {
            return Err(ConfigError::InvalidArgument {
                detail: format!(
                    "设备名 {device_name:?} 长度非法：必须在 1..={MAX_DEVICE_NAME_LEN} 之间"
                ),
            });
        }
        let mtu = self.mtu.ok_or(ConfigError::Missing { field: "MTU" })?;
        if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
            return Err(ConfigError::InvalidMtu {
                value: mtu,
                min: MIN_MTU,
                max: MAX_MTU,
            });
        }
        for rule in &self.routes {
            rule.validate()?;
        }
        Ok(RuntimeConfig {
            device_name,
            mtu,
            routes: self.routes,
            read_timeout_ms: self.read_timeout_ms.unwrap_or(DEFAULT_READ_TIMEOUT_MS),
            session_capacity: self.session_capacity.unwrap_or(DEFAULT_SESSION_CAPACITY),
            session_ttl_ms: self.session_ttl_ms.unwrap_or(DEFAULT_SESSION_TTL_MS),
            max_packets: self.max_packets.unwrap_or(0),
            max_steps: self.max_steps.unwrap_or(0),
            environment: self.environment.unwrap_or(1),
            device_id: self.device_id.unwrap_or(1),
            epoch: self.epoch.unwrap_or(1),
        })
    }
}

/// 已校验的配置：字段都合法，可以直接拿去开设备、装路由表。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// TUN 设备名。
    pub device_name: String,
    /// 接口 MTU。
    pub mtu: u16,
    /// 出接口路由规则。
    pub routes: Vec<RouteRule>,
    /// 收包超时（毫秒）。
    pub read_timeout_ms: u64,
    /// 出口会话表容量。
    pub session_capacity: usize,
    /// 会话 TTL（毫秒）。
    pub session_ttl_ms: u64,
    /// 收包预算（0 表示不限）。
    pub max_packets: u64,
    /// 步数预算（0 表示不限）。
    pub max_steps: u64,
    /// 演示接线的环境号。
    pub environment: u64,
    /// 演示接线的设备号。
    pub device_id: u64,
    /// 演示接线的代次。
    pub epoch: u64,
}

impl RuntimeConfig {
    /// 把路由规则装进 `tcp::connector::RouteTable`。
    ///
    /// 路由表是**出接口**（网卡）的最长前缀匹配表，与出口层的协议选择是两层职责。
    /// 入表前每条规则都已校验，这里再校验一次是为了不给「绕过 `into_config` 的
    /// 手工构造」留口子——fail-closed 优先。
    pub fn route_table(&self) -> Result<RouteTable, ConfigError> {
        let mut table = RouteTable::new();
        for rule in &self.routes {
            rule.validate()?;
            let destination =
                RouteDestination::prefix(rule.prefix, rule.prefix_len).map_err(|_| {
                    ConfigError::InvalidRoutePrefix {
                        prefix: rule.prefix,
                        prefix_len: rule.prefix_len,
                    }
                })?;
            table
                .insert(destination, rule.interface_index, rule.source)
                .map_err(|error| ConfigError::RouteTable {
                    detail: error.to_string(),
                })?;
        }
        Ok(table)
    }

    /// 收包超时（毫秒）。
    #[must_use]
    pub fn read_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.read_timeout_ms)
    }
}

/// 解析命令行：`key=value` 形式。
///
/// 支持的键：`device_name`、`mtu`、`route`、`read_timeout_ms`、`session_capacity`、
/// `session_ttl_ms`、`max_packets`、`max_steps`、`environment`、`device_id`、`epoch`。
/// `route` 的值形如 `10.0.0.0/24,7,10.0.0.1`（前缀、出接口索引、源地址）。
///
/// 未知键、非 `key=value`、数值无法解析一律 [`ConfigError::InvalidArgument`]。
pub fn parse_args<I, S>(args: I) -> Result<RawConfig, ConfigError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut raw = RawConfig::default();
    for arg in args {
        let arg = arg.as_ref();
        let Some((key, value)) = arg.split_once('=') else {
            return Err(ConfigError::InvalidArgument {
                detail: format!("{arg:?} 不是 key=value 形式"),
            });
        };
        match key {
            "device_name" => raw.device_name = Some(value.to_string()),
            "mtu" => raw.mtu = Some(number(value, "MTU")?),
            "route" => raw.routes.push(parse_route(value)?),
            "read_timeout_ms" => raw.read_timeout_ms = Some(number(value, "read_timeout_ms")?),
            "session_capacity" => raw.session_capacity = Some(number(value, "session_capacity")?),
            "session_ttl_ms" => raw.session_ttl_ms = Some(number(value, "session_ttl_ms")?),
            "max_packets" => raw.max_packets = Some(number(value, "max_packets")?),
            "max_steps" => raw.max_steps = Some(number(value, "max_steps")?),
            "environment" => raw.environment = Some(number(value, "environment")?),
            "device_id" => raw.device_id = Some(number(value, "device_id")?),
            "epoch" => raw.epoch = Some(number(value, "epoch")?),
            _ => {
                return Err(ConfigError::InvalidArgument {
                    detail: format!("未知键 {key:?}"),
                })
            }
        }
    }
    Ok(raw)
}

/// 解析一个十进制数值参数。
fn number<T>(value: &str, field: &str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
{
    value
        .parse::<T>()
        .map_err(|_| ConfigError::InvalidArgument {
            detail: format!("{field} 的值 {value:?} 不是合法数值"),
        })
}

/// 解析一条路由规则：`前缀/长度,出接口索引,源地址`。
fn parse_route(value: &str) -> Result<RouteRule, ConfigError> {
    let parts: Vec<&str> = value.split(',').collect();
    if parts.len() != 3 {
        return Err(ConfigError::InvalidArgument {
            detail: format!("route {value:?} 应为 前缀/长度,出接口索引,源地址"),
        });
    }
    let (prefix, prefix_len) =
        parts[0]
            .split_once('/')
            .ok_or_else(|| ConfigError::InvalidArgument {
                detail: format!("route 前缀 {:?} 缺少 /长度", parts[0]),
            })?;
    let prefix: IpAddr = prefix.parse().map_err(|_| ConfigError::InvalidArgument {
        detail: format!("route 前缀 {prefix:?} 不是合法地址"),
    })?;
    let prefix_len: u8 = prefix_len
        .parse()
        .map_err(|_| ConfigError::InvalidArgument {
            detail: format!("route 前缀长度 {prefix_len:?} 不是合法数值"),
        })?;
    let interface_index: u32 = parts[1].parse().map_err(|_| ConfigError::InvalidArgument {
        detail: format!("route 出接口索引 {:?} 不是合法数值", parts[1]),
    })?;
    let source: IpAddr = parts[2].parse().map_err(|_| ConfigError::InvalidArgument {
        detail: format!("route 源地址 {:?} 不是合法地址", parts[2]),
    })?;
    Ok(RouteRule {
        prefix,
        prefix_len,
        interface_index,
        source,
    })
}
