//! 路由目标前缀：平台无关的构造与规范形式校验。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::RouteError;

/// 一条路由目标：IPv4/IPv6 网段前缀，主机路由即 `/32`、`/128`。
///
/// 字段公开是为了让调用方直接构造常量；但 [`super::RouteManager::install`] 与
/// [`super::RouteManager::dry_run`] 都会重新校验，公开字段不能绕过 fail-closed
/// 检查（例如手工构造带主机位的「前缀」会在 [`super::RouteSpec::validate`] 被拒）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteDestination {
    /// IPv4 目标网段。
    V4 { network: Ipv4Addr, prefix_len: u8 },
    /// IPv6 目标网段。
    V6 { network: Ipv6Addr, prefix_len: u8 },
}

impl RouteDestination {
    /// 主机路由：IPv4 为 `/32`，IPv6 为 `/128`。
    #[must_use]
    pub fn host(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(v4) => Self::V4 {
                network: v4,
                prefix_len: 32,
            },
            IpAddr::V6(v6) => Self::V6 {
                network: v6,
                prefix_len: 128,
            },
        }
    }

    /// 网段路由。主机位必须为零：本层不做静默归一化，带主机位的前缀一律拒绝。
    pub fn prefix(address: IpAddr, prefix_len: u8) -> Result<Self, RouteError> {
        let destination = match address {
            IpAddr::V4(v4) => Self::V4 {
                network: v4,
                prefix_len,
            },
            IpAddr::V6(v6) => Self::V6 {
                network: v6,
                prefix_len,
            },
        };
        destination.validate()?;
        Ok(destination)
    }

    /// 目标网络地址。
    #[must_use]
    pub fn network(self) -> IpAddr {
        match self {
            Self::V4 { network, .. } => IpAddr::V4(network),
            Self::V6 { network, .. } => IpAddr::V6(network),
        }
    }

    /// 前缀长度。
    #[must_use]
    pub fn prefix_len(self) -> u8 {
        match self {
            Self::V4 { prefix_len, .. } | Self::V6 { prefix_len, .. } => prefix_len,
        }
    }

    /// 协议族名称，仅用于错误信息。
    #[must_use]
    pub fn family(self) -> &'static str {
        match self {
            Self::V4 { .. } => "IPv4",
            Self::V6 { .. } => "IPv6",
        }
    }

    /// 是否缺省路由（`0.0.0.0/0` 或 `::/0`）。
    #[must_use]
    pub fn is_default(self) -> bool {
        self.prefix_len() == 0
    }

    /// `netsh` 接受的目标写法：`<network>/<prefix>`。
    #[must_use]
    pub fn netsh_prefix(self) -> String {
        format!("{}/{}", self.network(), self.prefix_len())
    }

    /// 校验前缀长度与前缀的规范形式（主机位必须为零）。
    pub fn validate(self) -> Result<(), RouteError> {
        match self {
            Self::V4 {
                network,
                prefix_len,
            } => {
                if prefix_len > 32 {
                    return Err(RouteError::InvalidPrefix {
                        family: "IPv4",
                        prefix_len,
                        max: 32,
                    });
                }
                let mask = v4_mask(prefix_len);
                if u32::from(network) & mask != u32::from(network) {
                    return Err(RouteError::HostBitsSet {
                        address: IpAddr::V4(network),
                        prefix_len,
                    });
                }
                Ok(())
            }
            Self::V6 {
                network,
                prefix_len,
            } => {
                if prefix_len > 128 {
                    return Err(RouteError::InvalidPrefix {
                        family: "IPv6",
                        prefix_len,
                        max: 128,
                    });
                }
                let mask = v6_mask(prefix_len);
                if u128::from(network) & mask != u128::from(network) {
                    return Err(RouteError::HostBitsSet {
                        address: IpAddr::V6(network),
                        prefix_len,
                    });
                }
                Ok(())
            }
        }
    }
}

/// IPv4 前缀掩码；调用方必须先确认 `prefix_len <= 32`。
pub(super) fn v4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    }
}

/// IPv6 前缀掩码；调用方必须先确认 `prefix_len <= 128`。
pub(super) fn v6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_cover_edges() {
        assert_eq!(v4_mask(0), 0);
        assert_eq!(v4_mask(32), u32::MAX);
        assert_eq!(v4_mask(24), 0xffff_ff00);
        assert_eq!(v6_mask(0), 0);
        assert_eq!(v6_mask(128), u128::MAX);
        assert_eq!(v6_mask(64), u128::MAX << 64);
    }

    #[test]
    fn prefix_rejects_host_bits_and_overflow() {
        let host_bits = RouteDestination::prefix("192.0.2.7".parse().unwrap(), 24);
        assert!(matches!(host_bits, Err(RouteError::HostBitsSet { .. })));
        let overflow = RouteDestination::prefix("::1".parse().unwrap(), 129);
        assert!(matches!(
            overflow,
            Err(RouteError::InvalidPrefix { family: "IPv6", .. })
        ));
        assert!(RouteDestination::prefix("192.0.2.0".parse().unwrap(), 24).is_ok());
    }
}
