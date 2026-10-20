//! 出接口路由表：最长前缀匹配，纯内存、由调用方注入。
//!
//! 本 crate 的 `crate::route` 只提供**系统路由的安装/撤销原语**，既不提供查表，
//! 也不读系统路由表；因此这里的路由表由调用方用 [`RouteTable::insert`] 显式注入。
//! 查不到出接口时调用方必须 fail-closed（[`ActiveError::NoRoute`]）。
//!
//! 前缀用 `crate::route::RouteDestination` 表示（IPv4 `/32`、IPv6 `/128` 为主机
//! 路由）；插入时校验前缀的规范形式，带主机位的前缀一律拒绝。

use std::net::IpAddr;

use crate::route::RouteDestination;
use crate::tcp::active::ActiveError;

/// 一条出接口路由：前缀 → 出接口索引 + 源地址。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// 目标前缀。
    pub prefix: RouteDestination,
    /// 出接口索引（0 表示未指定，仅作占位）。
    pub interface_index: u32,
    /// 选此路由时使用的源地址。
    pub source: IpAddr,
}

/// 路由表：按最长前缀匹配查表。
///
/// 表内容由调用方注入；本模块**不读系统路由表**、不安装路由。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteTable {
    entries: Vec<RouteEntry>,
}

impl RouteTable {
    /// 空表：任何目的地址都查不到出接口。
    pub fn new() -> Self {
        Self::default()
    }

    /// 插入一条路由。前缀非法（主机位非零 / 长度越界）时 fail-closed 拒绝。
    pub fn insert(
        &mut self,
        prefix: RouteDestination,
        interface_index: u32,
        source: IpAddr,
    ) -> Result<(), ActiveError> {
        // `RouteDestination::validate` 的错误类型属于 route 模块；这里只把
        // 「前缀非法」这一事实映射成拒绝，不改写 route 模块的语义。
        if prefix.validate().is_err() {
            return Err(ActiveError::NoRoute(prefix.network()));
        }
        self.entries.push(RouteEntry {
            prefix,
            interface_index,
            source,
        });
        Ok(())
    }

    /// 插入一条主机路由（/32 或 /128）。
    pub fn insert_host(
        &mut self,
        address: IpAddr,
        interface_index: u32,
        source: IpAddr,
    ) -> Result<(), ActiveError> {
        self.insert(RouteDestination::host(address), interface_index, source)
    }

    /// 路由条目数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 表是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 最长前缀匹配：命中返回出接口与源地址；无命中返回 `None`（调用方 fail-closed）。
    ///
    /// 前缀长者胜出；同长度时先插入者胜出（顺序确定，便于用例复现）。
    pub fn lookup(&self, destination: IpAddr) -> Option<&RouteEntry> {
        self.entries
            .iter()
            .filter(|entry| prefix_matches(entry.prefix, destination))
            .max_by_key(|entry| entry.prefix.prefix_len())
    }
}

/// 前缀是否覆盖目的地址。地址族不一致一律不匹配。
fn prefix_matches(prefix: RouteDestination, address: IpAddr) -> bool {
    match (prefix, address) {
        (
            RouteDestination::V4 {
                network,
                prefix_len,
            },
            IpAddr::V4(target),
        ) => {
            let mask = mask_v4(prefix_len);
            u32::from(network) & mask == u32::from(target) & mask
        }
        (
            RouteDestination::V6 {
                network,
                prefix_len,
            },
            IpAddr::V6(target),
        ) => {
            let mask = mask_v6(prefix_len);
            u128::from(network) & mask == u128::from(target) & mask
        }
        _ => false,
    }
}

/// IPv4 前缀掩码；`prefix_len` 已在插入时校验过范围。
fn mask_v4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    }
}

/// IPv6 前缀掩码；`prefix_len` 已在插入时校验过范围。
fn mask_v6(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> RouteTable {
        let mut routes = RouteTable::new();
        routes
            .insert_host("10.0.0.2".parse().unwrap(), 3, "10.0.0.1".parse().unwrap())
            .unwrap();
        routes
            .insert(
                RouteDestination::prefix("10.0.0.0".parse().unwrap(), 24).unwrap(),
                7,
                "10.9.9.9".parse().unwrap(),
            )
            .unwrap();
        routes
    }

    #[test]
    fn longest_prefix_match_wins() {
        let routes = table();
        let hit = routes.lookup("10.0.0.2".parse().unwrap()).unwrap();
        assert_eq!(hit.interface_index, 3);
        let hit = routes.lookup("10.0.0.9".parse().unwrap()).unwrap();
        assert_eq!(hit.interface_index, 7);
        // 超出表范围：查不到 → 调用方 fail-closed。
        assert!(routes.lookup("192.0.2.1".parse().unwrap()).is_none());
    }

    #[test]
    fn invalid_prefix_is_rejected() {
        let mut routes = RouteTable::new();
        // 主机位非零的前缀一律拒绝。
        let bad = RouteDestination::prefix("10.0.0.7".parse().unwrap(), 24);
        assert!(bad.is_err());
        assert!(routes
            .insert_host("10.0.0.1".parse().unwrap(), 1, "10.0.0.1".parse().unwrap())
            .is_ok());
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn family_mismatch_never_matches() {
        let mut routes = RouteTable::new();
        routes
            .insert_host("10.0.0.2".parse().unwrap(), 3, "10.0.0.1".parse().unwrap())
            .unwrap();
        assert!(routes.lookup("::1".parse().unwrap()).is_none());
    }
}
