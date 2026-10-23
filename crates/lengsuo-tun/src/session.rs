//! 通用五元组会话表：容量与 TTL 参数化，过期由调用方时钟驱动，拒绝时 fail-closed。
//!
//! 键为（协议、源地址、源端口、目的地址、目的端口）；IPv4 与 IPv6 地址共用同一套键，
//! 值类型是泛型 `V`，本模块不解释其含义，也不做任何协议解析。
//!
//! 表内不调用系统时钟、不做网络 IO：每次操作都要求调用方传入单调时钟刻度 `now`
//! （单位毫秒），因此过期行为完全确定、可纯内存测试。
//!
//! 语义要点：
//! - 容量满时拒绝**新**会话并返回 [`OpenError::Capacity`]，把值原样交还调用方，
//!   绝不随机或按序驱逐既有条目（fail-closed）。
//! - 插入与命中都会把该条目的过期时间刷新为 `now + ttl`（饱和加法，不回绕）。
//! - 命中一条已过期的条目按未命中处理，并在该次操作里就地回收这一条目；
//!   这只影响被访问的键，不构成对其它会话的驱逐。
//! - 全部键含 IPv4/IPv6 两种地址族都可插入与查找；哈希、比较与移除都走标准库
//!   带检查的接口，任何入参都不触发 panic，也不使用 `unsafe`。

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use crate::packet::{PacketInfo, Transport};

/// 单调时钟刻度，单位毫秒。由调用方提供，本模块不做任何系统调用。
pub type Clock = u64;

/// 会话表的拒绝原因。目前只有一种：容量已满。
pub enum OpenError<V> {
    /// 表已达 `capacity` 且键不存在：拒绝新会话，不驱逐任何既有条目，
    /// 待插入的值原样交还调用方。
    Capacity { capacity: usize, value: V },
}

impl<V> OpenError<V> {
    /// 取回被拒绝的值，便于调用方释放或改走其它路径。
    pub fn into_value(self) -> V {
        match self {
            OpenError::Capacity { value, .. } => value,
        }
    }

    /// 触发拒绝的容量上限。
    pub fn capacity(&self) -> usize {
        match self {
            OpenError::Capacity { capacity, .. } => *capacity,
        }
    }
}

impl<V> fmt::Display for OpenError<V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Capacity { capacity, .. } => write!(
                formatter,
                "会话表已达上限 {capacity}，拒绝新会话且不驱逐既有条目"
            ),
        }
    }
}

impl<V> fmt::Debug for OpenError<V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // V 不要求 Debug（载荷可能含隐私），只输出结构。
        match self {
            OpenError::Capacity { capacity, .. } => formatter
                .debug_struct("OpenError::Capacity")
                .field("capacity", capacity)
                .finish(),
        }
    }
}

impl<V> fmt::Debug for SessionTable<V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTable")
            .field("len", &self.entries.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl<V> std::error::Error for OpenError<V> {}

/// 有向的五元组会话键：协议、源地址端口、目的地址端口。
///
/// `(A→B)` 与 `(B→A)` 是两个不同的键，[`SessionKey::reversed`] 供上层显式换算回程键。
/// 两端地址族允许不一致（IPv4 与 IPv6 混合的键同样只作哈希与比较），本模块不因
/// 地址族差异而拒绝或 panic。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey {
    protocol: Transport,
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
}

impl SessionKey {
    pub fn new(
        protocol: Transport,
        source: IpAddr,
        source_port: u16,
        destination: IpAddr,
        destination_port: u16,
    ) -> Self {
        Self {
            protocol,
            source,
            source_port,
            destination,
            destination_port,
        }
    }

    /// 由 [`packet::inspect`] 已核对的元数据构造键，避免调用方逐字段搬运。
    pub fn from_info(info: PacketInfo) -> Self {
        Self::new(
            info.protocol,
            info.source,
            info.source_port,
            info.destination,
            info.destination_port,
        )
    }

    /// 反向键：源与目的（地址和端口）互换，协议不变。
    pub fn reversed(&self) -> Self {
        Self::new(
            self.protocol,
            self.destination,
            self.destination_port,
            self.source,
            self.source_port,
        )
    }

    pub fn protocol(&self) -> Transport {
        self.protocol
    }

    pub fn source(&self) -> IpAddr {
        self.source
    }

    pub fn source_port(&self) -> u16 {
        self.source_port
    }

    pub fn destination(&self) -> IpAddr {
        self.destination
    }

    pub fn destination_port(&self) -> u16 {
        self.destination_port
    }
}

/// 一条会话：值与绝对过期刻度。
struct EntryOf<V> {
    value: V,
    expires_at: Clock,
}

impl<V> EntryOf<V> {
    /// 过期判定：`expires_at <= now` 视为过期，即 TTL 恰好到点即失效。
    fn expired(&self, now: Clock) -> bool {
        self.expires_at <= now
    }

    fn refresh(&mut self, now: Clock, ttl: Clock) {
        self.expires_at = now.saturating_add(ttl);
    }
}

/// 泛型五元组会话表。
pub struct SessionTable<V> {
    entries: HashMap<SessionKey, EntryOf<V>>,
    capacity: usize,
    ttl: Clock,
}

impl<V> SessionTable<V> {
    /// 建立容量上限为 `capacity`、每条目存活 `ttl` 毫秒的表。
    /// `capacity` 为 0 时表永远拒绝新会话（同样是 fail-closed，不驱逐）。
    pub fn new(capacity: usize, ttl: Clock) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity.min(1024)),
            capacity,
            ttl,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn ttl(&self) -> Clock {
        self.ttl
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 还可容纳的新会话数；已过期但未被 `gc` 或访问回收的条目仍占用额度。
    pub fn remaining(&self) -> usize {
        self.capacity.saturating_sub(self.entries.len())
    }

    /// 键是否占着条目（含已过期未回收的）。用于观察占用，不代表会话仍可用。
    pub fn contains(&self, key: SessionKey) -> bool {
        self.entries.contains_key(&key)
    }

    /// 打开会话：新键在容量内插入；容量满则拒绝且不驱逐；已有键覆盖旧值并刷新 TTL。
    ///
    /// 覆盖是显式语义：同一键重复 `open` 不增加条目数，旧值被丢弃。
    pub fn open(&mut self, key: SessionKey, value: V, now: Clock) -> Result<&mut V, OpenError<V>> {
        self.take_if_expired(&key, now);
        let ttl = self.ttl;
        let expires_at = now.saturating_add(ttl);
        // 容量判定在不持有条目借用时完成：满表且键不存在 → 拒绝不驱逐。
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            return Err(OpenError::Capacity {
                capacity: self.capacity,
                value,
            });
        }
        match self.entries.get_mut(&key) {
            Some(entry) => {
                entry.value = value;
                entry.expires_at = expires_at;
            }
            None => {
                self.entries.insert(key, EntryOf { value, expires_at });
            }
        }
        let entry = self.entries.get_mut(&key).expect("条目刚已确保存在");
        Ok(&mut entry.value)
    }

    /// 命中并刷新 TTL；未命中或已过期返回 `None`（过期条目顺带回收）。
    pub fn get(&mut self, key: SessionKey, now: Clock) -> Option<&mut V> {
        self.take_if_expired(&key, now);
        let ttl = self.ttl;
        let entry = self.entries.get_mut(&key)?;
        entry.refresh(now, ttl);
        Some(&mut entry.value)
    }

    /// 只读查询，不刷新 TTL；已过期的条目按不存在处理，但不回收。
    pub fn peek(&self, key: SessionKey, now: Clock) -> Option<&V> {
        match self.entries.get(&key) {
            Some(entry) if !entry.expired(now) => Some(&entry.value),
            _ => None,
        }
    }

    /// 显式关闭会话并取回值，与是否过期无关。
    pub fn close(&mut self, key: SessionKey) -> Option<V> {
        self.entries.remove(&key).map(|entry| entry.value)
    }

    /// 按谓词移出会话并返回「键 + 值」（顺序不保证），与是否过期无关。
    ///
    /// 谓词只看到键与值，看不到过期刻度：本模块不做任何外部状态判定，
    /// 「设备断开」等失效原因由调用方用自己的谓词表达。空表或没有命中时返回空
    /// `Vec`，不 panic。
    pub fn drain_where(&mut self, pred: impl Fn(&SessionKey, &V) -> bool) -> Vec<(SessionKey, V)> {
        let keys: Vec<SessionKey> = self
            .entries
            .iter()
            .filter(|(key, entry)| pred(key, &entry.value))
            .map(|(key, _)| *key)
            .collect();
        let mut drained = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(entry) = self.entries.remove(&key) {
                drained.push((key, entry.value));
            }
        }
        drained
    }

    /// 回收所有过期条目，返回被回收的值（顺序不保证）。
    pub fn gc(&mut self, now: Clock) -> Vec<V> {
        let expired: Vec<SessionKey> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expired(now))
            .map(|(key, _)| *key)
            .collect();
        let mut drained = Vec::with_capacity(expired.len());
        for key in expired {
            if let Some(entry) = self.entries.remove(&key) {
                drained.push(entry.value);
            }
        }
        drained
    }

    /// 就地回收单个过期键：只影响被访问的键，不触碰其它会话。
    fn take_if_expired(&mut self, key: &SessionKey, now: Clock) {
        let expired = self
            .entries
            .get(key)
            .is_some_and(|entry| entry.expired(now));
        if expired {
            self.entries.remove(key);
        }
    }
}
