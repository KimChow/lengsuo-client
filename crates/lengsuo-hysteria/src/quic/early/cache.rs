//! 0-RTT 会话票据存储与 rustls 接线。
//!
//! [`SessionCache`] 是与 rustls `ClientSessionStore` 同形的可注入抽象；
//! [`MemorySessionCache`] 提供容量可配、按服务端名 LRU 驱逐的内存实现。
//! [`configure_tls`] 在 `EarlyDataConfig::enabled` 时设置
//! `enable_early_data = true` 并把 `resumption` 换成注入的缓存；关闭时
//! **不修改**任何配置，保证既有 1-RTT 行为逐字节不变。

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use quinn::rustls::client::{
    ClientSessionStore, Resumption, Tls12ClientSessionValue, Tls13ClientSessionValue,
};
use quinn::rustls::pki_types::ServerName;
use quinn::rustls::NamedGroup;

use super::EarlyDataConfig;

/// 单个服务端名下最多保留的 TLS 1.3 票据数（服务端可下发多张）。
const MAX_TICKETS_PER_SERVER: usize = 8;

/// 可注入的会话恢复存储抽象（与 rustls `ClientSessionStore` 同形）。
///
/// 调用方可以持有一个 [`MemorySessionCache`] 并在多次连接间复用，使票据
/// 不必只存在于 rustls 内部缺省缓存中。
pub trait SessionCache: fmt::Debug + Send + Sync {
    /// 记录服务端选择的密钥交换组。
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup);
    /// 查询密钥交换组提示。
    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup>;
    /// 记录 TLS 1.2 会话。
    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue);
    /// 取 TLS 1.2 会话。
    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue>;
    /// 删除 TLS 1.2 会话。
    fn remove_tls12_session(&self, server_name: &ServerName<'static>);
    /// 追加一张 TLS 1.3 票据。
    fn insert_tls13_ticket(&self, server_name: ServerName<'static>, value: Tls13ClientSessionValue);
    /// 取走一张 TLS 1.3 票据（每张票据至多返回一次）。
    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue>;
    /// 当前记录的服务端名数量。
    fn server_count(&self) -> usize;
    /// 某服务端名下的 TLS 1.3 票据数。
    fn ticket_count(&self, server_name: &ServerName<'_>) -> usize;
    /// 清空全部票据与提示。
    fn clear(&self);
}

/// rustls `ClientSessionStore` 适配器：把注入的 [`SessionCache`] 接给
/// `rustls::client::Resumption::store`（rustls 的 trait 是外部 trait，
/// 直接为任意 `SessionCache` 做 blanket impl 会违反孤儿规则）。
#[derive(Debug)]
struct SessionCacheAdapter(Arc<dyn SessionCache>);

impl ClientSessionStore for SessionCacheAdapter {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.0.set_kx_hint(server_name, group);
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.0.kx_hint(server_name)
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.0.set_tls12_session(server_name, value);
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.0.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.0.remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        self.0.insert_tls13_ticket(server_name, value);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        self.0.take_tls13_ticket(server_name)
    }
}

#[derive(Debug, Default)]
struct CacheEntry {
    kx_hint: Option<NamedGroup>,
    tls12: Option<Tls12ClientSessionValue>,
    tickets: VecDeque<Tls13ClientSessionValue>,
}

#[derive(Debug)]
struct CacheInner {
    capacity: usize,
    /// 最近使用的服务端名在队尾（LRU 驱逐队首）。
    order: VecDeque<ServerName<'static>>,
    entries: HashMap<ServerName<'static>, CacheEntry>,
}

/// 有 LRU 语义的内存会话缓存：容量按「服务端名」计，每个服务端名最多保留
/// [`MAX_TICKETS_PER_SERVER`] 张 TLS 1.3 票据。[`Self::new`] 容量为 0 时
/// 不存储任何内容（等价于禁用恢复，`into_0rtt` 将回退 1-RTT）。
#[derive(Debug)]
pub struct MemorySessionCache {
    inner: Mutex<CacheInner>,
}

impl MemorySessionCache {
    /// 创建容量为 `capacity` 个服务端名的缓存。
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(CacheInner {
                capacity,
                order: VecDeque::new(),
                entries: HashMap::new(),
            }),
        }
    }

    /// 容量（服务端名数量）。
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.lock().expect("会话缓存锁中毒").capacity
    }

    /// 诊断用：查看最近一张 TLS 1.3 票据声明的早数据上限（不取走票据）。
    /// 返回 `0` 表示服务端票据未授予 0-RTT 权限，此时 rustls 不会产生早数据。
    #[must_use]
    pub fn ticket_max_early_data(&self, server_name: &ServerName<'_>) -> Option<u32> {
        let inner = self.inner.lock().expect("会话缓存锁中毒");
        let entry = inner.entries.get(&server_name.to_owned())?;
        entry
            .tickets
            .back()
            .map(Tls13ClientSessionValue::max_early_data_size)
    }

    /// 写入路径：必要时新建条目并按 LRU 驱逐队首，随后把该键移到队尾。
    fn write_entry(&self, server_name: &ServerName<'_>, f: impl FnOnce(&mut CacheEntry)) {
        let mut inner = self.inner.lock().expect("会话缓存锁中毒");
        if inner.capacity == 0 {
            return;
        }
        let key = server_name.to_owned();
        if !inner.entries.contains_key(&key) {
            if inner.entries.len() >= inner.capacity {
                if let Some(evicted) = inner.order.pop_front() {
                    inner.entries.remove(&evicted);
                }
            }
            inner.entries.insert(key.clone(), CacheEntry::default());
        }
        touch(&mut inner.order, &key);
        f(inner.entries.get_mut(&key).expect("刚插入或已存在的条目"));
    }

    /// 读取路径：未命中返回 `None`，**不**创建条目、不驱逐其他条目。
    fn read_entry<R>(
        &self,
        server_name: &ServerName<'_>,
        f: impl FnOnce(&mut CacheEntry) -> R,
    ) -> Option<R> {
        let mut inner = self.inner.lock().expect("会话缓存锁中毒");
        if inner.capacity == 0 {
            return None;
        }
        let key = server_name.to_owned();
        if !inner.entries.contains_key(&key) {
            return None;
        }
        touch(&mut inner.order, &key);
        inner.entries.get_mut(&key).map(f)
    }
}

fn touch(order: &mut VecDeque<ServerName<'static>>, key: &ServerName<'static>) {
    if let Some(pos) = order.iter().position(|k| k == key) {
        order.remove(pos);
    }
    order.push_back(key.clone());
}

impl SessionCache for MemorySessionCache {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.write_entry(&server_name, |e| e.kx_hint = Some(group));
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.read_entry(server_name, |e| e.kx_hint).flatten()
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.write_entry(&server_name, |e| e.tls12 = Some(value));
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.read_entry(server_name, |e| e.tls12.clone()).flatten()
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.write_entry(server_name, |e| e.tls12 = None);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        self.write_entry(&server_name, |e| {
            e.tickets.push_back(value);
            while e.tickets.len() > MAX_TICKETS_PER_SERVER {
                e.tickets.pop_front();
            }
        });
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        // 每张票据至多返回一次（rustls 契约）：取走后不归还。
        self.read_entry(server_name, |e| e.tickets.pop_back())
            .flatten()
    }

    fn server_count(&self) -> usize {
        self.inner.lock().expect("会话缓存锁中毒").entries.len()
    }

    fn ticket_count(&self, server_name: &ServerName<'_>) -> usize {
        self.inner
            .lock()
            .expect("会话缓存锁中毒")
            .entries
            .get(&server_name.to_owned())
            .map_or(0, |e| e.tickets.len())
    }

    fn clear(&self) {
        let mut inner = self.inner.lock().expect("会话缓存锁中毒");
        inner.order.clear();
        inner.entries.clear();
    }
}

/// 0-RTT 配置错误（仅在启用时校验）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EarlyDataError {
    /// 启用 0-RTT 但没有可用的会话缓存。
    #[error("启用 0-RTT 需要会话缓存（SessionCache）")]
    MissingSessionCache,
    /// 预算为 0 但仍要求发送早数据属于配置矛盾。
    #[error("max_early_data 为 0：禁止发送任何早数据，请改用 enabled = false")]
    ZeroEarlyDataBudget,
}

/// 把 0-RTT 设置接入 rustls 客户端配置：
/// `enable_early_data = true`，并把 `resumption` 换为注入的 [`SessionCache`]。
/// `enabled = false` 时**不修改** `tls`（保持既有 1-RTT 行为完全不变）。
pub fn configure_tls(
    tls: &mut quinn::rustls::ClientConfig,
    config: &EarlyDataConfig,
    cache: Option<Arc<dyn SessionCache>>,
) -> Result<(), EarlyDataError> {
    if !config.enabled {
        return Ok(());
    }
    if config.max_early_data == Some(0) {
        return Err(EarlyDataError::ZeroEarlyDataBudget);
    }
    let cache = cache.ok_or(EarlyDataError::MissingSessionCache)?;
    tls.enable_early_data = true;
    tls.resumption = Resumption::store(Arc::new(SessionCacheAdapter(cache)));
    Ok(())
}
