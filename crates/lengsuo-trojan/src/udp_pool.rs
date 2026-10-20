//! UDP 会话池：按**目标地址**复用出站 `UdpSocket`（NAT 会话映射）。
//!
//! 参考基线：Xray v26.3.27（commit `d2758a0`），`proxy/trojan/server.go:247-320`
//! 的 `handleUDPPayload` 与 `transport/internet/udp/dispatcher.go`：
//! - 参考 `udp.NewDispatcher(dispatcher, 回程回调)` 按目标复用出站链路；本模块落成
//!   **按目标地址索引的 socket 映射**：同目标多包复用同一 socket，不同目标不同 socket。
//! - 参考 `signal.CancelAfterInactivity(ctx, entry.terminate, time.Minute)` ⇒ 本模块的
//!   **条目空闲回收**（到点移除条目、socket 真正释放）。
//! - 参考 `defer udpServer.RemoveRay()` ⇒ 本模块的 `close()`（显式释放全部 socket）。
//! - 参考 `if !s.cone || dest == nil { dest = &destination }` ⇒ 本模块的 `cone` 模式：
//!   首包目标固定，**后续包自身的目标被忽略**（参考语义，不是 bug）。
//!
//! 并发：表结构由 `StdMutex` 保护，**锁内不做 IO**；建表路径用独立的创建锁串行，
//! 保证同一目标**只绑定一个** socket；同目标的发送按条目内锁串行；每个条目一个
//! 读任务，回程经有界队列回到调用方，队列满则丢弃该数据报（对齐参考
//! `dispatcherConn.callback` 的 `default:` 分支）并计数。
//!
//! 错误信息只含目标地址、计数与 IO 原因，不含口令、密钥与载荷明文。

mod entry;
mod types;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use ss_core::target::TargetAddr;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Mutex as AsyncMutex};

use entry::{spawn_reader, Entry};
pub use types::{Dispatch, Error, Inbound, PoolConfig};

/// 默认条目空闲回收阈值（对齐参考 `policy.SessionDefault()` 的 `ConnectionIdle`
/// = 300 秒）。
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// 池条目上界默认值（每条目一个出站 socket）。
pub const DEFAULT_MAX_ENTRIES: usize = 64;

/// 回程队列容量（对齐参考 `dispatcherConn.cache` 的有界缓存：满则丢弃）。
pub const DEFAULT_INBOUND_CAPACITY: usize = 256;

/// 出站 DNS 解析的截止上限。
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// 池内部状态。
struct Inner {
    config: PoolConfig,
    /// 目标地址 → 出站条目。锁只保护表结构，IO 一律在锁外。
    table: StdMutex<HashMap<TargetAddr, Arc<Entry>>>,
    /// cone 模式固定的首包目标。
    cone_dest: StdMutex<Option<TargetAddr>>,
    /// 建表串行锁：保证同一目标只绑定一个 socket（表锁之外的独立锁）。
    create_lock: AsyncMutex<()>,
    /// 回程队列发送端（克隆给各条目的读任务）。
    inbound_tx: mpsc::Sender<Inbound>,
    /// 回程队列接收端（调用方消费）。
    inbound_rx: AsyncMutex<mpsc::Receiver<Inbound>>,
    /// 当前存活的出站 socket 数（条目关闭后归零）。
    live_sockets: Arc<AtomicUsize>,
    /// 累计建立的出站 socket 数（含已回收的）。
    created_sockets: AtomicUsize,
    /// 因回程队列满而丢弃的数据报数。
    dropped_replies: Arc<AtomicUsize>,
    /// 活跃序号分配器（LRU 排序键，单调递增）。
    activity_seq: Arc<AtomicU64>,
    /// 池是否已关闭。
    closed: AtomicBool,
    /// 时间基准。
    epoch: Instant,
    /// 空闲回收任务句柄。
    reaper: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    /// 关闭信号：置位后回程队列消费者随即拿到 `None`。
    shutdown: watch::Sender<bool>,
}

impl Inner {
    /// 取表锁；中毒时取回内部状态（锁内不做 IO，不会 panic）。
    fn table(&self) -> MutexGuard<'_, HashMap<TargetAddr, Arc<Entry>>> {
        self.table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 池是否已关闭。
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// 回收空闲超时的条目，返回回收条数。
    fn reap_expired(&self) -> usize {
        let now = self.epoch.elapsed().as_millis() as u64;
        let idle = self.config.idle_timeout.as_millis() as u64;
        let expired: Vec<Arc<Entry>> = {
            let mut table = self.table();
            let keys: Vec<TargetAddr> = table
                .iter()
                .filter(|(_, entry)| now.saturating_sub(entry.last_active()) >= idle)
                .map(|(key, _)| key.clone())
                .collect();
            keys.into_iter()
                .filter_map(|key| table.remove(&key))
                .collect()
        };
        // 关闭在锁外做：读任务退出后 socket 随条目析构释放。
        for entry in &expired {
            entry.close();
        }
        expired.len()
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(handle) = self
            .reaper
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            handle.abort();
        }
        for entry in self.table().values() {
            entry.close();
        }
    }
}

/// UDP 会话池：按目标地址复用出站 socket，条目可被空闲回收或显式关闭。
pub struct UdpPool {
    inner: Arc<Inner>,
}

impl UdpPool {
    /// 新建一个池。`config` 非法（零时长/零上界）时直接拒绝，不建池。
    pub fn new(config: PoolConfig) -> Result<Self, Error> {
        config.validate()?;
        let (tx, rx) = mpsc::channel(DEFAULT_INBOUND_CAPACITY);
        let (shutdown, _) = watch::channel(false);
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                table: StdMutex::new(HashMap::new()),
                cone_dest: StdMutex::new(None),
                create_lock: AsyncMutex::new(()),
                inbound_tx: tx,
                inbound_rx: AsyncMutex::new(rx),
                live_sockets: Arc::new(AtomicUsize::new(0)),
                created_sockets: AtomicUsize::new(0),
                dropped_replies: Arc::new(AtomicUsize::new(0)),
                activity_seq: Arc::new(AtomicU64::new(0)),
                closed: AtomicBool::new(false),
                epoch: Instant::now(),
                reaper: StdMutex::new(None),
                shutdown,
            }),
        })
    }

    /// 当前池配置。
    #[must_use]
    pub fn config(&self) -> PoolConfig {
        self.inner.config
    }

    /// 池内条目数。
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.inner.table().len()
    }

    /// 当前存活的出站 socket 数（条目被关闭后归零）。
    #[must_use]
    pub fn live_sockets(&self) -> usize {
        self.inner.live_sockets.load(Ordering::SeqCst)
    }

    /// 累计建立的出站 socket 数。
    #[must_use]
    pub fn created_sockets(&self) -> usize {
        self.inner.created_sockets.load(Ordering::SeqCst)
    }

    /// 因回程队列满而丢弃的数据报数。
    #[must_use]
    pub fn dropped_replies(&self) -> usize {
        self.inner.dropped_replies.load(Ordering::SeqCst)
    }

    /// 池是否已关闭。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// 投递一个数据报到目标地址；同一目标复用同一 socket。
    ///
    /// cone 模式下首包目标被固定，后续包**自身的目标被忽略**（参考语义）。
    pub async fn dispatch(&self, target: &TargetAddr, payload: &[u8]) -> Result<Dispatch, Error> {
        if self.inner.is_closed() {
            return Err(Error::Closed);
        }
        let limit = self.inner.config.payload_limit;
        if limit != 0 && payload.len() > limit {
            return Err(Error::Oversize(payload.len()));
        }
        let effective = self.effective_target(target);
        let (entry, reused) = self.ensure_entry(&effective).await?;
        entry.send(payload).await?;
        Ok(Dispatch {
            target: effective,
            reused,
        })
    }

    /// 收取一个回程数据报；池关闭或队列关闭时返回 `None`。
    pub async fn recv(&self) -> Option<Inbound> {
        let mut rx = self.inner.inbound_rx.lock().await;
        rx.recv().await
    }

    /// 立即回收所有空闲超时的条目，返回回收条数。
    pub fn reap_expired(&self) -> usize {
        self.inner.reap_expired()
    }

    /// 显式关闭池：释放全部出站 socket 并停止回程队列。
    ///
    /// 关闭后 `dispatch` 立即返回 `Error::Closed`，等待中的 `recv` 拿到 `None`。
    pub async fn close(&self) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let entries: Vec<Arc<Entry>> = self.inner.table().drain().map(|(_, e)| e).collect();
        for entry in &entries {
            entry.close();
        }
        // 关闭回程通道：等待中的消费者随即拿到 `None`。
        let _ = self.inner.shutdown.send(true);
        self.inner.inbound_rx.lock().await.close();
    }

    /// 启动空闲回收后台任务（幂等）。返回是否由本次调用启动。
    pub fn spawn_reaper(&self) -> bool {
        let mut guard = self
            .inner
            .reaper
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.is_some() {
            return false;
        }
        let interval = (self.inner.config.idle_timeout / 2)
            .max(Duration::from_millis(50))
            .min(Duration::from_secs(5));
        // 后台任务持弱引用：池被丢弃后任务自行结束（无 `Arc` 环）。
        let weak: Weak<Inner> = Arc::downgrade(&self.inner);
        *guard = Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let Some(inner) = weak.upgrade() else {
                    break;
                };
                inner.reap_expired();
            }
        }));
        true
    }

    /// 解析实际目标：cone 模式下固定首包目标，否则用该包自带的目标。
    fn effective_target(&self, target: &TargetAddr) -> TargetAddr {
        if !self.inner.config.cone {
            return target.clone();
        }
        let mut guard = self
            .inner
            .cone_dest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match guard.as_ref() {
            Some(fixed) => fixed.clone(),
            None => {
                guard.replace(target.clone());
                target.clone()
            }
        }
    }

    /// 取出（或建立）目标对应的出站条目。绑定与解析都在表锁之外。
    async fn ensure_entry(&self, target: &TargetAddr) -> Result<(Arc<Entry>, bool), Error> {
        if let Some(entry) = self.inner.table().get(target) {
            return Ok((Arc::clone(entry), true));
        }
        // 建表路径串行化：同一目标只绑定一个 socket（表锁之外的独立锁）。
        let _creating = self.inner.create_lock.lock().await;
        if let Some(entry) = self.inner.table().get(target) {
            return Ok((Arc::clone(entry), true));
        }
        // 解析与绑定都不在表锁内完成，避免 IO 持锁。
        let resolved = resolve(target).await?;
        let socket = UdpSocket::bind(bind_addr(resolved))
            .await
            .map_err(Error::Bind)?;

        let entry = Arc::new(Entry::new(
            resolved,
            socket,
            self.inner.epoch,
            Arc::clone(&self.inner.live_sockets),
            Arc::clone(&self.inner.activity_seq),
        ));
        {
            let mut table = self.inner.table();
            // 上界：淘汰最久未用的条目（LRU），不拒绝新包。
            if table.len() >= self.inner.config.max_entries {
                if let Some(key) = lru_key(&table) {
                    if let Some(victim) = table.remove(&key) {
                        victim.close();
                    }
                }
            }
            table.insert(target.clone(), Arc::clone(&entry));
        }
        self.inner.live_sockets.fetch_add(1, Ordering::SeqCst);
        self.inner.created_sockets.fetch_add(1, Ordering::SeqCst);
        spawn_reader(
            Arc::clone(&entry),
            self.inner.inbound_tx.clone(),
            Arc::clone(&self.inner.dropped_replies),
        );
        Ok((entry, false))
    }
}

/// 选出最久未用的条目键（LRU 淘汰）。
///
/// 按**活跃序号**排序而非毫秒时间戳：同一毫秒内建立的两个条目时间戳相同，
/// LRU 会退化成任意顺序，淘汰对象不可预测。
fn lru_key(table: &HashMap<TargetAddr, Arc<Entry>>) -> Option<TargetAddr> {
    table
        .iter()
        .min_by_key(|(_, entry)| entry.activity_seq())
        .map(|(key, _)| key.clone())
}

/// 出站 socket 的绑定地址：按解析结果的地址族绑定通配源。
fn bind_addr(resolved: SocketAddr) -> SocketAddr {
    match resolved.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

/// 把目标地址解析为可 `send_to` 的地址；域名取首条解析结果。
async fn resolve(target: &TargetAddr) -> Result<SocketAddr, Error> {
    match target {
        TargetAddr::V4(ip, port) => Ok(SocketAddr::from((*ip, *port))),
        TargetAddr::V6(ip, port) => Ok(SocketAddr::from((*ip, *port))),
        TargetAddr::Domain(host, port) => {
            let mut addrs = tokio::time::timeout(
                RESOLVE_TIMEOUT,
                tokio::net::lookup_host((host.as_str(), *port)),
            )
            .await
            .map_err(|_| {
                Error::Resolve(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "域名解析超时",
                ))
            })?
            .map_err(Error::Resolve)?;
            addrs.next().ok_or_else(|| {
                Error::Resolve(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "域名无解析结果",
                ))
            })
        }
    }
}
