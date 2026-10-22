//! 客户端侧空闲会话复用池的**接线层**：把 [`IdleSessionPool`] 接进客户端会话生命周期。
//!
//! 基线 anytls-go fd6167acd6d73b9fa3e607659951847fbc9e6c50：
//! - `proxy/session/client.go`：`Client` 与池一一对应、`CreateStream` 的
//!   「先取用空闲、未命中则新建」、流 `dieHook` 的归还、会话 `dieHook` 的注销、
//!   `idleCleanup` / `idleCleanupExpTime` 的定时回收与 `minIdleSession` 保留；
//! - `cmd/client/myclient.go`：`sessionClient` 持有唯一的 `session.Client`
//!   （本模块的 [`ClientPool`] 即该持有者）；
//! - `cmd/client/main.go`：`-m minIdleSession`（保留的最小空闲会话数）、
//!   `-dr`（禁用复用）。
//!
//! ## 与参考的逐条对应
//!
//! | 参考（anytls-go） | 本模块 |
//! |---|---|
//! | `session.Client`（池的持有者，与客户端一一对应） | [`ClientPool`] |
//! | `Client.sessions` + `sessionCounter`（会话登记与自增序号） | [`ClientPool`] 的登记与序号 |
//! | `Client.getIdleSession()` | [`ClientPool::acquire`]（命中分支） |
//! | `Client.createSession()` | [`ClientPool::acquire`]（未命中分支） |
//! | 流 `dieHook` → `idleSession.Insert(MaxUint64-seq, s)` | [`ClientPool::release`] |
//! | 会话 `dieHook` → `idleSession.Remove` + `delete(c.sessions, seq)` | [`ClientPool::session_closed`] |
//! | `util.StartRoutine(die, interval, c.idleCleanup)` | [`spawn_cleanup_driver`] |
//! | `c.idleCleanupExpTime` | [`ClientPool::cleanup`] |
//! | `-dr` / `disableReuse` | [`PoolConfig::reuse`] = `false` |
//!
//! ## 边界
//!
//! - 池只搬**会话编号**与时间戳，不持有传输层对象（TLS 连接由调用方持有）。
//!   关闭与回收通过返回值/回调交给调用方执行（参考里由 `session.Close()` 完成）。
//! - 策略（超时、最小保留数、容量上限、是否复用）全部来自 [`PoolConfig`]，
//!   本模块不硬编码；间隔与超时的 `<= 5s → 30s` 夹取由 [`IdleSessionPool`] 承担
//!   （与参考 `NewClient` 同规则）。
//! - `max_idle` 在参考中不存在（参考的空闲表无上限），本实现自设容量上限；
//!   池满时 **fail-closed**：拒绝入池并要求调用方关闭该会话。
//! - 空闲会话的**取用顺序**与**最小保留数的续期对象**沿用 [`IdleSessionPool`]
//!   的既有语义（见 `pool.rs` 的模块文档与 `tests/pool.rs`）；与参考的差异见
//!   `docs/anytls-idle-pool.md` 的「偏离清单」。
use crate::pool::{IdleSessionPool, PoolError};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

/// 回收驱动的单次等待上限（毫秒）。
///
/// 配置的检查间隔若超过此值，驱动按此上限轮询（防止 `Instant` 加法溢出而 panic）；
/// 池内 `next_check` 仍以配置间隔为准，故回收时机仍由配置决定。
pub const MAX_DRIVER_INTERVAL_MS: u64 = 60_000;

/// 复用池策略：全部来自配置，本模块不硬编码任何策略常量。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    /// 回收检查间隔（毫秒）。参考 `idleSessionCheckInterval`；
    /// `<= 5s` 由 [`IdleSessionPool`] 按参考规则拉回 30s。
    pub check_interval_ms: u64,
    /// 空闲超时（毫秒）。参考 `idleSessionTimeout`；同样按参考规则夹取。
    pub idle_timeout_ms: u64,
    /// 保留的最小空闲会话数（参考 `minIdleSession`）。
    pub min_idle: usize,
    /// 空闲会话数上限（参考无此参数；本实现自设，见偏离清单）。
    pub max_idle: u64,
    /// 是否允许复用（参考 `-dr` / `disableReuse`）。
    pub reuse: bool,
}

impl PoolConfig {
    /// 参考 `cmd/client/main.go` 的默认：`-m 5`（保留 5 条空闲会话）、
    /// `-dr false`（允许复用）。间隔与超时取参考 `NewMyClient` 的 30s。
    ///
    /// ⚠️ 30s 会被 [`IdleSessionPool`] 的 `<= 5s → 30s` 规则**原样保留**（不夹取）。
    pub fn reference_defaults() -> Self {
        Self {
            check_interval_ms: 30_000,
            idle_timeout_ms: 30_000,
            min_idle: 5,
            max_idle: 64,
            reuse: true,
        }
    }
}

/// 一次取用的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acquired {
    /// 会话编号（参考 `session.seq`，单调递增且永不复用）。
    pub session_id: u64,
    /// 是否命中空闲池（`true` = 复用既有会话，`false` = 新建）。
    pub reused: bool,
}

/// 归还一条会话的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseOutcome {
    /// 已进入空闲池，可被再次取用。
    Pooled,
    /// 池已满：会话被注销，调用方**必须关闭**它（fail-closed）。
    PoolFull,
    /// 复用已关闭（`reuse = false`）：会话被注销，调用方**必须关闭**它。
    ReuseDisabled,
    /// 会话已关闭或未登记：幂等，调用方无需处理。
    AlreadyClosed,
}

/// 客户端会话复用池的持有者：对应参考 `session.Client`。
///
/// 一个持有者对应一个客户端实例（参考 `myclient.go` 里唯一的 `sessionClient`），
/// 其下管理多条**会话**：每条会话 = 一条已认证的 TLS 连接 = 一个自增编号。
/// 池内空闲会话按参考的 LIFO 取用（最近归还者先被取用）。
pub struct ClientPool {
    pool: IdleSessionPool,
    config: PoolConfig,
    /// 下一个会话编号（参考 `sessionCounter`，从 1 开始单调递增）。
    next_seq: u64,
}

impl ClientPool {
    /// 按配置构造。配置非法（容量为零或 `min_idle > max_idle`）时 fail-closed。
    pub fn new(config: PoolConfig) -> Result<Self, PoolError> {
        let pool = IdleSessionPool::new(
            config.check_interval_ms,
            config.idle_timeout_ms,
            config.min_idle,
            config.max_idle,
        )?;
        Ok(Self {
            pool,
            config,
            next_seq: 0,
        })
    }

    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// 取用一条会话：命中空闲池则复用，未命中则新建并登记（参考 `CreateStream`）。
    pub fn acquire(&mut self, now: u64) -> Result<Acquired, PoolError> {
        if self.config.reuse {
            if let Some(session_id) = self.pool.acquire(now)? {
                return Ok(Acquired {
                    session_id,
                    reused: true,
                });
            }
        }
        let session_id = self
            .next_seq
            .checked_add(1)
            .ok_or(PoolError::SessionIdExhausted)?;
        self.next_seq = session_id;
        self.pool.register(session_id, now)?;
        Ok(Acquired {
            session_id,
            reused: false,
        })
    }

    /// 归还一条会话（参考流 `dieHook`）：进入空闲池等待复用。
    ///
    /// 池满时 **fail-closed**：注销该会话并要求调用方关闭它，绝不静默丢弃。
    pub fn release(&mut self, session_id: u64, now: u64) -> Result<ReleaseOutcome, PoolError> {
        if !self.config.reuse {
            self.pool.on_session_closed(session_id);
            return Ok(ReleaseOutcome::ReuseDisabled);
        }
        match self.pool.release(session_id, now) {
            Ok(()) => Ok(ReleaseOutcome::Pooled),
            // 池满：注销 + 上层关闭。
            Err(PoolError::InvalidConfig) => {
                self.pool.on_session_closed(session_id);
                Ok(ReleaseOutcome::PoolFull)
            }
            // 已在池中：参考用同一个键覆盖（刷新 `idleSince`），本池保持原归还时刻，
            // 语义上仍是「在池中」，重复归还不改变归属。
            Err(PoolError::AlreadyIdle) => Ok(ReleaseOutcome::Pooled),
            // 已关闭 / 未登记：幂等。
            Err(PoolError::Closed) | Err(PoolError::UnknownSession) => {
                Ok(ReleaseOutcome::AlreadyClosed)
            }
            Err(other) => Err(other),
        }
    }

    /// 连接断开或会话关闭（参考会话 `dieHook`）：注销会话，无论其是否在池中。
    ///
    /// 返回该会话此前是否在空闲池里。
    pub fn session_closed(&mut self, session_id: u64) -> bool {
        self.pool.on_session_closed(session_id)
    }

    /// 到期结算（参考 `idleCleanupExpTime`）：回收超时会话并注销它们。
    ///
    /// 返回本次回收的会话编号：调用方**必须关闭**这些会话的传输层对象。
    pub fn cleanup(&mut self, now: u64) -> Result<Vec<u64>, PoolError> {
        let reclaimed = self.pool.cleanup_expired(now)?;
        // 参考里回收 ⇔ `session.Close()` ⇔ 会话 `dieHook` 注销；本池据此注销，
        // 免得被回收的会话仍留在登记表里被再次归还。
        for session_id in &reclaimed {
            self.pool.on_session_closed(*session_id);
        }
        Ok(reclaimed)
    }

    /// 本轮是否已到结算时刻（参考由定时器按间隔触发）。
    pub fn is_check_due(&self, now: u64) -> bool {
        self.pool.is_check_due(now)
    }

    /// 回收驱动是否应当运行（参考 `NewClient`：**仅在允许复用时**才
    /// `util.StartRoutine(…, c.idleCleanup)`；`disableReuse` 时参考根本不启动驱动）。
    pub fn driver_enabled(&self) -> bool {
        self.config.reuse
    }

    /// 关闭整个池（参考 `Client.Close`）：注销全部会话，返回它们的编号。
    pub fn close_all(&mut self) -> Vec<u64> {
        self.pool.close_all()
    }

    pub fn idle_len(&self) -> usize {
        self.pool.idle_len()
    }

    pub fn registered_len(&self) -> usize {
        self.pool.registered_len()
    }

    pub fn contains(&self, session_id: u64) -> bool {
        self.pool.contains(session_id)
    }

    /// 夹取后的空闲超时（毫秒）。
    pub fn idle_timeout_ms(&self) -> u64 {
        self.pool.idle_timeout_ms()
    }
    /// 夹取后的检查间隔（毫秒）。
    pub fn check_interval_ms(&self) -> u64 {
        self.pool.check_interval_ms()
    }

    pub fn min_idle(&self) -> usize {
        self.pool.min_idle()
    }

    pub fn max_idle(&self) -> usize {
        self.pool.max_idle()
    }
}

/// 进程内单调毫秒时钟：生产代码给池结算用（同一时钟源，不可混用合成时钟）。
pub fn monotonic_ms() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// 启动空闲池的回收驱动（参考 `util.StartRoutine(die, interval, c.idleCleanup)`）。
///
/// - 驱动用 `tokio::time::sleep` 定时结算，**有界等待**（单次不超过
///   [`MAX_DRIVER_INTERVAL_MS`]），绝不 busy-loop；
/// - 结算在锁内完成、回调在锁外执行，锁绝不跨 `await` 持有；
/// - 时钟回拨等结算错误不终止驱动：跳过本轮，继续下一轮；
/// - 驱动**不自行关闭**会话：被回收的编号交给 `on_reclaim`，由持有传输层的一方
///   执行关闭（参考里是 `session.Close()`）；
/// - 复用被关闭时**不启动驱动**（参考 `NewClient` 只在 `!disableReuse` 时
///   `util.StartRoutine`）。
///
/// 返回的句柄由调用方 `abort()` 即可停止驱动。
pub fn spawn_cleanup_driver(
    pool: Arc<Mutex<ClientPool>>,
    on_reclaim: Arc<dyn Fn(u64) + Send + Sync>,
) -> tokio::task::JoinHandle<()> {
    let period = Duration::from_millis(lock(&pool).check_interval_ms().min(MAX_DRIVER_INTERVAL_MS));
    let enabled = lock(&pool).driver_enabled();
    tokio::spawn(async move {
        if !enabled {
            // 复用被关闭：池里永远不会有空闲会话，参考也不启动清理例程。
            return;
        }
        loop {
            // 参考 `util.StartRoutine` 是 `time.Sleep(d); f()`：**先等一个间隔**再结算，
            // 故首次结算发生在 t=间隔，而非 t=0。
            tokio::time::sleep(period).await;
            let reclaimed = {
                let mut guard = lock(&pool);
                // 结算失败（时钟回拨）只跳过本轮：驱动必须活着继续观察。
                guard.cleanup(monotonic_ms()).unwrap_or_default()
            };
            for session_id in reclaimed {
                on_reclaim(session_id);
            }
        }
    })
}

/// 取锁：中毒时取回内层值（后台驱动不该因一次 panic 而整体停摆）。
fn lock(pool: &Arc<Mutex<ClientPool>>) -> MutexGuard<'_, ClientPool> {
    pool.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
