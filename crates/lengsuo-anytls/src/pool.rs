//! 空闲会话复用池：纯内存策略与结算，不含 TLS、网络与 I/O。
//! 基线 anytls-go fd6167acd6d73b9fa3e607659951847fbc9e6c50 `proxy/session/client.go`：
//! `Client.getIdleSession`（后进先出取用）、`Client.createSession` 的 dieHook
//! 归还/移除语义、`Client.idleCleanupExpTime` 的最小保留数与超时回收。
//! 参考用 `stl4go.SkipList` 按 `math.MaxUint64 - seq` 排序后取第一个元素；
//! 键随会话序号单调递增（seq 为 uint64 累加器），故等价于「最后归还者先被取用」。
//! 本实现以栈记录归还顺序（栈顶即最近归还），语义与参考的取用顺序一致。
//!
//! 参考只提供 `minIdleSession`；任务书要求的 `maxIdleSession` 在参考中不存在，
//! 本模块实现为「池容量上限」并已在报告与文档中标注为语言/需求差异，非参考行为。
//! 状态用单调 `u64` 时钟结算，调用方传入的 `now` 必须非递减，否则返回 `NonMonotonic`。

use std::collections::HashSet;

/// 参考 `NewClient` 对间隔的下限：`<= 5s` 一律拉回 30s。
const INTERVAL_FLOOR_SECS: u64 = 5;
/// 拉回后的默认间隔。
const DEFAULT_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PoolError {
    #[error("池配置非法")]
    InvalidConfig,
    #[error("会话编号为零或尚未登记")]
    UnknownSession,
    #[error("会话已在池中")]
    AlreadyIdle,
    #[error("会话已关闭，不得入池")]
    Closed,
    #[error("时间戳早于上一次结算")]
    NonMonotonic,
}

/// 一个可复用的空闲会话。池只搬运编号与时间戳，不持有连接本身。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IdleEntry {
    session_id: u64,
    /// 归还时刻（池时钟毫秒）。
    idle_since: u64,
    /// 最近一次结算活动时间，用于 `minIdleSession` 保护的续期。
    activity: u64,
}

/// 与 `Client` 一一对应的复用池。
#[derive(Debug)]
pub struct IdleSessionPool {
    min_idle: usize,
    max_idle: usize,
    idle_timeout_ms: u64,
    check_interval_ms: u64,
    /// 登记在册（活跃 + 空闲）的会话编号。
    registered: HashSet<u64>,
    /// 已关闭但可能仍被登记的会话编号。
    closed: HashSet<u64>,
    /// 归还顺序栈：栈顶为最近归还，取用与参考同为 LIFO。
    idle: Vec<IdleEntry>,
    /// 下次允许结算的时刻。
    next_check: u64,
    /// 上一次结算时刻，用于拒绝回拨时钟。
    last_now: u64,
    /// 累计回收的会话编号。
    reclaimed: Vec<u64>,
}

impl IdleSessionPool {
    /// `check_interval`/`idle_timeout` 以毫秒给出：参考在构造时把
    /// `<= 5s` 的取值一律拉回 30s，此处保持同一夹取规则。
    pub fn new(
        check_interval_ms: u64,
        idle_timeout_ms: u64,
        min_idle: usize,
        max_idle: u64,
    ) -> Result<Self, PoolError> {
        if min_idle as u64 > max_idle || max_idle == 0 {
            return Err(PoolError::InvalidConfig);
        }
        Ok(Self {
            min_idle,
            max_idle: max_idle as usize,
            idle_timeout_ms: clamp_interval(idle_timeout_ms),
            check_interval_ms: clamp_interval(check_interval_ms),
            registered: HashSet::new(),
            closed: HashSet::new(),
            idle: Vec::new(),
            next_check: 0,
            last_now: 0,
            reclaimed: Vec::new(),
        })
    }

    /// 夹取后的空闲超时（毫秒）。
    pub fn idle_timeout_ms(&self) -> u64 {
        self.idle_timeout_ms
    }

    /// 夹取后的检查间隔（毫秒）。
    pub fn check_interval_ms(&self) -> u64 {
        self.check_interval_ms
    }

    pub fn min_idle(&self) -> usize {
        self.min_idle
    }

    pub fn max_idle(&self) -> usize {
        self.max_idle
    }

    pub fn idle_len(&self) -> usize {
        self.idle.len()
    }

    pub fn registered_len(&self) -> usize {
        self.registered.len()
    }

    pub fn contains(&self, session_id: u64) -> bool {
        self.registered.contains(&session_id)
    }

    /// 会话关闭钩子（参考 `Session.dieHook`）：无论当前空闲与否都注销，
    /// 并返回「是否曾在池中」。
    pub fn on_session_closed(&mut self, session_id: u64) -> bool {
        self.registered.remove(&session_id);
        self.closed.insert(session_id);
        self.remove_idle(session_id).is_some()
    }

    /// 新会话建成（参考 `Client.createSession` 登记 `c.sessions[seq]`）。
    pub fn register(&mut self, session_id: u64, now: u64) -> Result<(), PoolError> {
        if session_id == 0 {
            return Err(PoolError::UnknownSession);
        }
        self.poll_clock(now)?;
        if self.closed.contains(&session_id) {
            return Err(PoolError::Closed);
        }
        self.registered.insert(session_id);
        Ok(())
    }

    /// 取用空闲会话（参考 `Client.getIdleSession`）。
    /// 空池返回 `None`，调用方据此新建会话。
    pub fn acquire(&mut self, now: u64) -> Result<Option<u64>, PoolError> {
        self.poll_clock(now)?;
        while let Some(entry) = self.idle.pop() {
            if self.closed.contains(&entry.session_id)
                || !self.registered.contains(&entry.session_id)
            {
                continue;
            }
            return Ok(Some(entry.session_id));
        }
        Ok(None)
    }

    /// 归还空闲会话（参考 `Stream.dieHook` 中的 `idleSession.Insert`）。
    /// 池满时拒绝入池，由调用方关闭该会话；重复归还返回 `AlreadyIdle`。
    pub fn release(&mut self, session_id: u64, now: u64) -> Result<(), PoolError> {
        self.poll_clock(now)?;
        if self.closed.contains(&session_id) || !self.registered.contains(&session_id) {
            return Err(PoolError::Closed);
        }
        if self.idle.iter().any(|entry| entry.session_id == session_id) {
            return Err(PoolError::AlreadyIdle);
        }
        if self.idle.len() >= self.max_idle {
            return Err(PoolError::InvalidConfig);
        }
        self.idle.push(IdleEntry {
            session_id,
            idle_since: now,
            activity: now,
        });
        Ok(())
    }

    /// 到期结算（参考 `idleCleanupExpTime`）：按取用顺序自栈顶向栈底遍历，
    /// 未到期的会话计为 `activeCount`；`activeCount < min_idle` 的会话续期保留；
    /// 其余超过 `idle_timeout` 的会话回收。返回本次回收的会话编号。
    pub fn cleanup_expired(&mut self, now: u64) -> Result<Vec<u64>, PoolError> {
        self.poll_clock(now)?;
        if now < self.next_check {
            return Ok(Vec::new());
        }
        self.next_check = now.saturating_add(self.check_interval_ms);

        let exp_time = now.saturating_sub(self.idle_timeout_ms);
        let mut active_count = 0usize;
        let mut keep: Vec<IdleEntry> = Vec::with_capacity(self.idle.len());
        let mut reclaimed: Vec<u64> = Vec::new();

        // `idle` 的栈底是最早归还的会话，与参考 SkipList 的遍历顺序一致。
        for mut entry in self.idle.drain(..) {
            if entry.idle_since >= exp_time {
                active_count += 1;
                keep.push(entry);
                continue;
            }
            if active_count < self.min_idle {
                entry.activity = now;
                active_count += 1;
                keep.push(entry);
                continue;
            }
            reclaimed.push(entry.session_id);
        }
        self.idle = keep;
        self.reclaimed.extend_from_slice(&reclaimed);
        Ok(reclaimed)
    }

    /// 本次结算周期是否已到。到点即由 `cleanup_expired` 其后的全局时钟驱动。
    pub fn is_check_due(&self, now: u64) -> bool {
        now >= self.next_check
    }

    /// 关闭整个池（参考 `Client.Close`）：注销全部会话并清空空闲栈。
    pub fn close_all(&mut self) -> Vec<u64> {
        let mut all: Vec<u64> = self.registered.drain().collect();
        self.idle.clear();
        self.closed.clear();
        all.sort_unstable();
        all
    }

    /// 历史累计回收编号，供测试与诊断使用。
    pub fn reclaimed(&self) -> &[u64] {
        &self.reclaimed
    }

    fn poll_clock(&mut self, now: u64) -> Result<(), PoolError> {
        if now < self.last_now {
            return Err(PoolError::NonMonotonic);
        }
        self.last_now = now;
        Ok(())
    }

    fn remove_idle(&mut self, session_id: u64) -> Option<IdleEntry> {
        let position = self
            .idle
            .iter()
            .position(|entry| entry.session_id == session_id)?;
        Some(self.idle.remove(position))
    }
}

/// 参考 `NewClient`：间隔 `<= 5s` 一律拉回 30s。
fn clamp_interval(millis: u64) -> u64 {
    if millis <= INTERVAL_FLOOR_SECS * 1000 {
        DEFAULT_INTERVAL_SECS * 1000
    } else {
        millis
    }
}
