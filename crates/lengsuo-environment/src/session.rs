//! 环境侧最小会话表：键=归一化五元组，值=环境身份 + 绑定代次 + 到期时间。
//!
//! `lengsuo-tun` 只提供报文元数据解析与校验和验证，没有任何会话原语，
//! 因此这里给出环境侧自有的最小实现，并沿用其「不伪造归属」的约定：
//! - 容量满时一律拒绝新登记，**不做任何随机驱逐**，已在册会话不受影响。
//! - 每条会话有两道时间线：`idle_ttl` 是有流量即可续期的存活期，
//!   `hard_ttl` 是从首次登记起算的绝对上限，续期永远不能突破它。
//! - 时间算术一律带检查，溢出即拒绝（fail-closed），不静默延长寿命。

use crate::flow::{FlowKey, Timestamp};
use crate::router::EnvironmentId;
use std::{collections::BTreeMap, fmt, time::Duration};

/// 会话表拒绝原因。所有分支都是拒绝，不存在「未登记即直连」的第三种结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// 容量必须大于零。
    InvalidCapacity,
    /// 表已满，拒绝新登记；未驱逐任何既有条目。
    Full,
    /// 同一五元组已被另一个环境占用（跨环境抢占）。
    Occupied { key: FlowKey, holder: EnvironmentId },
    /// 存活期算术溢出，无法计算到期时间。
    Clock,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::InvalidCapacity => write!(f, "会话表容量必须大于零"),
            SessionError::Full => write!(f, "会话表已满，拒绝新会话"),
            SessionError::Occupied { key, holder } => {
                write!(f, "会话 {key:?} 已被环境 {holder:?} 占用")
            }
            SessionError::Clock => write!(f, "会话时间计算溢出"),
        }
    }
}

impl std::error::Error for SessionError {}

/// 一条已登记会话。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    pub environment: EnvironmentId,
    /// 登记时环境绑定的出口代次；代次变化即视为旧会话失效。
    pub epoch: u64,
    /// 有流量时可续期到的时刻；已登记会话只受绝对上限约束。
    pub expires_at: Timestamp,
    /// 首次登记时确定的绝对到期时刻，续期不可突破。
    pub hard_deadline: Timestamp,
}

#[derive(Debug)]
pub struct SessionTable {
    entries: BTreeMap<FlowKey, Session>,
    capacity: usize,
    idle_ttl: Duration,
    hard_ttl: Duration,
}

impl SessionTable {
    pub fn new(
        capacity: usize,
        idle_ttl: Duration,
        hard_ttl: Duration,
    ) -> Result<Self, SessionError> {
        if capacity == 0 {
            return Err(SessionError::InvalidCapacity);
        }
        Ok(Self {
            entries: BTreeMap::new(),
            capacity,
            idle_ttl,
            hard_ttl,
        })
    }

    /// 登记或续期一条会话。
    ///
    /// 既有条目属于别的环境时返回 [`SessionError::Occupied`] 且不改动原条目；
    /// 环境相同且未到期则只续期，不占用新槽位、也不后移绝对上限；
    /// 表满且键尚未登记时返回 [`SessionError::Full`]；键已登记（含已过期的条目）时
    /// 沿用原槽位、不再新占位，因此上限只约束并发会话总数。
    /// 首次登记的绝对上限在此刻锁定，存活期内任何续期都不会把它往后推；
    /// 已过期的条目视为新会话并锁定新的上限（寿命不会被无限续期）。
    /// 属于其他环境的过期条目仍返回 `Occupied`：本表不做任何自动驱逐，
    /// 需要上层显式 `close` 后该键才能被其他环境接管。
    pub fn open(
        &mut self,
        key: FlowKey,
        environment: EnvironmentId,
        epoch: u64,
        now: Timestamp,
    ) -> Result<Session, SessionError> {
        let live = self.live(key, now);
        let deadline = match (self.entries.get(&key).copied(), live) {
            (Some(existing), _) if existing.environment != environment => {
                return Err(SessionError::Occupied {
                    key,
                    holder: existing.environment,
                })
            }
            // 仍存活：沿用已锁定的绝对上限。
            (Some(existing), Some(alive)) if existing.environment == environment => {
                alive.hard_deadline
            }
            // 新会话或已到期会话：必须占一个槽位，并锁定新的上限。
            _ if self.entries.len() >= self.capacity && !self.entries.contains_key(&key) => {
                return Err(SessionError::Full)
            }
            _ => now.checked_add(self.hard_ttl).ok_or(SessionError::Clock)?,
        };
        let idle = now.checked_add(self.idle_ttl).ok_or(SessionError::Clock)?;
        let session = Session {
            environment,
            epoch,
            expires_at: Timestamp(idle.0.min(deadline.0)),
            hard_deadline: deadline,
        };
        self.entries.insert(key, session);
        Ok(session)
    }

    /// 查询并续期，返回「续期前的条目」与「续期结果」。
    ///
    /// 条目不存在或已到期返回 `None`（过期条目顺手回收槽位）；
    /// 续期本身失败（时间溢出）时条目作废，宁可拒绝后续报文。
    pub fn refresh(
        &mut self,
        key: FlowKey,
        now: Timestamp,
    ) -> Option<(Session, Result<Session, SessionError>)> {
        let existing = self.live(key, now)?;
        let session = self.open(key, existing.environment, existing.epoch, now);
        if session.is_err() {
            // 时间溢出等异常：条目作废，后续报文一律按未登记处理。
            self.entries.remove(&key);
        }
        Some((existing, session))
    }

    /// 只读查询，不续期；过期视为不存在。
    pub fn get(&self, key: FlowKey, now: Timestamp) -> Option<Session> {
        self.entries.get(&key).copied().filter(|s| is_live(s, now))
    }

    /// 该键是否存在但已到期：用于区分「从未登记」与「会话过期」。
    pub fn expired(&self, key: FlowKey, now: Timestamp) -> bool {
        match self.entries.get(&key).copied() {
            Some(session) => !is_live(&session, now),
            None => false,
        }
    }

    pub fn remove(&mut self, key: FlowKey) -> Option<Session> {
        self.entries.remove(&key)
    }

    /// 撤销某环境的全部会话，对齐运行时既有的撤销语义。返回被清除条数。
    pub fn revoke(&mut self, environment: EnvironmentId) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, session| session.environment != environment);
        before - self.entries.len()
    }

    /// 只保留代次仍等于当前权威值的会话（租约被换掉时清除旧代次）。
    pub fn retain_epoch(&mut self, environment: EnvironmentId, epoch: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, session| !(session.environment == environment && session.epoch != epoch));
        before - self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 只读遍历全部条目（含已到期者），供上层判定失效归属。
    pub fn iter(&self) -> impl Iterator<Item = (&FlowKey, &Session)> {
        self.entries.iter()
    }

    /// 清除所有已到期条目并返回数量，供上层周期性回收槽位。
    pub fn reap(&mut self, now: Timestamp) -> usize {
        let stale: Vec<FlowKey> = self
            .entries
            .iter()
            .filter(|(_, session)| !is_live(session, now))
            .map(|(key, _)| *key)
            .collect();
        let count = stale.len();
        for key in stale {
            self.entries.remove(&key);
        }
        count
    }

    fn live(&self, key: FlowKey, now: Timestamp) -> Option<Session> {
        self.entries.get(&key).copied().filter(|s| is_live(s, now))
    }
}

fn is_live(session: &Session, now: Timestamp) -> bool {
    now < session.expires_at
}
