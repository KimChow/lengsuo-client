//! 每个密钥及环境 epoch 独占接收器；认证后才更新重放窗口和对端地址。
//!
//! 内存窗口不跨进程重启保存。需要跨重启保护时，用 [`Receiver::with_replay_store`]
//! 挂接 [`crate::replay_store::ReplayStore`]：认证通过后先查持久化集合，
//! 已见的 `(session_id, packet_id)` fail-closed 拒绝，新 id 落盘后转发。
//! 未挂接时行为与既有内存窗口一致（重启即重置），调用方必须显式选择。
//!
//! [`Sessions`] 抽出「会话 + 重放窗口 + 可选持久化集合」这一层，供
//! [`Receiver`]（单用户 UDP/TCP 载荷）与 UDP 多用户 EIH 服务端
//! （[`crate::eih_udp::EihUdpServer`]）共用，保证两条 UDP 收包路径的
//! 重放语义**逐条一致**（内存窗口、容量上限、跨重启集合、时钟回退）。
use crate::{crypto::Key, packet::Decoded, replay_store::ReplayStore, Error};
use ss_core::replay::Window;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

/// 由可信运行时提供，禁止从报文或用户请求中取得。
#[derive(Clone, Copy)]
pub struct Clock {
    pub unix_seconds: u64,
    pub monotonic: Instant,
}
struct Session {
    replay: Window,
    clock: Clock,
    peer: SocketAddr,
}

/// 会话表：每会话一个重放窗口 + 对端地址 + 存活时间。
///
/// 语义与既有单用户接收器完全一致：
/// - **认证通过后**才登记；伪造、重放与容量拒绝都不改变任何状态；
/// - 内存窗口跨进程重启即重置，跨重启保护由调用方挂接
///   [`ReplayStore`] 并在每次接受后调用 [`Sessions::flush_replay`] 落盘；
/// - 并发安全由调用方保证：调用方须以 `Mutex`（或等价物）串行化本表与存储。
pub struct Sessions {
    capacity: usize,
    retention: Duration,
    clock: Option<Clock>,
    sessions: BTreeMap<[u8; 8], Session>,
    /// 调用方挂接的跨重启重放集合；`None` 表示仅内存窗口。
    store: Option<ReplayStore>,
}
impl Sessions {
    /// 容量至少 1；保留期至少 60 秒（与「已证明过期」的条件一致）。
    pub fn new(capacity: usize, retention: Duration) -> Result<Self, Error> {
        if capacity < 1 || retention < Duration::from_secs(60) {
            return Err(Error::SessionPolicy);
        }
        Ok(Self {
            capacity,
            retention,
            clock: None,
            sessions: BTreeMap::new(),
            store: None,
        })
    }
    /// 挂接跨重启重放集合；调用方负责以互斥量串行化本表与存储，
    /// 并在每次接受后调用 [`Sessions::flush_replay`] 落盘。
    #[must_use]
    pub fn with_replay_store(mut self, store: ReplayStore) -> Self {
        self.store = Some(store);
        self
    }
    /// 将跨重启重放集合落盘；未挂接存储时为空操作。
    pub fn flush_replay(&self) -> Result<(), Error> {
        match &self.store {
            Some(store) => store.flush(),
            None => Ok(()),
        }
    }
    /// 时钟回退判定；必须早于任何状态变更。
    pub fn check_clock(&self, now: Clock) -> Result<(), Error> {
        if self.clock.is_some_and(|last| {
            now.unix_seconds < last.unix_seconds || now.monotonic < last.monotonic
        }) {
            return Err(Error::ClockRollback);
        }
        Ok(())
    }
    fn expired(&self, session: &Session, now: Clock) -> bool {
        // ±30 秒允许窗口包含端点；必须超过 60 整秒才能证明旧包已过期。
        now.unix_seconds.saturating_sub(session.clock.unix_seconds) > 60
            && now
                .monotonic
                .checked_duration_since(session.clock.monotonic)
                .is_some_and(|age| age >= self.retention)
    }
    /// 登记一次**已认证**的收发：先过内存窗口，再查持久化集合，最后才提交状态。
    pub fn accept(
        &mut self,
        session_id: [u8; 8],
        packet_id: u64,
        peer: SocketAddr,
        now: Clock,
    ) -> Result<(), Error> {
        self.check_clock(now)?;
        let existing = self
            .sessions
            .get(&session_id)
            .filter(|s| !self.expired(s, now));
        let mut replay = existing.map_or_else(|| Window::new(u64::MAX), |s| s.replay.clone());
        replay
            .accept_authenticated(packet_id)
            .map_err(|_| Error::Replay)?;
        if existing.is_none()
            && self
                .sessions
                .values()
                .filter(|s| !self.expired(s, now))
                .count()
                >= self.capacity
        {
            return Err(Error::SessionCapacity);
        }
        // 跨重启保护：认证通过后查持久化集合，已见的 (session, packet id) fail-closed。
        if let Some(store) = &mut self.store {
            if !store.accept(session_id, packet_id) {
                return Err(Error::Replay);
            }
        }
        // 全部检查通过后再提交：伪造、重放和容量拒绝均不更新地址或存活时间。
        self.gc(now)?;
        self.sessions.insert(
            session_id,
            Session {
                replay,
                clock: now,
                peer,
            },
        );
        Ok(())
    }
    /// 该会话最近一次成功登记的对端地址。
    pub fn last_peer(&self, session_id: [u8; 8]) -> Option<SocketAddr> {
        self.sessions.get(&session_id).map(|s| s.peer)
    }
    /// 可信定时器可回收已证明过期的会话；不驱逐仍有效的会话。
    pub fn gc(&mut self, now: Clock) -> Result<(), Error> {
        self.check_clock(now)?;
        let retention = self.retention;
        self.sessions.retain(|_, session| {
            !(now.unix_seconds.saturating_sub(session.clock.unix_seconds) > 60
                && now
                    .monotonic
                    .checked_duration_since(session.clock.monotonic)
                    .is_some_and(|age| age >= retention))
        });
        self.clock = Some(now);
        Ok(())
    }
}
pub struct Receiver {
    key: Key,
    client: Option<[u8; 8]>,
    sessions: Sessions,
}
impl Receiver {
    /// None 接收请求；Some 接收绑定到指定客户端会话的响应。
    /// 响应方向至少允许两个服务端会话，以支持服务端会话轮换。
    pub fn new(
        key: Key,
        client: Option<[u8; 8]>,
        capacity: usize,
        retention: Duration,
    ) -> Result<Self, Error> {
        let minimum = if client.is_some() { 2 } else { 1 };
        if capacity < minimum || retention < Duration::from_secs(60) {
            return Err(Error::SessionPolicy);
        }
        Ok(Self {
            key,
            client,
            sessions: Sessions::new(capacity, retention)?,
        })
    }
    /// 挂接跨重启重放集合；调用方负责以互斥量串行化本 `Receiver` 与其存储，
    /// 并在每次接受后调用 [`Receiver::flush_replay`] 落盘。
    #[must_use]
    pub fn with_replay_store(mut self, store: ReplayStore) -> Self {
        self.sessions = self.sessions.with_replay_store(store);
        self
    }
    /// 将跨重启重放集合落盘；未挂接存储时为空操作。
    pub fn flush_replay(&self) -> Result<(), Error> {
        self.sessions.flush_replay()
    }
    pub fn receive(
        &mut self,
        packet: &[u8],
        peer: SocketAddr,
        now: Clock,
    ) -> Result<Decoded, Error> {
        self.sessions.check_clock(now)?;
        let decoded = match self.client {
            Some(client) => self.key.open_server(packet, now.unix_seconds, client)?,
            None => self.key.open_client(packet, now.unix_seconds)?,
        };
        self.sessions
            .accept(decoded.session_id, decoded.packet_id, peer, now)?;
        Ok(decoded)
    }
    pub fn last_peer(&self, session_id: [u8; 8]) -> Option<SocketAddr> {
        self.sessions.last_peer(session_id)
    }
    /// 可信定时器可回收已证明过期的会话；不驱逐仍有效的会话。
    pub fn gc(&mut self, now: Clock) -> Result<(), Error> {
        self.sessions.gc(now)
    }
}
