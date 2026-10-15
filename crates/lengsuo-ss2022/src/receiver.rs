//! 每个密钥及环境 epoch 独占接收器；认证后才更新重放窗口和对端地址。
//! 内存状态不跨进程重启保存，重启必须恢复状态或轮换实际密钥。
use crate::{crypto::Key, packet::Decoded, Error};
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
pub struct Receiver {
    key: Key,
    client: Option<[u8; 8]>,
    capacity: usize,
    retention: Duration,
    clock: Option<Clock>,
    sessions: BTreeMap<[u8; 8], Session>,
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
            capacity,
            retention,
            clock: None,
            sessions: BTreeMap::new(),
        })
    }
    fn validate_clock(&self, now: Clock) -> Result<(), Error> {
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
    pub fn receive(
        &mut self,
        packet: &[u8],
        peer: SocketAddr,
        now: Clock,
    ) -> Result<Decoded, Error> {
        self.validate_clock(now)?;
        let decoded = match self.client {
            Some(client) => self.key.open_server(packet, now.unix_seconds, client)?,
            None => self.key.open_client(packet, now.unix_seconds)?,
        };
        let existing = self
            .sessions
            .get(&decoded.session_id)
            .filter(|s| !self.expired(s, now));
        let mut replay = existing.map_or_else(|| Window::new(u64::MAX), |s| s.replay.clone());
        replay
            .accept_authenticated(decoded.packet_id)
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
        // 全部检查通过后再提交：伪造、重放和容量拒绝均不更新地址或存活时间。
        self.gc(now)?;
        self.sessions.insert(
            decoded.session_id,
            Session {
                replay,
                clock: now,
                peer,
            },
        );
        Ok(decoded)
    }
    pub fn last_peer(&self, session_id: [u8; 8]) -> Option<SocketAddr> {
        self.sessions.get(&session_id).map(|s| s.peer)
    }
    /// 可信定时器可回收已证明过期的会话；不驱逐仍有效的会话。
    pub fn gc(&mut self, now: Clock) -> Result<(), Error> {
        self.validate_clock(now)?;
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
