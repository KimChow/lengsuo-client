//! SIP022 TCP 接收侧：salt → 固定头 chunk → 变长头 chunk → `ss_core::chunk` 载荷帧。
//!
//! 校验顺序（全部通过后才提交状态）：AEAD 认证 → 固定头自洽（type / 声明长与填充上限）
//! → 注入时钟的时间窗 → 变长头认证 → 关联块合法 → padding 两处声明精确一致
//! → salt 与会话标识防重放。任一步失败或单次读超时都永久 poison 本 [`Reader`]：
//! 不降级明文、不用半途状态重试、不消费后续帧。
use ss_core::{
    chunk::read_chunk,
    crypto::{SessionAead, TAG_LEN},
    replay::Window,
    target::TargetAddr,
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{
    map_core, suite, Direction, Header, FIXED_HEADER_LEN, FIXED_HEADER_WIRE_LEN, PADDING_FIELD_LEN,
    RESPONSE_ASSOCIATION_LEN, TIMESTAMP_WINDOW_SECS,
};
use crate::{crypto::Key, receiver::Clock, Error};

/// 会话标识记忆池容量上限（本项目策略，不是协议常量）。
pub const MAX_TRACKED_SESSIONS: usize = 4096;

/// 变长头关联块：请求为 SOCKS5 目标地址，响应为请求会话标识。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Association {
    /// 请求流：目标地址。
    Request(TargetAddr),
    /// 响应流：所属请求流的会话标识。
    Response(u64),
}

/// 开场（两个头部 chunk）全部校验通过后的会话信息。
/// 不含 Debug，避免目标地址与会话标识进入日志。
pub struct Opened {
    pub session_id: u64,
    pub timestamp: u64,
    pub association: Association,
    /// 变长头携带的首批载荷（可为空）。
    pub payload: Vec<u8>,
}

/// salt + 会话标识防重放守卫（SIP022 §3.1.4 记忆池）。
///
/// 两层协作，计数器语义复用 `ss_core::replay::Window`：
/// - `session_ids` / `salts` 是权威记忆池，保留已建立连接的标识及其注入时钟，
///   超过 `retention` 才回收（规范 mandates 至少 60 秒），精确重复一律拒绝；
/// - `window` 是近窗快路径：会话标识作为计数器投入窗口，`Duplicate`（与当前最高
///   标识相同或窗口内已记录）直接拒绝；`TooOld` 只说明随机选取的标识落在 8192 位
///   窗口之外，对最高值本无单调关系，此时以该标识重新起窗——旧位与新最高标识的距离
///   本就落在窗口外，重新起窗不削弱保护，历史精确性仍由记忆池负责。
///
/// 时钟回退拒绝；任何拒绝都不修改池与窗口状态（与 `receiver.rs` 提交语义一致）。
pub struct SessionReplay {
    session_ids: BTreeMap<u64, Clock>,
    salts: BTreeMap<Vec<u8>, Clock>,
    window: Window,
    retention: Duration,
    clock: Option<Clock>,
}

impl SessionReplay {
    /// `retention` 不得小于 60 秒（SIP022 最短 salt 记忆时长）。
    pub fn new(retention: Duration) -> Result<Self, Error> {
        if retention < Duration::from_secs(60) {
            return Err(Error::SessionPolicy);
        }
        Ok(Self {
            session_ids: BTreeMap::new(),
            salts: BTreeMap::new(),
            window: Window::new(u64::MAX),
            retention,
            clock: None,
        })
    }
    /// 当前仍被记忆的连接数（诊断与测试用）。
    pub fn remembered(&self) -> usize {
        self.session_ids.len()
    }

    fn validate_clock(&self, now: Clock) -> Result<(), Error> {
        if self.clock.is_some_and(|last| {
            now.unix_seconds < last.unix_seconds || now.monotonic < last.monotonic
        }) {
            return Err(Error::ClockRollback);
        }
        Ok(())
    }

    fn expired(&self, seen: Clock, now: Clock) -> bool {
        Self::expired_at(seen, now, self.retention)
    }

    /// 与 receiver.rs 同语义：±30 秒窗口含端点，须超过 60 整秒才证明过期。
    fn expired_at(seen: Clock, now: Clock, retention: std::time::Duration) -> bool {
        now.unix_seconds.saturating_sub(seen.unix_seconds) > 60
            && now
                .monotonic
                .checked_duration_since(seen.monotonic)
                .is_some_and(|age| age >= retention)
    }

    fn live_count(&self, now: Clock) -> usize {
        self.session_ids
            .values()
            .filter(|seen| !self.expired(**seen, now))
            .count()
    }

    /// 可信定时器可回收已证明过期的连接；不驱逐仍有效的连接。
    pub fn gc(&mut self, now: Clock) -> Result<(), Error> {
        self.validate_clock(now)?;
        let retention = self.retention;
        self.session_ids
            .retain(|_, seen| !Self::expired_at(*seen, now, retention));
        self.salts
            .retain(|_, seen| !Self::expired_at(*seen, now, retention));
        self.clock = Some(now);
        Ok(())
    }

    /// **仅在开场全部校验通过后调用**：收下该连接的 salt 与会话标识。
    /// 重复、时钟回退或记忆池已满一律拒绝，且拒绝不改变任何状态。
    pub fn accept(&mut self, salt: &[u8], session_id: u64, now: Clock) -> Result<(), Error> {
        self.accept_with(salt, session_id, now, MAX_TRACKED_SESSIONS)
    }

    /// 同 [`SessionReplay::accept`]，但由调用方注入记忆池容量。
    pub fn accept_with(
        &mut self,
        salt: &[u8],
        session_id: u64,
        now: Clock,
        capacity: usize,
    ) -> Result<(), Error> {
        self.validate_clock(now)?;
        if capacity == 0 || capacity > MAX_TRACKED_SESSIONS {
            return Err(Error::SessionPolicy);
        }
        if self
            .session_ids
            .get(&session_id)
            .is_some_and(|seen| !self.expired(*seen, now))
        {
            return Err(Error::Replay);
        }
        if self
            .salts
            .get(salt)
            .is_some_and(|seen| !self.expired(*seen, now))
        {
            return Err(Error::Replay);
        }
        match self.window.accept_authenticated(session_id) {
            Ok(()) => {}
            // 与最高标识相同或窗口内已记录：与记忆池结论一致，拒绝。
            Err(ss_core::replay::Error::Duplicate { .. }) => return Err(Error::Replay),
            // 随机标识无单调性：落在窗口外则以该标识重新起窗。
            Err(_) => {
                let mut restarted = Window::new(u64::MAX);
                restarted
                    .accept_authenticated(session_id)
                    .map_err(|_| Error::Replay)?;
                self.window = restarted;
            }
        }
        if self.live_count(now) >= capacity {
            return Err(Error::SessionCapacity);
        }
        // 全部检查通过才提交。
        self.gc(now)?;
        self.session_ids.insert(session_id, now);
        self.salts.insert(salt.to_vec(), now);
        Ok(())
    }
}

/// 一条流的接收侧状态；nonce 序列与线上 chunk 顺序严格一致。
pub struct Reader {
    key: Key,
    direction: Direction,
    aead: Option<SessionAead>,
    read_timeout: Duration,
    opened: bool,
    poisoned: bool,
}

impl Reader {
    /// `read_timeout` 必须为正；单次读取超时即永久 poison。
    pub fn new(key: Key, direction: Direction, read_timeout: Duration) -> Result<Self, Error> {
        if read_timeout.is_zero() {
            return Err(Error::SessionPolicy);
        }
        Ok(Self {
            key,
            direction,
            aead: None,
            read_timeout,
            opened: false,
            poisoned: false,
        })
    }
    /// 两个头部 chunk 是否已收下并通过校验。
    pub fn is_opened(&self) -> bool {
        self.opened
    }
    /// 是否已永久失效（此后一切调用一律 `Error::Poisoned`）。
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// 读取并校验开场。`expected_peer`：请求方向须为 `None`；响应方向须为本端
    /// 已验证的请求会话标识（`Some`），用于把响应流绑定回该请求流。
    /// 任一环节失败（含超时）都会 poison 本 Reader。
    pub async fn open<R: AsyncRead + Unpin>(
        &mut self,
        stream: &mut R,
        replay: &mut SessionReplay,
        now: Clock,
        expected_peer: Option<u64>,
    ) -> Result<Opened, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        match self.open_inner(stream, replay, now, expected_peer).await {
            Ok(opened) => Ok(opened),
            Err(error) => Err(self.fail(error)),
        }
    }

    async fn open_inner<R: AsyncRead + Unpin>(
        &mut self,
        stream: &mut R,
        replay: &mut SessionReplay,
        now: Clock,
        expected_peer: Option<u64>,
    ) -> Result<Opened, Error> {
        if self.opened {
            return Err(Error::SessionPolicy);
        }
        // 请求方向不接受关联标识，响应方向必须绑定已验证的请求会话。
        if expected_peer.is_some() != (self.direction == Direction::Response) {
            return Err(Error::Direction);
        }
        let mut salt = vec![0u8; self.key.method().key_len()];
        self.read_exact(stream, &mut salt).await?;
        // 每个方向独立 salt → 独立子密钥 → 独立 nonce 序列（从全 0 起）。
        let mut aead = SessionAead::new(suite(self.key.method()), self.key.subkey(&salt));
        let mut fixed_wire = [0u8; FIXED_HEADER_WIRE_LEN];
        self.read_exact(stream, &mut fixed_wire).await?;
        let header = self.read_header(&mut aead, &fixed_wire, now)?;
        let mut var_wire = vec![0u8; usize::from(header.var_len) + TAG_LEN];
        self.read_exact(stream, &mut var_wire).await?;
        let (association, payload) = self.read_association(&mut aead, &var_wire, &header)?;
        let association = match (association, expected_peer) {
            (Association::Response(peer), Some(expected)) if peer == expected => {
                Association::Response(peer)
            }
            // 响应的关联标识与本端请求会话不符：不是这条流的响应。
            (Association::Response(_), Some(_)) => return Err(Error::ClientSession),
            (Association::Request(_), Some(_)) => return Err(Error::Direction),
            (value, None) => value,
        };
        replay.accept(&salt, header.session_id, now)?;
        // 全部通过后才提交会话状态。
        self.aead = Some(aead);
        self.opened = true;
        Ok(Opened {
            session_id: header.session_id,
            timestamp: header.timestamp,
            association,
            payload,
        })
    }

    fn read_header(
        &self,
        aead: &mut SessionAead,
        wire: &[u8],
        now: Clock,
    ) -> Result<Header, Error> {
        let plain = aead.open(wire).map_err(map_core)?;
        if plain.len() != FIXED_HEADER_LEN {
            return Err(Error::Length);
        }
        let header = Header::decode(&plain)?;
        if header.kind != self.direction.header_type() {
            return Err(Error::Direction);
        }
        header.validate()?;
        // 时间窗比对注入时钟，绝不采信报文自述的时间。
        if header.timestamp.abs_diff(now.unix_seconds) > TIMESTAMP_WINDOW_SECS {
            return Err(Error::Timestamp);
        }
        Ok(header)
    }

    fn read_association(
        &self,
        aead: &mut SessionAead,
        wire: &[u8],
        header: &Header,
    ) -> Result<(Association, Vec<u8>), Error> {
        let plain = aead.open(wire).map_err(map_core)?;
        if plain.len() != usize::from(header.var_len) {
            return Err(Error::Length);
        }
        let (association, association_len) = match self.direction {
            Direction::Request => {
                let (target, used) = TargetAddr::decode(&plain).map_err(map_core)?;
                (Association::Request(target), used)
            }
            Direction::Response => {
                if plain.len() < RESPONSE_ASSOCIATION_LEN + PADDING_FIELD_LEN {
                    return Err(Error::Length);
                }
                let peer = u64::from_be_bytes(
                    plain[..RESPONSE_ASSOCIATION_LEN]
                        .try_into()
                        .map_err(|_| Error::Length)?,
                );
                (Association::Response(peer), RESPONSE_ASSOCIATION_LEN)
            }
        };
        let declared_end = association_len
            .checked_add(PADDING_FIELD_LEN)
            .ok_or(Error::Length)?;
        let declared = plain
            .get(association_len..declared_end)
            .ok_or(Error::Length)?;
        let padding = usize::from(u16::from_be_bytes(
            declared.try_into().map_err(|_| Error::Length)?,
        ));
        // 变长头内的 padding 字段必须与固定头声明精确一致。
        if padding != usize::from(header.padding) {
            return Err(Error::HeaderPadding);
        }
        let payload_start = declared_end.checked_add(padding).ok_or(Error::Length)?;
        if payload_start > plain.len() {
            return Err(Error::HeaderPadding);
        }
        // SIP022：既无载荷又无填充的头部必须拒绝（否则暴露固定长度特征）。
        if payload_start == plain.len() && padding == 0 {
            return Err(Error::HeaderPadding);
        }
        Ok((association, plain[payload_start..].to_vec()))
    }

    /// 读取一个载荷帧。`Ok(None)` 表示对端正常收尾（终止 chunk）。
    pub async fn read_payload<R: AsyncRead + Unpin>(
        &mut self,
        stream: &mut R,
    ) -> Result<Option<Vec<u8>>, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if !self.opened {
            return Err(self.fail(Error::SessionPolicy));
        }
        let aead = self.aead.as_mut().ok_or(Error::Poisoned)?;
        let result = match tokio::time::timeout(self.read_timeout, read_chunk(stream, aead)).await {
            Ok(Ok(chunk)) => Ok(chunk),
            Ok(Err(error)) => Err(map_core(error)),
            Err(_) => Err(Error::Timeout),
        };
        result.map_err(|error| self.fail(error))
    }

    async fn read_exact<R: AsyncRead + Unpin>(
        &self,
        stream: &mut R,
        buf: &mut [u8],
    ) -> Result<(), Error> {
        match tokio::time::timeout(self.read_timeout, stream.read_exact(buf)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                Err(Error::Length)
            }
            Ok(Err(error)) => Err(Error::Io(error)),
            Err(_) => Err(Error::Timeout),
        }
    }

    fn fail(&mut self, error: Error) -> Error {
        self.poisoned = true;
        self.aead = None;
        error
    }
}

/// 单调时钟起点用 `Instant::now`；`unix_seconds` 由可信运行时注入。
pub fn clock_at(unix_seconds: u64, monotonic: Instant) -> Clock {
    Clock {
        unix_seconds,
        monotonic,
    }
}
