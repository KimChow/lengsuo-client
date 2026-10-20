//! SIP022 TCP 接收侧：salt → 固定头 chunk [→ 变长头 chunk | 首批载荷 chunk] → 载荷帧。
//!
//! 校验顺序（全部通过后才提交状态）：AEAD 认证 → 固定头自洽（type / salt 形态 /
//! 声明长）→ 注入时钟的时间窗 → 响应归属（request salt 逐字节比对）→ 变长头认证
//! 与关联块、padding 精确校验 → salt 防重放记忆池。任一步失败或单次读超时都永久
//! poison 本 [`Reader`]：不降级明文、不用半途状态重试、不消费后续帧。
//!
//! §3.1.2：请求流 = salt + 固定头 chunk（声明变长头长）+ 变长头 chunk；响应流 =
//! salt + 固定头 chunk（本身即第一个 length chunk，声明首批载荷 chunk 明文长），
//! 没有变长头。两个方向其后都接 length/payload chunk 对，u96le nonce 跨流连续。
use ss_core::{
    crypto::{SessionAead, TAG_LEN},
    target::TargetAddr,
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{
    fixed_header_wire_len, header::FixedHeader, map_core, read_chunk, salt_len, suite, Direction,
    PADDING_FIELD_LEN, TIMESTAMP_WINDOW_SECS,
};
use crate::{crypto::Key, receiver::Clock, Error};

/// salt 记忆池容量上限（本项目策略，不是协议常量）。
pub const MAX_TRACKED_SALTS: usize = 4096;

/// 开场关联块：请求为目标地址（变长头内），响应为原样回传的请求 salt。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Association {
    /// 请求流：SOCKS5 目标地址。
    Request(TargetAddr),
    /// 响应流：固定头携带的请求 salt 全量（16/32 字节），用于归属到请求流。
    Response(Vec<u8>),
}

/// 开场（salt + 固定头 [+ 变长头 / 首批载荷]）全部校验通过后的会话信息。
/// 不含 Debug，避免目标地址进入日志。
pub struct Opened {
    pub timestamp: u64,
    /// 请求方向自己的 salt：服务器用它派生同流响应子密钥（同流双向共用子密钥）。
    pub request_salt: Vec<u8>,
    pub association: Association,
    /// 请求：变长头携带的首批载荷；响应：固定头声明长度的载荷 chunk。可为空。
    pub payload: Vec<u8>,
}

/// salt 防重放记忆池（SIP022 §3.1.4）。
///
/// 服务端必须把所有到达 salt 存 60 秒，精确重复一律拒绝；TCP 流内没有会话标识
/// 字段，salt 是唯一可记忆的连接标识。规范明确禁止 Bloom filter 之类可能误判的
/// 结构，因此用 `BTreeMap<Vec<u8>, Clock>` 精确集合。超过 `retention`（且 Unix
/// 时间严格超过 60 整秒，与 `receiver.rs` 同语义）才回收，不驱逐仍有效的 salt。
/// 时钟回退拒绝；任何拒绝都不修改池状态（全部检查通过才提交）。
pub struct SessionReplay {
    salts: BTreeMap<Vec<u8>, Clock>,
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
            salts: BTreeMap::new(),
            retention,
            clock: None,
        })
    }
    /// 当前仍被记忆的 salt 数（诊断与测试用）。
    pub fn remembered(&self) -> usize {
        self.salts.len()
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
        self.salts
            .values()
            .filter(|seen| !self.expired(**seen, now))
            .count()
    }

    /// 可信定时器可回收已证明过期的 salt；不驱逐仍有效的 salt。
    pub fn gc(&mut self, now: Clock) -> Result<(), Error> {
        self.validate_clock(now)?;
        let retention = self.retention;
        self.salts
            .retain(|_, seen| !Self::expired_at(*seen, now, retention));
        self.clock = Some(now);
        Ok(())
    }

    /// **仅在开场全部校验通过后调用**：收下该连接的 salt。
    /// 重复、时钟回退或记忆池已满一律拒绝，且拒绝不改变任何状态。
    pub fn accept(&mut self, salt: &[u8], now: Clock) -> Result<(), Error> {
        self.accept_with(salt, now, MAX_TRACKED_SALTS)
    }

    /// 同 [`SessionReplay::accept`]，但由调用方注入记忆池容量。
    pub fn accept_with(&mut self, salt: &[u8], now: Clock, capacity: usize) -> Result<(), Error> {
        self.validate_clock(now)?;
        if capacity == 0 || capacity > MAX_TRACKED_SALTS {
            return Err(Error::SessionPolicy);
        }
        if self
            .salts
            .get(salt)
            .is_some_and(|seen| !self.expired(*seen, now))
        {
            return Err(Error::Replay);
        }
        if self.live_count(now) >= capacity {
            return Err(Error::SessionCapacity);
        }
        // 全部检查通过才提交。
        self.gc(now)?;
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
    /// 开场 chunk 是否已收下并通过校验。
    pub fn is_opened(&self) -> bool {
        self.opened
    }
    /// 是否已永久失效（此后一切调用一律 `Error::Poisoned`）。
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// 读取并校验开场。`expected_peer`：请求方向须为 `None`；响应方向须为本端
    /// 请求流的 salt（`Some`），固定头回传的 request salt 与之逐字节比对，不符
    /// 即不是这条流的响应。任一环节失败（含超时）都会 poison 本 Reader。
    pub async fn open<R: AsyncRead + Unpin>(
        &mut self,
        stream: &mut R,
        replay: &mut SessionReplay,
        now: Clock,
        expected_peer: Option<&[u8]>,
    ) -> Result<Opened, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        match self
            .open_inner(stream, replay, now, expected_peer, None)
            .await
        {
            Ok(opened) => Ok(opened),
            Err(error) => Err(self.fail(error)),
        }
    }

    /// 同 [`Reader::open`]，但 salt 已由调用方读出（SIP023 多用户服务端在
    /// 解析身份头时必然先读到 salt）。salt 长度必须等于套件密钥长度；本方法
    /// 从固定头 chunk 开始读。身份头解析失败时调用方根本不会走到这里。
    pub async fn open_after_salt<R: AsyncRead + Unpin>(
        &mut self,
        stream: &mut R,
        replay: &mut SessionReplay,
        now: Clock,
        expected_peer: Option<&[u8]>,
        salt: Vec<u8>,
    ) -> Result<Opened, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        match self
            .open_inner(stream, replay, now, expected_peer, Some(salt))
            .await
        {
            Ok(opened) => Ok(opened),
            Err(error) => Err(self.fail(error)),
        }
    }

    async fn open_inner<R: AsyncRead + Unpin>(
        &mut self,
        stream: &mut R,
        replay: &mut SessionReplay,
        now: Clock,
        expected_peer: Option<&[u8]>,
        ahead_salt: Option<Vec<u8>>,
    ) -> Result<Opened, Error> {
        if self.opened {
            return Err(Error::SessionPolicy);
        }
        // 请求方向不接受归属 salt，响应方向必须绑定本端请求 salt。
        if expected_peer.is_some() != self.direction.carries_request_salt() {
            return Err(Error::Direction);
        }
        let salt_len = salt_len(&self.key);
        let salt = match ahead_salt {
            Some(salt) if salt.len() == salt_len => salt,
            Some(_) => return Err(Error::KeyLength),
            None => {
                let mut salt = vec![0u8; salt_len];
                self.read_exact(stream, &mut salt).await?;
                salt
            }
        };
        // 每个方向独立 salt → 独立子密钥 → 独立 nonce 序列（从全 0 起）。
        let mut aead = SessionAead::new(suite(self.key.method()), self.key.subkey(&salt));
        let mut fixed_wire = vec![0u8; fixed_header_wire_len(self.direction, salt_len)];
        self.read_exact(stream, &mut fixed_wire).await?;
        let header = self.read_fixed_header(&mut aead, &fixed_wire, now)?;
        let (association, payload) = match self.direction {
            Direction::Request => {
                // 固定头的 length 声明紧随其后的变长头 chunk 明文长。
                let mut var_wire = vec![0u8; usize::from(header.length) + TAG_LEN];
                self.read_exact(stream, &mut var_wire).await?;
                self.read_variable_header(&mut aead, &var_wire)?
            }
            Direction::Response => {
                // §3.1.3：响应固定头原样回传请求 salt，客户端必须逐字节核对。
                match expected_peer {
                    Some(expected) if expected == header.request_salt.as_slice() => {}
                    Some(_) => return Err(Error::ClientSession),
                    None => return Err(Error::Direction),
                }
                // 固定头同时是第一个 length chunk：length = 首批载荷 chunk 明文长。
                let payload = self.read_first_payload(stream, &mut aead, &header).await?;
                (Association::Response(header.request_salt.clone()), payload)
            }
        };
        replay.accept(&salt, now)?;
        // 全部通过后才提交会话状态。
        self.aead = Some(aead);
        self.opened = true;
        Ok(Opened {
            timestamp: header.timestamp,
            request_salt: salt,
            association,
            payload,
        })
    }

    fn read_fixed_header(
        &self,
        aead: &mut SessionAead,
        wire: &[u8],
        now: Clock,
    ) -> Result<FixedHeader, Error> {
        let plain = aead.open(wire).map_err(map_core)?;
        let header = FixedHeader::decode(self.direction, salt_len(&self.key), &plain)?;
        header.validate(self.direction)?;
        // 时间窗比对注入时钟，绝不采信报文自述的时间。
        if header.timestamp.abs_diff(now.unix_seconds) > TIMESTAMP_WINDOW_SECS {
            return Err(Error::Timestamp);
        }
        Ok(header)
    }

    /// 请求变长头：`ATYP+地址+port | padding_len(u16be) | padding | 首批载荷`。
    fn read_variable_header(
        &self,
        aead: &mut SessionAead,
        wire: &[u8],
    ) -> Result<(Association, Vec<u8>), Error> {
        let plain = aead.open(wire).map_err(map_core)?;
        let (target, association_len) = TargetAddr::decode(&plain).map_err(map_core)?;
        let declared_end = association_len
            .checked_add(PADDING_FIELD_LEN)
            .ok_or(Error::Length)?;
        let declared = plain
            .get(association_len..declared_end)
            .ok_or(Error::Length)?;
        let padding = usize::from(u16::from_be_bytes(
            declared.try_into().map_err(|_| Error::Length)?,
        ));
        // padding 声明不得超过 SIP022 MaxPaddingLength。
        FixedHeader::check_padding_decl(padding as u16)?;
        let payload_start = declared_end.checked_add(padding).ok_or(Error::Length)?;
        if payload_start > plain.len() {
            return Err(Error::HeaderPadding);
        }
        let payload = plain[payload_start..].to_vec();
        // SIP022：既无载荷又无填充的头部必须拒绝（否则暴露固定长度特征）。
        if payload.is_empty() && padding == 0 {
            return Err(Error::HeaderPadding);
        }
        Ok((Association::Request(target), payload))
    }

    /// 响应固定头声明的首批载荷 chunk（length == 0 表示开场不带载荷）。
    async fn read_first_payload<R: AsyncRead + Unpin>(
        &self,
        stream: &mut R,
        aead: &mut SessionAead,
        header: &FixedHeader,
    ) -> Result<Vec<u8>, Error> {
        if header.length == 0 {
            return Ok(Vec::new());
        }
        let mut payload_wire = vec![0u8; usize::from(header.length) + TAG_LEN];
        self.read_exact(stream, &mut payload_wire).await?;
        aead.open(&payload_wire).map_err(map_core)
    }

    /// 读取一个载荷帧（length chunk + payload chunk）。`Ok(None)` 表示对端正常
    /// 收尾（终止 chunk）。响应与请求方向共用，chunk nonce 跨流连续。
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
            Ok(Err(error)) => Err(error),
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
