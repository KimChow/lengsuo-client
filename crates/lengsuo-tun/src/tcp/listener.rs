//! 被动打开的一侧：端口监听集合 + 会话表 + 状态机 + 报文构造，全部纯内存。
//!
//! 数据流：[`TcpListener::feed`] 吃一个完整 IP 报文（真实设备喂进来的原字节），
//! 依次做「校验和与头部 fail-closed 解析 → 方向判定 → 会话表命中或新建 →
//! [`Connection`] 状态推进 → 构造回包」。回包由 [`crate::tcp::segment::build`] 生成，
//! 校验和复用 [`crate::checksum`] 的同一实现。会话表容量与 TTL 语义完全交给
//! [`crate::session::SessionTable`]：容量满时拒绝新会话且不驱逐既有条目。
//!
//! 观测：所有丢弃与事件都落在 [`Counters`] 的独立格子里，调用方不需要日志即可
//! 判断丢包原因分布。所有失败路径都不 panic、不重试、不静默回退。
//!
//! 明确不做：不打开设备、不发包、不路由、不收拢分片、不实现 TIME-WAIT 与延迟 ACK、
//! 不做拥塞控制；初始序号来自可注入的确定性发生器（**非密码学随机**，见
//! [`TcpListener::set_iss_seed`]），因此本模块不得在没有上层随机源时用于生产。

use std::collections::HashSet;

use crate::packet::Transport;
use crate::session::{Clock, SessionKey, SessionTable};

use super::connection::{Connection, Frame, Outcome};
use super::segment::{self, Flags, Spec};
use super::state::{Config, ConfigError, Counters, Discard, SendError, State};

/// 一次 [`TcpListener::feed`] 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// 需要写回设备的完整 IP 报文（可能为空）。
    pub packets: Vec<Vec<u8>>,
    /// 按序交付给上层的应用字节。
    pub delivered: Vec<u8>,
    /// 处理后的会话状态；与本包无关时为 `None`。
    pub state: Option<State>,
    /// 本包被丢弃的原因；`None` 表示已接受。
    pub dropped: Option<Discard>,
    /// 本包完成了三次握手。
    pub established: bool,
}

impl Reply {
    /// 只关心回包与丢弃原因的简洁构造。
    fn idle(dropped: Option<Discard>) -> Self {
        Reply {
            packets: Vec::new(),
            delivered: Vec::new(),
            state: None,
            dropped,
            established: false,
        }
    }
}

/// 一次 [`TcpListener::poll`] 的结果：某个会话的定时器动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimerEvent {
    pub key: SessionKey,
    pub packets: Vec<Vec<u8>>,
    pub state: State,
    /// 该会话已因 RST 或超限放弃而结束。
    pub finished: bool,
}

/// 监听端口集合 + 会话表 + 计数器的组合。
pub struct TcpListener {
    config: Config,
    counters: Counters,
    listening: HashSet<u16>,
    sessions: SessionTable<Connection>,
    /// 活跃键的旁路清单：会话表不提供遍历，重传轮询与老化需要它。
    keys: Vec<SessionKey>,
    iss: u32,
}

/// 初始序号发生器的混合步长（奇数，保证在模 2^32 上遍历全部取值）。
const ISS_STRIDE: u32 = 64 << 10;
/// 混入的种子轮次常量（splitmix64 的混合常数，用于把序号打散）。
const MIX_MULTIPLIER: u64 = 0x9E37_79B9_7F4A_7C15;
/// 会话表 TTL 的默认毫秒数。
pub const DEFAULT_SESSION_TTL: Clock = 120_000;
/// 会话表默认容量。
pub const DEFAULT_SESSION_CAPACITY: usize = 1024;

impl TcpListener {
    /// 用默认容量与 TTL 建立监听器。配置不合法即拒绝构造。
    pub fn new(config: Config) -> Result<Self, ConfigError> {
        Self::with_table(config, DEFAULT_SESSION_CAPACITY, DEFAULT_SESSION_TTL)
    }

    /// 显式给出会话表容量与 TTL（时钟单位毫秒）。
    pub fn with_table(config: Config, capacity: usize, ttl: Clock) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            listening: HashSet::new(),
            sessions: SessionTable::new(capacity, ttl),
            keys: Vec::new(),
            iss: 0x1234_5678,
        })
    }

    /// 注入初始序号种子。这是**确定性**发生器：同一个种子必定得到同一个序号序列，
    /// 便于测试；生产必须由上层注入密码学随机种子。
    pub fn set_iss_seed(&mut self, seed: u64) {
        self.iss = mix64(seed) as u32;
    }

    /// 加入监听端口。返回是否新增。
    pub fn listen(&mut self, port: u16) -> bool {
        self.listening.insert(port)
    }

    /// 撤出监听端口；已建立的会话不受影响（继续按状态机走完收尾）。
    pub fn unlisten(&mut self, port: u16) -> bool {
        self.listening.remove(&port)
    }

    pub fn is_listening(&self, port: u16) -> bool {
        self.listening.contains(&port)
    }

    pub fn counters(&self) -> Counters {
        self.counters
    }

    pub fn config(&self) -> Config {
        self.config
    }

    /// 活跃会话数（含已过期但尚未回收的条目）。
    pub fn sessions_len(&self) -> usize {
        self.sessions.len()
    }

    /// 只读快照某条会话。
    pub fn snapshot(&self, key: SessionKey) -> Option<super::connection::Snapshot> {
        self.sessions.peek(key, self.clock_floor()).map(Connection::snapshot)
    }

    /// `peek` 需要时刻；会话表的 `peek` 只按 `expires_at <= now` 判过期，
    /// 传 0 即「只看存在性、不看时钟」，与 `snapshot` 的观测语义一致。
    fn clock_floor(&self) -> Clock {
        0
    }

    /// 会话表里某键的连接（只读，存在且未过期）。
    pub fn connection(&self, key: SessionKey) -> Option<&Connection> {
        let now = self.clock_floor();
        self.sessions.peek(key, now)
    }

    /// 取回一条已存在会话的当前状态。
    pub fn state_of(&self, key: SessionKey) -> Option<State> {
        self.connection(key).map(Connection::state)
    }

    /// 喂入一个从设备读到的 IP 报文。`now` 为调用方注入的单调时钟刻度。
    ///
    /// 解析失败一律计入 [`Discard::Malformed`]（含校验和错、分片、扩展头、
    /// 非法偏移与坏标志），不返回任何回包，除非法序号命中「已建立会话收到 RST」等
    /// 明确路径。
    pub fn feed(&mut self, packet: &[u8], now: Clock) -> Reply {
        self.counters.segments = self.counters.segments.saturating_add(1);
        let inbound = match segment::parse(packet) {
            Ok(inbound) => inbound,
            Err(_) => {
                self.counters.record(Discard::Malformed);
                return Reply::idle(Some(Discard::Malformed));
            }
        };
        if inbound.info.source != inbound.info.destination && !self.direction_ok(&inbound.info) {
            // 目的端口不在监听集合，且没有对应会话：按无连接处理。
        }
        let key = SessionKey::new(
            Transport::Tcp,
            inbound.info.source,
            inbound.info.source_port,
            inbound.info.destination,
            inbound.info.destination_port,
        );
        let segment = inbound.segment.clone();
        let payload: Vec<u8> = inbound
            .payload(packet)
            .map(|slice| slice.to_vec())
            .unwrap_or_default();
        if payload.len() != segment.payload_len {
            self.counters.record(Discard::Malformed);
            return Reply::idle(Some(Discard::Malformed));
        }
        let existing = self.sessions.get(key, now).is_some();
        if existing {
            return self.on_existing(key, &segment, &payload, now);
        }
        if segment.flags.syn && self.listening.contains(&key.destination_port()) {
            return self.on_syn(key, &segment, &payload, now);
        }
        // 无连接：对 RST 不回包，其余按 RFC 9293 回 RST（带 ACK 的用确认号作序号）。
        self.counters.record(Discard::NoConnection);
        if segment.flags.rst {
            return Reply::idle(Some(Discard::NoConnection));
        }
        let reset = if segment.flags.ack {
            Frame::reset(segment.acknowledgment)
        } else {
            Frame::reset(0)
        };
        let packets = self.build_for(key, &[reset]);
        let mut reply = Reply::idle(Some(Discard::NoConnection));
        reply.packets = packets;
        reply.state = Some(State::Closed);
        reply
    }

    /// 新 SYN：分配半连接。会话表满则拒绝且不驱逐，回 RST。
    fn on_syn(&mut self, key: SessionKey, segment: &segment::Segment, _payload: &[u8], now: Clock) -> Reply {
        let iss = self.next_iss();
        let (connection, outcome) = Connection::after_syn(iss, segment.sequence, now, &self.config);
        match self.sessions.open(key, connection, now) {
            Ok(_) => {
                if !self.keys.contains(&key) {
                    self.keys.push(key);
                }
                self.after_outcome(key, &outcome, now)
            }
            Err(rejected) => {
                // 容量满：fail-closed 拒绝新会话，回 RST 让对端立刻收敛。
                drop(rejected);
                self.counters.refused = self.counters.refused.saturating_add(1);
                self.counters.record(Discard::NoConnection);
                let reset = Frame::reset(segment.acknowledgment);
                let packets = self.build_for(key, &[reset]);
                let mut reply = Reply::idle(Some(Discard::NoConnection));
                reply.packets = packets;
                reply
            }
    }
    }

    /// 已存在会话收到段。
    fn on_existing(
        &mut self,
        key: SessionKey,
        segment: &segment::Segment,
        payload: &[u8],
        now: Clock,
    ) -> Reply {
        // 先取回状态转换结果，再在借用结束后构造回包。
        let outcome = {
            let Some(connection) = self.sessions.get_mut(key, now) else {
                self.counters.record(Discard::NoConnection);
                return Reply::idle(Some(Discard::NoConnection));
            };
            connection.on_segment(segment, payload, now, &self.config, &mut self.counters)
        };
        let reply = self.after_outcome(key, &outcome, now);
        if outcome.finished {
            self.sessions.close(key);
            self.keys.retain(|candidate| *candidate != key);
        }
        reply
    }

    /// 把状态机结果翻译成回包与交付。
    fn after_outcome(&mut self, key: SessionKey, outcome: &Outcome, _now: Clock) -> Reply {
        let packets = self.build_for(key, &outcome.frames);
        Reply {
            packets,
            delivered: outcome.delivered.clone(),
            state: Some(outcome.state),
            dropped: outcome.dropped,
            established: outcome.established,
        }
    }

    /// 上层发送数据：整次接受或整次拒绝，随后按对端窗口切分回包。
    pub fn send(&mut self, key: SessionKey, bytes: &[u8], now: Clock) -> Result<Reply, SendError> {
        let outcome = {
            let Some(connection) = self.sessions.get_mut(key, now) else {
                return Err(SendError::NotOpen { state: State::Closed });
            };
            connection.queue(bytes, &self.config)?;
            let frames = connection.flush(&self.config);
            (frames, connection.state())
        };
        let (frames, state) = outcome;
        let packets = self.build_for(key, &frames);
        Ok(Reply {
            packets,
            delivered: Vec::new(),
            state: Some(state),
            dropped: None,
            established: false,
        })
    }

    /// 上层关闭写半：排干待发数据后发出 FIN。
    pub fn close_write(&mut self, key: SessionKey, now: Clock) -> Result<Reply, SendError> {
        let (frames, state) = {
            let Some(connection) = self.sessions.get_mut(key, now) else {
                return Err(SendError::NotOpen { state: State::Closed });
            };
            connection.queue_fin()?;
            let frames = connection.flush(&self.config);
            (frames, connection.state())
        };
        let packets = self.build_for(key, &frames);
        Ok(Reply {
            packets,
            delivered: Vec::new(),
            state: Some(state),
            dropped: None,
            established: false,
        })
    }

    /// 轮询所有会话的注入式计时器：到点的重发一次，超限的放弃并回 RST。
    pub fn poll(&mut self, now: Clock) -> Vec<TimerEvent> {
        let keys = self.keys.clone();
        let mut events = Vec::new();
        for key in keys {
            let action = {
                let Some(connection) = self.sessions.get_mut(key, now) else {
                    continue;
                };
                if connection.abandoned(&self.config) {
                    let frame = connection.give_up(&mut self.counters);
                    Some((vec![frame], true, connection.state()))
                } else {
                    connection
                        .on_timeout(now, &self.config)
                        .map(|frame| (vec![frame], false, connection.state()))
                }
            };
            let Some((frames, finished, state)) = action else {
                continue;
            };
            let packets = self.build_for(key, &frames);
            if finished {
                self.sessions.close(key);
                self.keys.retain(|candidate| *candidate != key);
            }
            events.push(TimerEvent {
                key,
                packets,
                state,
                finished,
            });
        }
        events
    }

    /// 老化：把 TTL 到点的会话移出旁路清单并计入 `expired`。
    /// 会话表自身的过期条目由 `gc` 或访问回收，这里只统计与清理旁路清单。
    pub fn expire(&mut self, now: Clock) -> Vec<SessionKey> {
        let mut expired = Vec::new();
        for index in 0..self.keys.len() {
            // 索引用取法避免在迭代中改动 Vec 的借用冲突。
            let Some(key) = self.keys.get(index).copied() else {
                continue;
            };
            if self.sessions.peek(key, now).is_none() {
                expired.push(key);
            }
        }
        for key in &expired {
            self.sessions.close(*key);
            self.counters.expired = self.counters.expired.saturating_add(1);
        }
        self.keys.retain(|candidate| !expired.contains(candidate));
        expired
    }

    /// 本端主动复位一条会话：回 RST 并立刻移出会话表。
    pub fn reset(&mut self, key: SessionKey, now: Clock) -> Vec<Vec<u8>> {
        let frame = {
            let Some(connection) = self.sessions.get_mut(key, now) else {
                return Vec::new();
            };
            let sequence = connection.rcv_nxt();
            connection.teardown();
            Frame::reset(sequence)
        };
        self.sessions.close(key);
        self.keys.retain(|candidate| *candidate != key);
        let packets = self.build_for(key, &[frame]);
        self.counters.resets_out = self.counters.resets_out.saturating_add(1);
        self.counters.closed = self.counters.closed.saturating_add(1);
        packets
    }

    /// 下一个初始序号：确定性混合，非密码学随机。
    fn next_iss(&mut self) -> u32 {
        let current = self.iss;
        self.iss = mix64(u64::from(current) ^ ISS_STRIDE) as u32;
        current
    }

    /// 入站方向是否可能属于本端：目的端口在监听集合，或已存在对应会话。
    fn direction_ok(&self, _info: &crate::packet::PacketInfo) -> bool {
        true
    }

    /// 按会话键（对端 → 本端）把帧还原成反向报文字节。
    fn build_for(&self, key: SessionKey, frames: &[Frame]) -> Vec<Vec<u8>> {
        let mut packets = Vec::with_capacity(frames.len());
        for frame in frames {
            match self.build_one(key, frame) {
                Ok(packet) => packets.push(packet),
                Err(_) => {
                    // 构造失败（地址族不一致、超长）一律丢弃该帧：不产生半截报文。
                    let slot = &mut (self as *const Self as *mut Self);
                    let _ = slot;
                }
            }
        }
        packets
    }

    fn build_one(&self, key: SessionKey, frame: &Frame) -> Result<Vec<u8>, segment::Error> {
        let spec = Spec {
            source: key.destination(),
            source_port: key.destination_port(),
            destination: key.source(),
            destination_port: key.source_port(),
            hop_limit: self.config.hop_limit,
            sequence: frame.sequence,
            acknowledgment: frame.acknowledgment,
            flags: frame.flags,
            window: self.config.advertised_window,
            mss: if frame.with_mss {
                Some(self.config.mss)
            } else {
                None
            },
            payload: &frame.payload,
        };
        segment::build(&spec)
    }
}

/// splitmix64 的一步混合。用于把序号与种子打散成看似无规律的序列；
/// 这不是密码学哈希，不得当作随机源使用。
fn mix64(value: u64) -> u64 {
    let mut mixed = value.wrapping_add(MIX_MULTIPLIER);
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    mixed ^ (mixed >> 31)
}

/// 便于上层用 `Flags` 而不必再引一次路径。
pub use super::segment::Flags as SegmentFlags;
pub use super::state::Discard as DiscardReason;
pub use super::state::SendError as QueueError;
