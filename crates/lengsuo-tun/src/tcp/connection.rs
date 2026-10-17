//! 单条被动打开会话的序号与状态推进：只接受已解析的 [`Segment`]，不解析字节、
//! 不构造报文、不做 IO。所有上限取自注入的 [`Config`]，所有时间取自调用方传入的
//! [`Clock`]，因此行为完全确定、可在纯内存里穷举验证。
//!
//! 固定处理次序：载荷长度自洽 → RST → 重复 SYN → 确认号合法 → 确认推进 →
//! 接收侧序号 → 收尾。任何一步不合法都返回 [`Discard`] 交由上层计数；本模块
//! **没有 `panic!`、`unwrap`、`expect` 与裸索引切片**，序号比较全部走回绕安全的模运算。
//!
//! 与 RFC 9293 的有意差异（不得对外声称完全一致）：
//! - 不实现半连接队列分级、TIME-WAIT、延迟 ACK 合并、非法 ACK 的 challenge ACK；
//! - 不实现窗口缩放、SACK、紧急数据与拥塞控制；接收窗口恒等于配置的宣告值，
//!   不随失序缓冲的占用而收缩；
//! - 主动关闭（在 ESTABLISHED 就发出 FIN）复用 `LastAck` 表示「本端 FIN 未确认」，
//!   不引入 FIN-WAIT 状态；
//! - 本端 FIN 已发出后，对端继续送来的数据或重复 FIN 一律按 [`Discard::AfterFinish`]
//!   丢弃，因此同时交换 FIN 的收尾路径在本栈不成立。

use std::collections::VecDeque;

use crate::session::Clock;

use super::segment::{Flags, Segment};
use super::state::{
    seq_ge, seq_gt, seq_le, seq_lt, seq_within, Config, Counters, Discard, SendError, State,
};

/// 本端要发出的一帧。构造完整报文由 `listener` 负责——只有它知道地址与端口。
/// 每帧自带序号与确认号，因此 `Data`/`Fin` 天然捎带确认，不需要另发一帧 ACK。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub flags: Flags,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub payload: Vec<u8>,
    /// 是否携带 MSS 选项（只有 SYN-ACK 为真）。
    pub with_mss: bool,
}

impl Frame {
    fn plain(flags: Flags, sequence: u32, acknowledgment: u32, payload: Vec<u8>) -> Self {
        Frame {
            flags,
            sequence,
            acknowledgment,
            payload,
            with_mss: false,
        }
    }

    fn syn_ack(iss: u32, acknowledgment: u32) -> Self {
        Frame {
            flags: Flags::SYN_ACK,
            sequence: iss,
            acknowledgment,
            payload: Vec::new(),
            with_mss: true,
        }
    }

    /// 复位帧：序号取对端确认号（对端已确认到哪），不携带 ACK 位。
    pub fn reset(acknowledgment: u32) -> Self {
        Frame::plain(
            Flags {
                rst: true,
                ..Flags::NONE
            },
            acknowledgment,
            0,
            Vec::new(),
        )
    }
}

/// 一次输入的处理结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// 需要发出的帧（可能为空）。
    pub frames: Vec<Frame>,
    /// 按序交付给上层的应用字节。
    pub delivered: Vec<u8>,
    /// 处理后的状态。
    pub state: State,
    /// 本段被丢弃的原因；`None` 表示已接受。
    pub dropped: Option<Discard>,
    /// 会话已结束（正常收尾或被复位拆除），上层应把条目移出会话表。
    pub finished: bool,
    /// 本次输入完成了三次握手。
    pub established: bool,
}

impl Outcome {
    fn new(state: State) -> Self {
        Outcome {
            frames: Vec::new(),
            delivered: Vec::new(),
            state,
            dropped: None,
            finished: false,
            established: false,
        }
    }

    fn silent(state: State, dropped: Discard) -> Self {
        let mut outcome = Outcome::new(state);
        outcome.dropped = Some(dropped);
        outcome
    }
}

/// 失序缓冲中的一个块。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Block {
    sequence: u32,
    bytes: Vec<u8>,
    fin: bool,
}

/// 一条会话的序号、窗口、缓冲与计时状态。
#[derive(Debug, Clone)]
pub struct Connection {
    state: State,
    /// 本端初始序号：SYN-ACK 自身占 1 个序号，首个数据字节自 `iss + 1` 起。
    iss: u32,
    /// 对端初始序号。
    irs: u32,
    /// 最旧的未确认序号。
    snd_una: u32,
    /// 下一个待发送序号。
    snd_nxt: u32,
    /// 下一个期望接收的序号。
    rcv_nxt: u32,
    /// 对端宣告的接收窗口（不做缩放）。
    peer_window: u16,
    /// 已发出且未确认的字节。
    inflight: VecDeque<u8>,
    /// 已发出且未确认的本端 FIN。
    fin_inflight: bool,
    /// 本端是否已发出过 FIN。
    fin_sent: bool,
    /// 排队待发的字节。
    pending: VecDeque<u8>,
    /// 排干待发字节后需要发出 FIN。
    fin_pending: bool,
    /// 已收到对端 FIN。
    peer_fin: bool,
    gaps: Vec<Block>,
    gap_bytes: usize,
    /// 下一次重传的时间点（注入式时钟刻度）。
    timer: Clock,
    /// 同一内容连续重传次数；收到新确认即归零。
    retransmits: u32,
}

/// 接收侧一次判定的结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reception {
    /// 未接受本段（原因已由接收函数计数）。
    Rejected,
    /// 接受且没有新字节可交付（失序缓冲或直接命中已确认区间）。
    Buffered,
    /// 接受并有新内容需要确认。
    Acknowledge,
}

impl Connection {
    /// 收到合法 SYN 后建立半连接：状态 `SynReceived`，并给出待回的 SYN-ACK。
    pub fn after_syn(iss: u32, irs: u32, now: Clock, config: &Config) -> (Self, Outcome) {
        let connection = Self {
            state: State::SynReceived,
            iss,
            irs,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            rcv_nxt: irs.wrapping_add(1),
            peer_window: 0,
            inflight: VecDeque::new(),
            fin_inflight: false,
            fin_sent: false,
            pending: VecDeque::new(),
            fin_pending: false,
            peer_fin: false,
            gaps: Vec::new(),
            gap_bytes: 0,
            timer: now.saturating_add(config.retransmit_timeout_ms),
            retransmits: 0,
        };
        let mut outcome = Outcome::new(connection.state);
        outcome
            .frames
            .push(Frame::syn_ack(iss, connection.rcv_nxt));
        (connection, outcome)
    }

    // ---- 只读访问器 ----
    pub fn state(&self) -> State {
        self.state
    }
    pub fn iss(&self) -> u32 {
        self.iss
    }
    pub fn irs(&self) -> u32 {
        self.irs
    }
    pub fn rcv_nxt(&self) -> u32 {
        self.rcv_nxt
    }
    pub fn snd_nxt(&self) -> u32 {
        self.snd_nxt
    }
    pub fn snd_una(&self) -> u32 {
        self.snd_una
    }
    pub fn peer_window(&self) -> u16 {
        self.peer_window
    }
    pub fn pending_bytes(&self) -> usize {
        self.pending.len()
    }
    pub fn inflight_bytes(&self) -> usize {
        self.inflight.len()
    }
    pub fn gap_bytes(&self) -> usize {
        self.gap_bytes
    }
    pub fn timer(&self) -> Clock {
        self.timer
    }
    pub fn retransmits(&self) -> u32 {
        self.retransmits
    }

    /// 已发出序号区间的上界（不含）。`snd_nxt` 本身就记录了最高已发序号 + 1。
    fn snd_max(&self) -> u32 {
        self.snd_nxt
    }

    /// 本端接收窗口右界（不含）。
    fn rcv_max(&self, config: &Config) -> u32 {
        self.rcv_nxt.wrapping_add(u32::from(config.advertised_window))
    }

    /// 入站段入口。`payload` 必须是该段解析出的载荷切片。
    pub fn on_segment(
        &mut self,
        segment: &Segment,
        payload: &[u8],
        now: Clock,
        config: &Config,
        counters: &mut Counters,
    ) -> Outcome {
        if payload.len() != segment.payload_len {
            // 调用方交来的切片长度与段声明不一致：fail-closed，不做任何状态转换。
            counters.record(Discard::Malformed);
            return Outcome::silent(self.state, Discard::Malformed);
        }
        if segment.flags.rst {
            return self.on_rst(segment, config, counters);
        }
        match self.state {
            State::Closed => {
                counters.record(Discard::NoConnection);
                let mut outcome = Outcome::silent(State::Closed, Discard::NoConnection);
                outcome.finished = true;
                outcome
            }
            State::Listen => {
                // 会话表里的条目不会是 Listen；防御性分支，不 panic。
                counters.record(Discard::NoConnection);
                Outcome::silent(self.state, Discard::NoConnection)
            }
            State::SynReceived => self.on_syn_received(segment, payload, now, config, counters),
            State::Established | State::CloseWait | State::LastAck => {
                if segment.flags.syn {
                    counters.record(Discard::BadSequence);
                    return Outcome::silent(self.state, Discard::BadSequence);
                }
                self.on_open(segment, payload, now, config, counters)
            }
        }
    }

    /// 半连接状态下收到 SYN：序号相同视为对端重传，重发 SYN-ACK。
    fn on_syn_received(
        &mut self,
        segment: &Segment,
        payload: &[u8],
        now: Clock,
        config: &Config,
        counters: &mut Counters,
    ) -> Outcome {
        if segment.flags.syn {
            if segment.sequence == self.irs {
                counters.syn_retransmits = counters.syn_retransmits.saturating_add(1);
                self.timer = now.saturating_add(config.retransmit_timeout_ms);
                let mut outcome = Outcome::new(self.state);
                outcome
                    .frames
                    .push(Frame::syn_ack(self.iss, self.rcv_nxt));
                return outcome;
            }
            counters.record(Discard::BadSequence);
            return Outcome::silent(self.state, Discard::BadSequence);
        }
        if !segment.flags.ack {
            counters.record(Discard::BadSequence);
            return Outcome::silent(self.state, Discard::BadSequence);
        }
        // 必须恰好确认 SYN-ACK；确认号越界一律按非法序号丢弃。
        if segment.acknowledgment != self.snd_nxt {
            counters.record(Discard::BadSequence);
            return Outcome::silent(self.state, Discard::BadSequence);
        }
        self.state = State::Established;
        self.snd_una = segment.acknowledgment;
        self.peer_window = segment.window;
        self.retransmits = 0;
        counters.established = counters.established.saturating_add(1);
        let mut outcome = self.on_open(segment, payload, now, config, counters);
        outcome.established = true;
        outcome.state = self.state;
        // 第三次握手本身已是确认：无新内容时不再回一帧空 ACK（避免确认风暴）。
        if outcome.delivered.is_empty()
            && !segment.flags.fin
            && outcome.dropped.is_none()
            && outcome.frames.iter().all(Self::is_plain_ack)
        {
            outcome.frames.clear();
        }
        outcome
    }

    /// 收到合法 RST：拆除会话，不产生任何回包。
    fn on_rst(&mut self, segment: &Segment, config: &Config, counters: &mut Counters) -> Outcome {
        let acceptable = if self.state == State::SynReceived {
            // 半连接相关序号：对端初始序号，或 SYN-ACK 自身的序号。
            segment.sequence == self.irs || segment.sequence == self.rcv_nxt.wrapping_sub(1)
        } else {
            seq_within(self.rcv_nxt.wrapping_sub(1), self.rcv_max(config), segment.sequence)
        };
        if !acceptable {
            counters.record(Discard::BadSequence);
            return Outcome::silent(self.state, Discard::BadSequence);
        }
        counters.resets_in = counters.resets_in.saturating_add(1);
        self.teardown();
        let mut outcome = Outcome::new(State::Closed);
        outcome.finished = true;
        outcome
    }

    /// 已建立一侧的通用处理。
    fn on_open(
        &mut self,
        segment: &Segment,
        payload: &[u8],
        now: Clock,
        config: &Config,
        counters: &mut Counters,
    ) -> Outcome {
        if !segment.flags.ack {
            counters.record(Discard::BadSequence);
            return Outcome::silent(self.state, Discard::BadSequence);
        }
        let ack = segment.acknowledgment;
        if seq_gt(ack, self.snd_max()) {
            // 确认了本端从未发出的序号。
            counters.record(Discard::BadSequence);
            return Outcome::silent(self.state, Discard::BadSequence);
        }
        let mut outcome = Outcome::new(self.state);
        let advanced = self.apply_ack(ack);
        self.peer_window = segment.window;
        if self.state == State::SynReceived {
            self.timer = now.saturating_add(config.retransmit_timeout_ms);
        }
        if outcome_is_closed(self.state) {
            outcome.state = self.state;
            outcome.finished = true;
            counters.closed = counters.closed.saturating_add(1);
            return outcome;
        }
        let carries = !payload.is_empty() || segment.flags.fin;
        if !carries {
            // 纯确认或窗口更新：序号仍需在接收窗口内，否则按窗口外丢弃。
            if !self.acceptable_sequence(segment, config) {
                counters.record(Discard::OutOfWindow);
                let mut dropped = Outcome::silent(self.state, Discard::OutOfWindow);
                dropped.frames.push(self.ack_frame());
                return dropped;
            }
            if !advanced {
                // 重复的当前确认：回一个 ACK 让对端尽快收敛，不再触发投递。
                outcome.frames.push(self.ack_frame());
            }
            outcome.frames.extend(self.flush(config));
            outcome.state = self.state;
            return outcome;
        }
        let reception = self.receive(segment, payload, config, counters, &mut outcome);
        if reception == Reception::Rejected {
            outcome.state = self.state;
            if matches!(
                outcome.dropped,
                Some(Discard::Stale) | Some(Discard::Overlap) | Some(Discard::OutOfWindow)
            ) {
                // 旧段与窗口外段仍回 ACK，便于对端尽快恢复；原因已被计数。
                outcome.frames.push(self.ack_frame());
            }
            return outcome;
        }
        if self.peer_fin && self.state == State::Established {
            self.state = State::CloseWait;
            // 被动关闭一侧立刻回自己的 FIN，走 CLOSE-WAIT → LAST-ACK → CLOSED。
            self.fin_pending = true;
        }
        let mut frames = Vec::new();
        if reception == Reception::Acknowledge || self.peer_fin {
            frames.push(self.ack_frame());
        }
        frames.extend(self.flush(config));
        outcome.frames = frames;
        outcome.state = self.state;
        outcome
    }

    /// 纯 ACK 帧的判定辅助。
    fn is_plain_ack(frame: &Frame) -> bool {
        frame.flags == Flags::ACK && frame.payload.is_empty() && !frame.with_mss
    }

    fn ack_frame(&self) -> Frame {
        Frame::plain(Flags::ACK, self.snd_nxt, self.rcv_nxt, Vec::new())
    }

    /// 用对端确认号推进发送侧，返回是否推进了未确认区间。
    fn apply_ack(&mut self, ack: u32) -> bool {
        if seq_le(ack, self.snd_una) {
            return false;
        }
        let advanced = usize::try_from(ack.wrapping_sub(self.snd_una)).unwrap_or(usize::MAX);
        if advanced <= self.inflight.len() {
            self.inflight.drain(..advanced);
        } else {
            self.inflight.clear();
            if self.fin_inflight {
                self.fin_inflight = false;
                if self.state == State::LastAck {
                    self.state = State::Closed;
                }
            }
        }
        self.snd_una = ack;
        self.retransmits = 0;
        true
    }

    /// 序号是否落在接收窗口 [RCV.NXT, RCV.WND] 内（纯 ACK 段用）。
    fn acceptable_sequence(&self, segment: &Segment, config: &Config) -> bool {
        seq_within(
            self.rcv_nxt,
            self.rcv_max(config).wrapping_add(1),
            segment.sequence,
        )
    }

    /// 接收侧：旧段、前缀重叠、窗口外、失序缓冲与顺序交付。
    fn receive(
        &mut self,
        segment: &Segment,
        payload: &[u8],
        config: &Config,
        counters: &mut Counters,
        outcome: &mut Outcome,
    ) -> Reception {
        if self.fin_sent {
            counters.record(Discard::AfterFinish);
            outcome.dropped = Some(Discard::AfterFinish);
            return Reception::Rejected;
        }
        let left = segment.sequence;
        let right = segment.sequence_end();
        let window_end = self.rcv_max(config);
        if seq_le(right, self.rcv_nxt) {
            // 全部落在已交付区间之前：旧段或重复段。
            counters.record(Discard::Stale);
            outcome.dropped = Some(Discard::Stale);
            return Reception::Rejected;
        }
        if seq_lt(left, self.rcv_nxt) {
            counters.record(Discard::Overlap);
            let skip = self.rcv_nxt.wrapping_sub(left);
            let Ok(skip) = usize::try_from(skip) else {
                outcome.dropped = Some(Discard::Stale);
                return Reception::Rejected;
            };
            let Some(tail) = payload.get(skip..) else {
                outcome.dropped = Some(Discard::Stale);
                return Reception::Rejected;
            };
            let tail = tail.to_vec();
            // 重叠段的右边界同样不得越出窗口。
            if seq_gt(self.rcv_nxt.wrapping_add(tail.len() as u32), window_end) {
                counters.record(Discard::OutOfWindow);
                outcome.dropped = Some(Discard::OutOfWindow);
                return Reception::Rejected;
            }
            return self.absorb(self.rcv_nxt, &tail, segment.flags.fin, config, counters, outcome);
        }
        if !seq_within(self.rcv_nxt, window_end, left) || seq_gt(right, window_end) {
            counters.record(Discard::OutOfWindow);
            outcome.dropped = Some(Discard::OutOfWindow);
            return Reception::Rejected;
        }
        self.absorb(left, payload, segment.flags.fin, config, counters, outcome)
    }

    /// 收下（或缓冲）一段已确认在窗口内的数据。
    fn absorb(
        &mut self,
        sequence: u32,
        bytes: &[u8],
        fin: bool,
        config: &Config,
        counters: &mut Counters,
        outcome: &mut Outcome,
    ) -> Reception {
        if self.peer_fin {
            // 已收过对端 FIN，又收到新数据：按协议错误丢弃。
            counters.record(Discard::BadSequence);
            outcome.dropped = Some(Discard::BadSequence);
            return Reception::Rejected;
        }
        if sequence != self.rcv_nxt {
            if self.gaps.len() >= config.max_reorder_segments
                || self
                    .gap_bytes
                    .saturating_add(bytes.len())
                    .saturating_add(usize::from(fin))
                    > config.max_reorder_bytes
            {
                counters.record(Discard::ReorderFull);
                outcome.dropped = Some(Discard::ReorderFull);
                return Reception::Rejected;
            }
            if self.gaps.iter().any(|block| block.sequence == sequence) {
                // 同一序号的失序副本：不重复缓冲，也不重复占用额度。
                counters.record(Discard::Stale);
                outcome.dropped = Some(Discard::Stale);
                return Reception::Buffered;
            }
            self.gap_bytes = self.gap_bytes.saturating_add(bytes.len());
            self.gaps.push(Block {
                sequence,
                bytes: bytes.to_vec(),
                fin,
            });
            return Reception::Buffered;
        }
        outcome.delivered.extend_from_slice(bytes);
        counters.delivered_bytes = counters.delivered_bytes.saturating_add(bytes.len() as u64);
        self.rcv_nxt = self.rcv_nxt.wrapping_add(bytes.len() as u32);
        if fin {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.peer_fin = true;
        }
        self.drain_gaps(counters, outcome);
        Reception::Acknowledge
    }

    /// 期望序号推进后，把缓冲里连续的部分并入交付流。
    fn drain_gaps(&mut self, counters: &mut Counters, outcome: &mut Outcome) {
        loop {
            let index = self
                .gaps
                .iter()
                .position(|block| block.sequence == self.rcv_nxt);
            let Some(index) = index else {
                break;
            };
            let block = self.gaps.remove(index);
            self.gap_bytes = self.gap_bytes.saturating_sub(block.bytes.len());
            outcome.delivered.extend_from_slice(&block.bytes);
            counters.delivered_bytes =
                counters.delivered_bytes.saturating_add(block.bytes.len() as u64);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(block.bytes.len() as u32);
            if block.fin {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.peer_fin = true;
                break;
            }
        }
    }

    /// 上层要发数据：整次接受或整次拒绝，不做部分写入。
    pub fn queue(&mut self, bytes: &[u8], config: &Config) -> Result<usize, SendError> {
        if !self.state.flowing() {
            return Err(SendError::NotOpen { state: self.state });
        }
        if self.fin_pending || self.fin_sent {
            return Err(SendError::Finished { state: self.state });
        }
        if self.pending.len().saturating_add(bytes.len()) > config.max_send_bytes {
            return Err(SendError::BufferFull {
                limit: config.max_send_bytes,
                value: bytes.len(),
            });
        }
        self.pending.extend(bytes);
        Ok(bytes.len())
    }

    /// 上层关闭写半：排干待发字节后由 [`Connection::flush`] 发出 FIN。
    pub fn queue_fin(&mut self) -> Result<(), SendError> {
        match self.state {
            State::Established | State::CloseWait => {
                self.fin_pending = true;
                Ok(())
            }
            other => Err(SendError::NotOpen { state: other }),
        }
    }

    /// 按对端窗口切分出可发送的帧。窗口为 0 时一帧都不发（fail-closed，不越窗）。
    pub fn flush(&mut self, config: &Config) -> Vec<Frame> {
        let mut frames = Vec::new();
        let room = usize::from(self.peer_window);
        while self.peer_window > 0 && !self.fin_pending && !self.pending.is_empty() {
            let free = room.saturating_sub(self.inflight.len());
            if free == 0 {
                break;
            }
            let take = free
                .min(self.pending.len())
                .min(usize::from(config.mss))
                .min(usize::MAX / 2);
            let bytes: Vec<u8> = self.pending.drain(..take).collect();
            let sequence = self.snd_nxt;
            self.snd_nxt = self.snd_nxt.wrapping_add(bytes.len() as u32);
            self.inflight.extend(&bytes);
            frames.push(Frame::plain(Flags::PSH_ACK, sequence, self.rcv_nxt, bytes));
        }
        if self.fin_pending && self.pending.is_empty() && self.peer_window > 0 {
            self.fin_pending = false;
            self.fin_sent = true;
            self.fin_inflight = true;
            let sequence = self.snd_nxt;
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            frames.push(Frame::new_fin(sequence, self.rcv_nxt));
            // CLOSE-WAIT 与「本端先关」都收敛到 LAST-ACK：语义是本端 FIN 未确认。
            if matches!(self.state, State::CloseWait | State::Established) {
                self.state = State::LastAck;
            }
        }
        frames
    }

    /// 计时器到点后的动作：`None` 表示无需动作。
    pub fn on_timeout(&mut self, now: Clock, config: &Config) -> Option<Frame> {
        if self.state == State::Closed || seq_lt(now, self.timer) {
            return None;
        }
        if self.abandoned(config) {
            return None;
        }
        if self.inflight.is_empty() && !self.fin_inflight {
            // 没有未确认内容：只是把窗口里排着的字节继续发出去，不计重传。
            let mut frames = self.flush(config);
            if frames.is_empty() {
                return None;
            }
            self.timer = now.saturating_add(config.retransmit_timeout_ms);
            return Some(frames.remove(0));
        }
        self.retransmits = self.retransmits.saturating_add(1);
        self.timer = now.saturating_add(config.retransmit_timeout_ms);
        if self.state == State::SynReceived {
            return Some(Frame::syn_ack(self.iss, self.rcv_nxt));
        }
        if self.inflight.is_empty() {
            // 只有 FIN 在途：原样重发。
            return Some(Frame::new_fin(self.snd_una, self.rcv_nxt));
        }
        let take = self.inflight.len().min(usize::from(config.mss));
        let bytes: Vec<u8> = self.inflight.iter().copied().take(take).collect();
        Some(Frame::plain(Flags::PSH_ACK, self.snd_una, self.rcv_nxt, bytes))
    }

    /// 是否已因重传超限而应放弃会话。
    pub fn abandoned(&self, config: &Config) -> bool {
        self.retransmits >= config.max_retransmits
    }

    /// 复位或超限放弃后的终态：清空全部缓冲。
    pub fn teardown(&mut self) {
        self.state = State::Closed;
        self.inflight.clear();
        self.pending.clear();
        self.gaps.clear();
        self.gap_bytes = 0;
        self.fin_pending = false;
        self.fin_inflight = false;
    }

    /// 重传超限：给出待发的 RST 并拆除会话。
    pub fn give_up(&mut self, counters: &mut Counters) -> Frame {
        counters.resets_out = counters.resets_out.saturating_add(1);
        let frame = Frame::reset(self.rcv_nxt);
        self.teardown();
        counters.closed = counters.closed.saturating_add(1);
        frame
    }

    /// 只读快照，供上层观测（不暴露缓冲内容）。
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            state: self.state,
            rcv_nxt: self.rcv_nxt,
            snd_nxt: self.snd_nxt,
            snd_una: self.snd_una,
            peer_window: self.peer_window,
            pending: self.pending.len(),
            inflight: self.inflight.len(),
            gap_bytes: self.gap_bytes,
            retransmits: self.retransmits,
            timer: self.timer,
        }
    }
}

impl Frame {
    fn new_fin(sequence: u32, acknowledgment: u32) -> Self {
        Frame::plain(Flags::FIN_ACK, sequence, acknowledgment, Vec::new())
    }
}

fn outcome_is_closed(state: State) -> bool {
    state == State::Closed
}

/// 状态与缓冲的只读快照。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub state: State,
    pub rcv_nxt: u32,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub peer_window: u16,
    pub pending: usize,
    pub inflight: usize,
    pub gap_bytes: usize,
    pub retransmits: u32,
    pub timer: Clock,
}
