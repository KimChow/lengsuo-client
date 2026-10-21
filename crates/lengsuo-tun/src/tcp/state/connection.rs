//! 单连接状态机：状态、动作与丢弃原因。

use crate::session::Clock;

use super::config::Config;
use super::seq::{seq_ge, seq_lt};
use crate::tcp::segment::{Flags, Segment};

/// 丢弃原因。所有非法输入都走这里，绝不 panic。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DiscardReason {
    /// 段不在当前状态允许的语义内（RFC 9293 要求直接丢弃，不回 RST）。
    #[error("当前状态不允许该段")]
    Unexpected,
    /// 序号完全落在接收窗口之外。
    #[error("序号在接收窗口之外")]
    OutOfWindow,
    /// 重复段：载荷已交付过，不重复交付。
    #[error("重复段，不重复交付")]
    Duplicate,
    /// 乱序缓冲已满，无法再缓存。
    #[error("乱序缓冲已满")]
    ReorderFull,
    /// 连接已终止（`Closed`），后续段一律丢弃。
    #[error("连接已关闭")]
    Closed,
}

/// 要发出的段。IP 头部与最终校验和由上层补齐。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendSegment {
    pub seq: u32,
    pub ack: u32,
    pub flags: Flags,
    pub window: u16,
    pub payload: Vec<u8>,
}

/// 状态机对单个段给出的动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// 需要回一个段。
    SendSegment(SendSegment),
    /// 按序到达的应用载荷，交上层写入对端 socket。
    Deliver(Vec<u8>),
    /// 丢弃并附原因，不产生任何回包。
    Discard(DiscardReason),
    /// 无动作（纯 ACK 被吸收、连接已终结等）。
    None,
}

/// 单连接状态。本卡不做半连接分级，`SynReceived` 直接代表一个连接。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Closed,
    /// 已打开监听，等待 SYN。
    Listen,
    /// 已回 SYN-ACK，等待对端 ACK。
    SynReceived,
    /// 三次握手完成，可双向传数据。
    Established,
    /// 收到对端 FIN，本端写端仍可发数据。
    CloseWait,
    /// 本端已发 FIN，等待其确认后进入 `Closed`。
    LastAck,
}

/// 缓存的一个乱序段。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Buffered {
    seq: u32,
    payload: Vec<u8>,
}

/// 单个 TCP 连接的状态机。字段含义见同名访问器与「偏离清单」。
#[derive(Debug, Clone)]
pub struct Connection {
    state: State,
    config: Config,
    /// 发送端下一个序号（SYN 与 FIN 各占一个）。
    snd_nxt: u32,
    /// 本端 FIN 所占的序号，未发出时为 `None`。
    fin_seq: Option<u32>,
    /// 期望收到的下一个序号。
    pub(super) rcv_nxt: u32,
    /// 对端最近一次通告的窗口，仅作记录供上层观察。
    peer_window: u16,
    reorder: Vec<Buffered>,
    /// 已交付的载荷字节总数，用于计算通告窗口与用例断言。
    delivered: u64,
    /// 被丢弃的段数，便于断言窗口外丢弃确实发生。
    discarded: u64,
}

impl Connection {
    /// 建立处于 `Closed` 的连接状态机。
    pub fn new(config: Config) -> Self {
        Self {
            state: State::Closed,
            config,
            snd_nxt: 0,
            fin_seq: None,
            rcv_nxt: 0,
            peer_window: 0,
            reorder: Vec::new(),
            delivered: 0,
            discarded: 0,
        }
    }
    /// 本端初始序号：由种子确定性推导，**不是密码学随机**。
    pub fn set_iss_seed(&mut self, seed: u32) {
        self.config.iss_seed = seed;
    }
    /// 进入监听：清空连接级计数器，等待 SYN。
    pub fn listen(&mut self) {
        self.state = State::Listen;
        self.snd_nxt = 0;
        self.fin_seq = None;
        self.rcv_nxt = 0;
        self.peer_window = 0;
        self.reorder.clear();
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed)
    }
    pub fn rcv_nxt(&self) -> u32 {
        self.rcv_nxt
    }
    pub fn snd_nxt(&self) -> u32 {
        self.snd_nxt
    }
    pub fn peer_window(&self) -> u16 {
        self.peer_window
    }
    /// 本端当前应通告的接收窗口（由接收缓冲余量推导，见 `advertise_window`）。
    pub fn advertised_window(&self) -> u16 {
        self.advertise_window()
    }
    pub fn delivered_bytes(&self) -> u64 {
        self.delivered
    }
    /// 推进发送端序号：上层已用 `snd_nxt()` 作为起点发出了 `bytes` 字节的应用载荷。
    /// 本内核不持有发送缓冲，也不做重传，因此这里只做序号记账（无回绕之外的语义）。
    pub fn advance_snd(&mut self, bytes: u32) {
        self.snd_nxt = self.snd_nxt.wrapping_add(bytes);
    }
    pub fn discarded_segments(&self) -> u64 {
        self.discarded
    }
    fn advertise_window(&self) -> u16 {
        let limit = usize::from(self.config.receive_window);
        let used = usize::try_from(self.delivered).unwrap_or(usize::MAX);
        let pending: usize = self.reorder.iter().map(|b| b.payload.len()).sum();
        u16::try_from(limit.saturating_sub(used).saturating_sub(pending)).unwrap_or(u16::MAX)
    }
    /// 处理一个已解析、已校验的段，返回要执行的动作。
    /// `clock` 只统一上层的时间口径，本内核不装定时器（见「偏离清单」）。
    pub fn advance(&mut self, seg: &Segment<'_>, _clock: Clock) -> Outcome {
        // RST 在任何状态下都立即终止连接（RFC 9293 §3.5.3）。
        if seg.flags.has_rst() {
            self.terminate();
            return Outcome::None;
        }
        match self.state {
            State::Closed => self.on_closed(seg),
            State::Listen => self.on_listen(seg),
            State::SynReceived => self.on_syn_received(seg),
            State::Established => self.on_established(seg),
            State::CloseWait => self.on_close_wait(seg),
            State::LastAck => self.on_last_ack(seg),
        }
    }
    fn terminate(&mut self) {
        self.state = State::Closed;
        self.reorder.clear();
        self.fin_seq = None;
    }
    fn on_closed(&mut self, seg: &Segment<'_>) -> Outcome {
        if seg.flags.has_syn() {
            return self.rst_to(seg);
        }
        self.discard(DiscardReason::Closed)
    }
    fn on_listen(&mut self, seg: &Segment<'_>) -> Outcome {
        if !seg.flags.has_syn() || seg.flags.has_ack() {
            return self.rst_to(seg);
        }
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.peer_window = seg.window;
        self.reorder.clear();
        let iss = self.config.iss_seed;
        self.snd_nxt = iss.wrapping_add(1);
        self.state = State::SynReceived;
        Outcome::SendSegment(self.segment(iss, Flags::SYN | Flags::ACK))
    }
    fn on_syn_received(&mut self, seg: &Segment<'_>) -> Outcome {
        // 重复 SYN：重发 SYN-ACK，序号保持首次选定的 ISN。
        if seg.flags.has_syn() {
            return Outcome::SendSegment(
                self.segment(self.snd_nxt.wrapping_sub(1), Flags::SYN | Flags::ACK),
            );
        }
        if !seg.flags.has_ack() || seg.ack != self.snd_nxt {
            return self.discard(DiscardReason::Unexpected);
        }
        self.state = State::Established;
        self.peer_window = seg.window;
        // 第三个 ACK 允许顺带携带数据（RFC 9293 §3.10.7.1）。
        self.ingest_payload(seg)
    }
    fn on_established(&mut self, seg: &Segment<'_>) -> Outcome {
        self.peer_window = seg.window;
        if seg.flags.has_fin() {
            return self.ingest_fin(seg);
        }
        self.ingest_payload(seg)
    }
    fn on_close_wait(&mut self, seg: &Segment<'_>) -> Outcome {
        self.peer_window = seg.window;
        if seg.flags.has_fin() {
            // 重复 FIN：只再确认一次，不重复推进 rcv_nxt。
            return Outcome::SendSegment(self.ack_segment());
        }
        self.ingest_payload(seg)
    }
    fn on_last_ack(&mut self, seg: &Segment<'_>) -> Outcome {
        self.peer_window = seg.window;
        let done = self
            .fin_seq
            .is_some_and(|fin| seg.flags.has_ack() && seq_ge(seg.ack, fin.wrapping_add(1)));
        if done {
            self.state = State::Closed;
            Outcome::None
        } else {
            self.discard(DiscardReason::Unexpected)
        }
    }
    fn ingest_fin(&mut self, seg: &Segment<'_>) -> Outcome {
        let end = seg.seq.wrapping_add(seg.payload.len() as u32);
        // 载荷与 FIN 同时到达：先把载荷按序交付，FIN 留待下一次处理。
        if !seg.payload.is_empty() && seq_lt(self.rcv_nxt, end) {
            return self.ingest_payload(seg);
        }
        if seq_ge(seg.seq, self.rcv_nxt) {
            self.rcv_nxt = seg.seq.wrapping_add(1);
        }
        self.state = State::CloseWait;
        Outcome::SendSegment(self.ack_segment())
    }
    fn ingest_payload(&mut self, seg: &Segment<'_>) -> Outcome {
        if seg.payload.is_empty() {
            // 纯 ACK / 窗口更新：吸收，并把当前窗口通告回给对端。
            return if !self.within_window(seg.seq) && seq_lt(seg.seq, self.rcv_nxt) {
                Outcome::None
            } else {
                Outcome::SendSegment(self.ack_segment())
            };
        }
        if seq_lt(seg.seq, self.rcv_nxt) {
            return self.discard(DiscardReason::Duplicate);
        }
        if !self.within_window(seg.seq) {
            return self.discard(DiscardReason::OutOfWindow);
        }
        if seg.seq != self.rcv_nxt {
            // 乱序：缓存一段，等前序到达后重排。
            if self.reorder.len() >= self.config.reorder_slots.max(1) {
                return self.discard(DiscardReason::ReorderFull);
            }
            self.reorder.push(Buffered {
                seq: seg.seq,
                payload: seg.payload.to_vec(),
            });
            return Outcome::SendSegment(self.ack_segment());
        }
        self.rcv_nxt = seg.seq.wrapping_add(seg.payload.len() as u32);
        let mut delivered = seg.payload.to_vec();
        delivered.extend_from_slice(&self.flush_reorder());
        self.delivered += delivered.len() as u64;
        Outcome::Deliver(delivered)
    }
    fn within_window(&self, seq: u32) -> bool {
        let window = u32::from(self.config.receive_window).max(1);
        seq_ge(seq, self.rcv_nxt) && seq_lt(seq, self.rcv_nxt.wrapping_add(window))
    }
    fn flush_reorder(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(index) = self.reorder.iter().position(|b| b.seq == self.rcv_nxt) {
            let buffered = self.reorder.remove(index);
            self.rcv_nxt = buffered.seq.wrapping_add(buffered.payload.len() as u32);
            out.extend_from_slice(&buffered.payload);
        }
        out
    }
    /// 关闭本端写端：发 FIN 并进入 `LastAck`。
    pub fn close(&mut self) -> Outcome {
        if !matches!(self.state, State::Established | State::CloseWait) {
            return Outcome::None;
        }
        let seq = self.snd_nxt;
        self.fin_seq = Some(seq);
        self.snd_nxt = seq.wrapping_add(1);
        self.state = State::LastAck;
        Outcome::SendSegment(self.segment(seq, Flags::FIN | Flags::ACK))
    }
    fn segment(&self, seq: u32, flags: Flags) -> SendSegment {
        SendSegment {
            seq,
            ack: self.rcv_nxt,
            flags,
            window: self.advertise_window(),
            payload: Vec::new(),
        }
    }
    fn ack_segment(&self) -> SendSegment {
        self.segment(self.snd_nxt, Flags::ACK)
    }
    fn rst_to(&mut self, seg: &Segment<'_>) -> Outcome {
        let (seq, ack) = if seg.flags.has_ack() {
            (seg.ack, 0)
        } else {
            (0, seg.next_seq())
        };
        Outcome::SendSegment(SendSegment {
            seq,
            ack,
            flags: Flags::RST,
            window: 0,
            payload: Vec::new(),
        })
    }
    fn discard(&mut self, reason: DiscardReason) -> Outcome {
        self.discarded += 1;
        Outcome::Discard(reason)
    }
}
