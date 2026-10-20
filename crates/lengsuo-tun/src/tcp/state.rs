//! 单连接 TCP 状态机内核：纯内存、无 IO、不建 socket。
//!
//! 只实现 RFC 9293 的**被动打开**路径：`Listen` 收 SYN → 回 SYN-ACK → 收 ACK 进
//! `Established`。调用方把已校验的 [`Segment`] 依次喂给 [`Connection::advance`]，并按
//! 返回的 [`Outcome`] 发包；本模块不构造 IP 头部、不写网卡。序号比较一律 32 位回绕
//! 安全（[`seq_lt`]/[`seq_ge`]，即 RFC 9293 §3.4 的 `SEG.LT` 系列）。初始序号来自确定性
//! 发生器 [`Connection::set_iss_seed`]：**不是密码学随机**，只为让用例可复现；生产部署
//! 必须由上层换用不可预测的 ISN（RFC 9293 §3.4.1 的防伪造要求不在本模块范围内）。
//! 有意不实现的项见文件末尾「偏离清单」。

use crate::session::Clock;

use super::segment::{Flags, Segment};

/// 单连接的缓冲上限与初始序号种子。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// 本端接收窗口通告上限（字节）。可用缓冲归零即通告零窗口。
    pub receive_window: u16,
    /// 乱序重排缓冲的段数上限，至少为 1。
    pub reorder_slots: usize,
    /// 本端初始序号种子；见 [`Connection::set_iss_seed`] 的非密码学说明。
    pub iss_seed: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            receive_window: 65_535,
            reorder_slots: 4,
            iss_seed: 0,
        }
    }
}

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
    rcv_nxt: u32,
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
    pub fn delivered_bytes(&self) -> u64 {
        self.delivered
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

/// 32 位回绕安全比较：`a` 是否在 `b` 之前（RFC 9293 §3.4 的 `SEG.LT`）。
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
/// `a >= b`（回绕安全）。
pub fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}
/// `a` 是否落在半开区间 `[start, end)` 内（回绕安全）。
pub fn seq_in(a: u32, start: u32, end: u32) -> bool {
    seq_ge(a, start) && seq_lt(a, end)
}

// ---- 与 RFC 9293 的有意差异（本卡范围内的取舍，逐条列出）----
//
// 1. 不做半连接队列分级：`SynReceived` 即一个真实连接，没有 SYN 队列/accept 队列。
// 2. 不做 TIME-WAIT：`LastAck` 收到最终 ACK 后直接 `Closed`，不保留 2MSL 静默期。
// 3. 不做延迟 ACK 合并：每个需要确认的段立即回一个 ACK，不等待第二个段或 200ms。
// 4. 不做 challenge ACK，也不实现 RFC 5961 的 RST 速率限制：RST 一律立即生效。
// 5. 不实现窗口缩放（RFC 7323）：窗口字段恒为 16 位原始值，无移位。
// 6. 不实现 SACK（RFC 2018）：乱序只做单段重排，无选择确认。
// 7. 不实现拥塞控制与慢启动：`snd_nxt` 只随发送推进，无 cwnd/ssthresh/RTT 估计。
// 8. 主动关闭不引入 FIN-WAIT-1/FIN-WAIT-2 分解：`close()` 统一停到 `LastAck`；
//    若对端尚未 FIN，仍由上层继续喂入对端 FIN 后才可能被最终 ACK 收尾。
// 9. 不做重传与超时管理：本内核不持有定时器（故 `clock` 入参在本卡内未被消费），
//    重传由上层按 `Outcome` 自行决定。

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_tmp::segment::{self, Flags};
    const NOW: Clock = 0;

    /// 经 `segment::build` 生成真字节再 `parse` 回来，用例走生产解析入口。
    fn seg<'a>(b: &'a mut Vec<u8>, seq: u32, ack: u32, f: Flags, pl: &[u8]) -> Segment<'a> {
        *b = segment::build(1, 2, seq, ack, f, 1024, &[], pl, &[0u8; 12]).unwrap();
        segment::parse(b).unwrap()
    }
    fn sent(o: Outcome) -> SendSegment {
        match o {
            Outcome::SendSegment(s) => s,
            other => panic!("应回段，实得 {other:?}"),
        }
    }
    fn conn(win: u16, slots: usize) -> Connection {
        Connection::new(Config {
            receive_window: win,
            reorder_slots: slots,
            iss_seed: 0,
        })
    }
    /// 建连：返回连接与对端下一序号（服务端 rcv_nxt）。
    fn est(win: u16, slots: usize) -> (Connection, u32) {
        let (mut b, mut c) = (Vec::new(), conn(win, slots));
        c.listen();
        let syn = sent(c.advance(&seg(&mut b, 1000, 0, Flags::SYN, &[]), NOW));
        let rcv = c.rcv_nxt();
        let third = seg(&mut b, rcv, syn.seq.wrapping_add(1), Flags::ACK, &[]);
        c.advance(&third, NOW);
        assert_eq!(c.state(), State::Established);
        (c, rcv)
    }

    #[test]
    fn handshake_duplicate_syn_and_bad_ack() {
        let (mut b, mut c) = (Vec::new(), conn(4096, 4));
        c.listen();
        let s = sent(c.advance(&seg(&mut b, 5000, 0, Flags::SYN, &[]), NOW));
        assert_eq!((s.seq, s.ack, s.flags), (0, 5001, Flags::SYN | Flags::ACK));
        // 重复 SYN 重发同一 ISN；确认号不合规则丢弃且状态不变。
        assert_eq!(
            sent(c.advance(&seg(&mut b, 5000, 0, Flags::SYN, &[]), NOW)).seq,
            0
        );
        let bad = seg(&mut b, 5001, 9, Flags::ACK, &[]);
        assert_eq!(
            c.advance(&bad, NOW),
            Outcome::Discard(DiscardReason::Unexpected)
        );
        assert_eq!(c.state(), State::SynReceived);
        let ok = seg(&mut b, 5001, 1, Flags::ACK, &[]);
        c.advance(&ok, NOW);
        assert_eq!(c.state(), State::Established);
    }

    #[test]
    fn delivery_duplicate_reorder_and_overflow() {
        let (mut c, rcv) = est(4096, 2);
        let mut b = Vec::new();
        let d = seg(&mut b, rcv, 0, Flags::ACK | Flags::PSH, b"abc");
        assert_eq!(c.advance(&d, NOW), Outcome::Deliver(b"abc".to_vec()));
        // 重复段不重复交付。
        let dup = seg(&mut b, rcv, 0, Flags::ACK, b"abc");
        assert_eq!(
            c.advance(&dup, NOW),
            Outcome::Discard(DiscardReason::Duplicate)
        );
        assert_eq!((c.rcv_nxt(), c.delivered_bytes()), (rcv + 3, 3));
        // 乱序：后段入缓冲，前段到达后按序一次交付。
        let base = c.rcv_nxt();
        let lo = seg(&mut b, base + 3, 0, Flags::ACK, b"def");
        assert!(matches!(c.advance(&lo, NOW), Outcome::SendSegment(_)));
        assert_eq!(c.rcv_nxt(), base);
        let hi = seg(&mut b, base, 0, Flags::ACK, b"ghi");
        assert_eq!(c.advance(&hi, NOW), Outcome::Deliver(b"ghidef".to_vec()));
        // 乱序槽位（2）满后第三段丢弃；窗口外段丢弃。
        for at in [base + 8, base + 9] {
            let s = seg(&mut b, at, 0, Flags::ACK, b"x");
            assert!(matches!(c.advance(&s, NOW), Outcome::SendSegment(_)));
        }
        let over = seg(&mut b, base + 10, 0, Flags::ACK, b"y");
        assert_eq!(
            c.advance(&over, NOW),
            Outcome::Discard(DiscardReason::ReorderFull)
        );
        let far = seg(&mut b, c.rcv_nxt() + 4096, 0, Flags::ACK, b"z");
        assert_eq!(
            c.advance(&far, NOW),
            Outcome::Discard(DiscardReason::OutOfWindow)
        );
        // 重复 1 + 乱序满 1 + 窗口外 1。
        assert_eq!(c.discarded_segments(), 3);
    }

    #[test]
    fn zero_window_and_window_update() {
        let (mut b, mut c) = (Vec::new(), conn(4, 2));
        c.listen();
        let s = sent(c.advance(&seg(&mut b, 100, 0, Flags::SYN, &[]), NOW));
        assert_eq!(s.window, 4);
        let third = seg(&mut b, 101, s.seq.wrapping_add(1), Flags::ACK, &[]);
        c.advance(&third, NOW);
        let data = seg(&mut b, 101, 0, Flags::ACK, b"wxyz");
        assert_eq!(c.advance(&data, NOW), Outcome::Deliver(b"wxyz".to_vec()));
        // 接收缓冲用尽后窗口更新通告 0。
        let upd = seg(&mut b, 105, 0, Flags::ACK, &[]);
        let u = sent(c.advance(&upd, NOW));
        assert_eq!((u.window, u.ack), (0, 105));
    }

    #[test]
    fn fin_close_wait_and_final_ack() {
        let (mut c, rcv) = est(4096, 2);
        let mut b = Vec::new();
        // 载荷与 FIN 同到：先交付载荷。
        let tail = seg(&mut b, rcv, 0, Flags::FIN | Flags::ACK, b"tail");
        assert_eq!(c.advance(&tail, NOW), Outcome::Deliver(b"tail".to_vec()));
        let fin = seg(&mut b, rcv + 4, 0, Flags::FIN | Flags::ACK, &[]);
        assert!(matches!(c.advance(&fin, NOW), Outcome::SendSegment(_)));
        assert_eq!((c.state(), c.rcv_nxt()), (State::CloseWait, rcv + 5));
        // 重复 FIN 不再推进 rcv_nxt。
        let again = seg(&mut b, rcv + 4, 0, Flags::FIN | Flags::ACK, &[]);
        assert!(matches!(c.advance(&again, NOW), Outcome::SendSegment(_)));
        assert_eq!(c.rcv_nxt(), rcv + 5);
        // 关写端 → LastAck；最终 ACK → Closed。
        let f = sent(c.close());
        assert_eq!(
            (f.flags, c.state()),
            (Flags::FIN | Flags::ACK, State::LastAck)
        );
        let last = seg(&mut b, rcv + 5, f.seq.wrapping_add(1), Flags::ACK, &[]);
        assert_eq!(c.advance(&last, NOW), Outcome::None);
        assert_eq!((c.state(), c.close()), (State::Closed, Outcome::None));
    }

    #[test]
    fn rst_and_unknown_quadruple() {
        let mut b = Vec::new();
        for target in [
            State::Listen,
            State::SynReceived,
            State::Established,
            State::CloseWait,
        ] {
            let mut c = conn(4096, 2);
            c.listen();
            if target != State::Listen {
                let s = sent(c.advance(&seg(&mut b, 1, 0, Flags::SYN, &[]), NOW));
                if target != State::SynReceived {
                    let t = seg(&mut b, 2, s.seq.wrapping_add(1), Flags::ACK, &[]);
                    c.advance(&t, NOW);
                    if target == State::CloseWait {
                        let f = seg(&mut b, 2, 0, Flags::FIN | Flags::ACK, &[]);
                        c.advance(&f, NOW);
                    }
                }
            }
            assert_eq!(c.state(), target);
            let rst = seg(&mut b, 77, 0, Flags::RST, &[]);
            assert_eq!(c.advance(&rst, NOW), Outcome::None);
            assert_eq!(c.state(), State::Closed);
            let _ = c.advance(&seg(&mut b, 78, 0, Flags::ACK, b"x"), NOW);
            assert_eq!(c.state(), State::Closed);
        }
        // Closed 收 SYN 回 RST，确认号 = 对端序号 + 1（SYN 占一位）。
        let mut c = conn(4096, 2);
        let rst = sent(c.advance(&seg(&mut b, 42, 0, Flags::SYN, &[]), NOW));
        assert_eq!((rst.flags, rst.seq, rst.ack), (Flags::RST, 0, 43));
        // Listen 收 ACK / 无标志段回 RST，状态保持 Listen。
        for f in [Flags::ACK, Flags::NONE] {
            let mut l = conn(4096, 2);
            l.listen();
            let bad = seg(&mut b, 9, 5, f, &[]);
            assert_eq!(sent(l.advance(&bad, NOW)).flags, Flags::RST);
            assert_eq!(l.state(), State::Listen);
        }
    }

    #[test]
    fn wraparound_helpers_and_hostile_inputs() {
        let (mut c, _) = est(4096, 2);
        let mut b = Vec::new();
        c.rcv_nxt = u32::MAX - 1;
        let wrap = seg(&mut b, u32::MAX - 1, 0, Flags::ACK, b"abcd");
        assert_eq!(c.advance(&wrap, NOW), Outcome::Deliver(b"abcd".to_vec()));
        assert_eq!(c.rcv_nxt(), 2, "序号必须回绕到 2 而不是溢出");
        // 回绕安全比较；跨度超 2^31 时按有符号语义取一端。
        assert!(seq_lt(u32::MAX, 0) && seq_ge(0, u32::MAX) && !seq_lt(1, 0));
        assert!(seq_in(0, u32::MAX, 1) && !seq_in(2, u32::MAX, 1));
        assert!(seq_lt(0x8000_0000, 0));
        // 非法输入全轮询：全部标志组合、序号极值、超长载荷、RST/FIN 反复投喂。
        let mut c = conn(4096, 2);
        c.listen();
        for bits in 0u8..=0x1fu8 {
            let s = seg(&mut b, 1, 0, Flags::from_byte(bits), &[]);
            let _ = c.advance(&s, NOW);
        }
        for v in [0, 1, u32::MAX, u32::MAX - 1, 0x8000_0000] {
            let s = seg(&mut b, v, v, Flags::ACK, b"x");
            let _ = c.advance(&s, NOW);
        }
        let big = vec![0u8; 60];
        let _ = c.advance(&seg(&mut b, 0, 0, Flags::ACK, &big), NOW);
        let _ = c.advance(&seg(&mut b, 0, 0, Flags::RST, &[]), NOW);
        let _ = c.advance(&seg(&mut b, 0, 0, Flags::FIN, b"z"), NOW);
        assert!(c.is_closed());
    }
}
