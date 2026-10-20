//! 主动方向的入向段处理：各状态下的握手推进与载荷收发。
//!
//! 三个分支与 RFC 9293 §3.10.7 的状态图一一对应：
//! - [`ActiveConnection::on_syn_sent`]：等 SYN-ACK（常规）或裸 SYN（同时打开）。
//! - [`ActiveConnection::on_syn_received`]：等最终 ACK（或同时打开路径下对端的 SYN-ACK）。
//! - [`ActiveConnection::on_established`]：交付载荷、吸收纯 ACK、处理对端 FIN。
//!
//! 所有拒绝路径都 fail-closed：要么回 RST 并失败，要么丢弃并计数。

use crate::tcp::segment::{Flags, Segment};
use crate::tcp::state::{seq_ge, seq_lt, DiscardReason};

use super::connect::ActiveConnection;
use super::types::{ActiveError, ActiveOutcome, ActiveState, OutboundSegment};

impl ActiveConnection {
    /// `SynSent`：等 SYN-ACK（常规）或裸 SYN（同时打开）。
    pub(super) fn on_syn_sent(&mut self, seg: &Segment<'_>) -> ActiveOutcome {
        if seg.flags.has_rst() {
            return self.fail(ActiveError::ConnectionRefused, None);
        }
        if seg.flags.has_syn() && seg.flags.has_ack() {
            let expected = self.iss.wrapping_add(1);
            if seg.ack != expected {
                // fail-closed：确认号不符 ⇒ 回 RST 并失败，绝不当作已连接。
                let reset = OutboundSegment {
                    seq: seg.ack,
                    ack: 0,
                    flags: Flags::RST,
                    window: 0,
                    options: Vec::new(),
                    payload: Vec::new(),
                };
                return self.fail(
                    ActiveError::AckMismatch {
                        expected,
                        got: seg.ack,
                    },
                    Some(reset),
                );
            }
            self.peer_isn = seg.seq;
            self.rcv_nxt = seg.seq.wrapping_add(1);
            self.snd_una = expected;
            self.peer_window = seg.window;
            // 常规主动打开：握手只剩最后一步（发最终 ACK）。
            // `SynReceived` 在本路径上是瞬态——产出最终 ACK 的瞬间即进入 Established，
            // 中间态记在状态历史里（RFC 9293 §3.10.7.3 的状态图同样如此）。
            self.transition(ActiveState::SynReceived);
            self.deadline = None;
            let ack = self.ack_segment();
            self.transition(ActiveState::Established);
            return ActiveOutcome::Send(ack);
        }
        if seg.flags.has_syn() {
            // 同时打开（RFC 9293 §3.6）：对端也是主动方，回 SYN+ACK 进 SynReceived。
            self.peer_isn = seg.seq;
            self.rcv_nxt = seg.seq.wrapping_add(1);
            self.peer_window = seg.window;
            self.transition(ActiveState::SynReceived);
            return ActiveOutcome::Send(self.syn_ack_segment());
        }
        self.discard(DiscardReason::Unexpected)
    }

    /// `SynReceived`：等最终 ACK（或同时打开路径下对端的 SYN-ACK）。
    pub(super) fn on_syn_received(&mut self, seg: &Segment<'_>) -> ActiveOutcome {
        if seg.flags.has_rst() {
            return self.fail(ActiveError::ConnectionRefused, None);
        }
        if seg.flags.has_syn() && !seg.flags.has_ack() {
            // 重复 SYN：重发 SYN+ACK，序号仍是首次选定的 ISN。
            return ActiveOutcome::Send(self.syn_ack_segment());
        }
        if seg.flags.has_ack() {
            let expected = self.iss.wrapping_add(1);
            if seg.ack != expected {
                return self.fail(
                    ActiveError::AckMismatch {
                        expected,
                        got: seg.ack,
                    },
                    None,
                );
            }
            self.snd_una = expected;
            self.transition(ActiveState::Established);
            self.deadline = None;
            return ActiveOutcome::None;
        }
        self.discard(DiscardReason::Unexpected)
    }

    /// `Established`：交付应用载荷、吸收纯 ACK、处理对端 FIN。
    pub(super) fn on_established(&mut self, seg: &Segment<'_>) -> ActiveOutcome {
        if seg.flags.has_rst() {
            return self.fail(ActiveError::ConnectionRefused, None);
        }
        if seg.flags.has_fin() {
            let end = seg.seq.wrapping_add(seg.payload.len() as u32);
            // 载荷与 FIN 同时到达：先交付载荷，FIN 的确认留给下一次发送（累计确认）。
            if !seg.payload.is_empty() && seq_lt(self.rcv_nxt, end) {
                self.rcv_nxt = end.wrapping_add(1);
                self.delivered += seg.payload.len() as u64;
                return ActiveOutcome::Deliver(seg.payload.to_vec());
            }
            if seq_ge(seg.seq, self.rcv_nxt) {
                self.rcv_nxt = seg.seq.wrapping_add(1);
            }
            return ActiveOutcome::Send(self.ack_segment());
        }
        if seg.payload.is_empty() {
            // 纯 ACK / 窗口更新：吸收，不回包（不回 ACK 避免与对端形成 ACK 乒乓）。
            self.peer_window = seg.window;
            return ActiveOutcome::None;
        }
        if seq_lt(seg.seq, self.rcv_nxt) {
            return self.discard(DiscardReason::Duplicate);
        }
        if seg.seq != self.rcv_nxt {
            return self.discard(DiscardReason::OutOfWindow);
        }
        self.rcv_nxt = seg.seq.wrapping_add(seg.payload.len() as u32);
        self.delivered += seg.payload.len() as u64;
        ActiveOutcome::Deliver(seg.payload.to_vec())
    }

    /// 连接失败：释放状态并给出原因（可选附带一个必须发出的 RST）。
    pub(super) fn fail(
        &mut self,
        reason: ActiveError,
        reset: Option<OutboundSegment>,
    ) -> ActiveOutcome {
        self.transition(ActiveState::Closed);
        self.deadline = None;
        ActiveOutcome::Failed { reason, reset }
    }

    /// 丢弃一个段并计数。
    pub(super) fn discard(&mut self, reason: DiscardReason) -> ActiveOutcome {
        self.discarded += 1;
        ActiveOutcome::Discarded(reason)
    }
}
