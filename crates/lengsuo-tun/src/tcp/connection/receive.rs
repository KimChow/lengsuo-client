//! 数据接收与失序缓冲推进。
use super::*;

impl Connection {
    pub(super) fn receive(
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
    pub(super) fn absorb(
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
    pub(super) fn drain_gaps(&mut self, counters: &mut Counters, outcome: &mut Outcome) {
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

}
