//! 应用发送队列、重传计时及生命周期。
use super::*;

impl Connection {
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
