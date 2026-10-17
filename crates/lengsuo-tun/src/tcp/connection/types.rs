//! 会话输入输出及快照类型。
use super::{Clock, Discard, Flags, State};

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
    pub(super) fn plain(flags: Flags, sequence: u32, acknowledgment: u32, payload: Vec<u8>) -> Self {
        Frame {
            flags,
            sequence,
            acknowledgment,
            payload,
            with_mss: false,
        }
    }

    pub(super) fn syn_ack(iss: u32, acknowledgment: u32) -> Self {
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
    pub(super) fn new(state: State) -> Self {
        Outcome {
            frames: Vec::new(),
            delivered: Vec::new(),
            state,
            dropped: None,
            finished: false,
            established: false,
        }
    }

    pub(super) fn silent(state: State, dropped: Discard) -> Self {
        let mut outcome = Outcome::new(state);
        outcome.dropped = Some(dropped);
        outcome
    }
}


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

impl Frame {
    pub(super) fn new_fin(sequence: u32, acknowledgment: u32) -> Self {
        Frame::plain(Flags::FIN_ACK, sequence, acknowledgment, Vec::new())
    }
}
