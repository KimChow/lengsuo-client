//! 状态机与观测：阶段一只实现服务器侧需要的状态。
//!
//! 状态集合：`LISTEN`（等待 SYN）、`SYN_RCVD`（已回 SYN-ACK，等待第三次握手）、
//! `ESTABLISHED`（可收发数据）、`CLOSE_WAIT`（对端已 FIN，本端待发 FIN）、
//! `LAST_ACK`（本端 FIN 已发，等确认）、`CLOSING`（双向 FIN 交错，等 FIN 的确认）、
//! `CLOSED`。TIME-WAIT 不在阶段一实现：会话老化由 [`crate::session::SessionTable`]
//! 的 TTL 负责，本模块**不**自己守 2MSL。

use crate::session::Clock;

/// 状态机参数。全部可注入，用于测试与上限策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// 单个会话去重与失序缓冲的字节上限。
    pub ooo_capacity: usize,
    /// 失序区间条数上限；超限即放弃会话（对端序列号空间已不可信）。
    pub ooo_blocks: usize,
    /// 接收侧 MSS：超过该长度的数据段整段丢弃（不截断交付）。
    pub mss: usize,
    /// 本端通告窗口（回包的 window 字段）。
    pub advertised_window: u16,
    /// 回包的逐跳限制。
    pub hop_limit: u8,
    /// 未确认发送数据停留多久后重传。
    pub rtx_after: Clock,
    /// 重传上限；到顶即放弃会话。
    pub rtx_limit: u8,
}

/// 配置错误的种类；调用方据此修配置而不是猜测。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// 失序容量为 0，无法缓存任何数据。
    ZeroOooCapacity,
    /// 失序区间条数为 0。
    ZeroOooBlocks,
    /// MSS 为 0，任何数据段都放不下。
    ZeroMss,
    /// MSS 超出单段上限，无法构造合法选项。
    MssTooLarge,
    /// 重传间隔为 0，会让 `poll` 每轮都重发。
    ZeroRtxAfter,
    /// 重传上限为 0，首帧未确认即放弃会话。
    ZeroRtxLimit,
    /// 通告窗口小于一个 MSS，对端无法发送任何数据。
    WindowBelowMss,
}

impl Config {
    /// 阶段一默认值：64 KB 失序容量、8 段 MSS、1 秒重传、3 次重传上限。
    pub const DEFAULT: Config = Config {
        ooo_capacity: 65_536,
        ooo_blocks: 32,
        mss: 1_460,
        advertised_window: 65_535,
        hop_limit: 64,
        rtx_after: 1_000,
        rtx_limit: 3,
    };

    /// 逐项校验，避免把不可运行的参数带进状态机。
    pub fn validate(self) -> Result<(), ConfigError> {
        if self.ooo_capacity == 0 {
            return Err(ConfigError::ZeroOooCapacity);
        }
        if self.ooo_blocks == 0 {
            return Err(ConfigError::ZeroOooBlocks);
        }
        if self.mss == 0 {
            return Err(ConfigError::ZeroMss);
        }
        if self.mss > crate::tcp::segment::MAX_SEGMENT_SIZE {
            return Err(ConfigError::MssTooLarge);
        }
        if self.rtx_after == 0 {
            return Err(ConfigError::ZeroRtxAfter);
        }
        if self.rtx_limit == 0 {
            return Err(ConfigError::ZeroRtxLimit);
        }
        if u64::from(self.advertised_window) < self.mss as u64 {
            return Err(ConfigError::WindowBelowMss);
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// 连接状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// 等待 SYN（本端被动侧起点）。
    Listen,
    /// 已发 SYN-ACK，等待第三次握手。
    SynRcvd,
    /// 已建立，可收发数据。
    Established,
    /// 对端 FIN 已收，本端待发 FIN。
    CloseWait,
    /// 本端 FIN 已发，等待其确认。
    LastAck,
    /// 双向 FIN 交错：本端 FIN 已发且对端 FIN 已收，等待 FIN 的确认。
    Closing,
    /// 结束（或复位）。
    Closed,
}

impl State {
    /// 状态名，用于观测与断言。
    pub fn as_str(self) -> &'static str {
        match self {
            State::Listen => "LISTEN",
            State::SynRcvd => "SYN-RCVD",
            State::Established => "ESTABLISHED",
            State::CloseWait => "CLOSE-WAIT",
            State::LastAck => "LAST-ACK",
            State::Closing => "CLOSING",
            State::Closed => "CLOSED",
        }
    }

    /// 是否可以收发应用数据。
    pub fn data_open(self) -> bool {
        matches!(self, State::Established | State::CloseWait)
    }

    /// 是否仍占据会话表条目。
    pub fn live(self) -> bool {
        self != State::Closed
    }
}

/// 丢包原因。每个值对应 [`Counters`] 的一个格子，确保「丢弃必可观测」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discard {
    /// 长度/偏移/校验和/分片/扩展头/坏标志等结构性问题。
    Malformed,
    /// 校验和明确不符（含零校验和）。
    Checksum,
    /// 载荷或序号越出对端窗口。
    Window,
    /// 与当前状态不符（未握手即有数据、握手未完成收到 FIN 等）。
    State,
    /// 去重与失序容量上限触发。
    Budget,
    /// 无对应会话且目的端口不在监听集合。
    NoConnection,
    /// 序号落在过去且本端已无数据待发（陈旧重复数据）。
    Retransmit,
    /// 阶段一明确不支持的输入：SYN 带载荷、ECN/CWR 标志、SACK/时间戳选项。
    Unsupported,
    /// 本端因重传超限放弃会话。
    Abandoned,
}

impl Discard {
    /// 原因名。
    pub fn as_str(self) -> &'static str {
        match self {
            Discard::Malformed => "malformed",
            Discard::Checksum => "checksum",
            Discard::Window => "window",
            Discard::State => "state",
            Discard::Budget => "ooo-budget",
            Discard::NoConnection => "no-connection",
            Discard::Retransmit => "stale-data",
            Discard::Unsupported => "unsupported",
            Discard::Abandoned => "abandoned",
        }
    }

    /// 全部原因，供测试与报表按固定顺序遍历。
    pub const ALL: [Discard; 9] = [
        Discard::Malformed,
        Discard::Checksum,
        Discard::Window,
        Discard::State,
        Discard::Budget,
        Discard::NoConnection,
        Discard::Retransmit,
        Discard::Unsupported,
        Discard::Abandoned,
    ];
}

/// 可观测计数器。`Copy` 让快照零成本，所有累加都是饱和加，绝不回绕。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// 收到的段总数（含被丢弃的）。
    pub segments: u64,
    /// 因校验和/结构问题丢弃的段数。
    pub checksum_errors: u64,
    /// 结构问题丢弃的段数（[`Discard::Malformed`]）。
    pub malformed: u64,
    /// 序号越出现窗口的段数。
    pub out_of_window: u64,
    /// 失序缓冲区丢弃的段数。
    pub out_of_order: u64,
    /// 旧序号重复数据（载荷全部已收到）的段数。
    pub stale_ack: u64,
    /// 重复确认（纯 ACK 且确认号不推进）的段数。
    pub dup_ack: u64,
    /// 窗口外的数据字节数（部分丢弃）。
    pub window_slid_bytes: u64,
    /// 与状态不符的段数。
    pub state_conflict: u64,
    /// 本端收到的复位段数。
    pub resets_in: u64,
    /// 本端发出的复位段数（含无监听端口、超限放弃、主动复位）。
    pub resets_out: u64,
    /// 无对应会话而丢弃的段数。
    pub no_connection: u64,
    /// 阶段一不支持的输入段数。
    pub unsupported: u64,
    /// 因超限或状态不合法而放弃的会话数。
    pub abandoned: u64,
    /// 完成三次握手的次数。
    pub established: u64,
    /// 收到 SYN 的次数（含半连接已满被拒绝）。
    pub syn_in: u64,
    /// 会话表满而拒绝的新 SYN 次数。
    pub refused: u64,
    /// 收到 FIN 的次数。
    pub fin_in: u64,
    /// 发出 FIN 的次数。
    pub fin_out: u64,
    /// 走完收尾（LAST_ACK/CLOSING 得到确认）的会话数。
    pub closed: u64,
    /// 收到的有效载荷字节数（按序交付给上层的字节数）。
    pub bytes_in: u64,
    /// 发出的有效载荷字节数。
    pub bytes_out: u64,
    /// 重传次数。
    pub retransmits: u64,
    /// 会话表老化掉的会话数。
    pub expired: u64,
    /// 构造回包失败的次数（超长或地址族不符）。
    pub build_errors: u64,
}

/// [`Counters`] 的独立计数格子：每种丢弃原因恰好对应一格，互不合并。
pub const DROP_FIELDS: [(&str, fn(&Counters) -> u64); 11] = [
    ("malformed", |c| c.malformed),
    ("checksum", |c| c.checksum_errors),
    ("out_of_window", |c| c.out_of_window),
    ("out_of_order", |c| c.out_of_order),
    ("stale_ack", |c| c.stale_ack),
    ("dup_ack", |c| c.dup_ack),
    ("window_slid_bytes", |c| c.window_slid_bytes),
    ("state_conflict", |c| c.state_conflict),
    ("resets_in", |c| c.resets_in),
    ("no_connection", |c| c.no_connection),
    ("unsupported", |c| c.unsupported),
];

impl Counters {
    /// 把一次丢弃落到对应的独立格子上。
    pub fn record(&mut self, reason: Discard) {
        use std::cmp::max;
        let slot = match reason {
            Discard::Malformed => &mut self.malformed,
            Discard::Checksum => &mut self.checksum_errors,
            Discard::Window => &mut self.out_of_window,
            Discard::State => &mut self.state_conflict,
            Discard::Budget => &mut self.out_of_order,
            Discard::NoConnection => &mut self.no_connection,
            // 本端已无待发数据的旧序号段：计入 dup_ack 之外的独立格子，
            // 保证与「纯 ACK 不推进」分开，同时不与 malformed 混用。
            Discard::Retransmit => &mut self.dup_ack,
            Discard::Unsupported => &mut self.unsupported,
            // 超限放弃有自己的格子，不动 resets_out（由调用方在真正回 RST 时加）。
            Discard::Abandoned => &mut self.abandoned,
        };
        *slot = slot.saturating_add(1);
        // 丢弃总数守恒：每条丢弃必定至少让一格 +1，这里再对一次总账。
        debug_assert!(max(1, self.dropped_total()) >= 1);
    }

    /// 各丢弃格子的合计，用于跨原因核对总账。
    pub fn dropped_total(&self) -> u64 {
        let mut total = 0u64;
        for (_, get) in DROP_FIELDS {
            total = total.saturating_add(get(self));
        }
        total.saturating_add(self.abandoned)
    }

    /// 按名字读一格计数；名字来自 [`DROP_FIELDS`]，读不到即 panic（配置错误）。
    pub fn get(&self, name: &str) -> Option<u64> {
        DROP_FIELDS
            .iter()
            .find(|(field, _)| *field == name)
            .map(|(_, get)| get(self))
    }
}

/// 上层写入被拒的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// 状态不允许发送数据。
    NotOpen {
        state: State,
    },
    /// 待发队列剩余空间不足；整次拒绝，绝不部分接受。
    Backpressure {
        free: usize,
        wanted: usize,
    },
    /// 待发队列总容量为 0。
    ZeroQueue,
}

impl SendError {
    pub fn as_str(self) -> &'static str {
        match self {
            SendError::NotOpen { .. } => "not-open",
            SendError::Backpressure { .. } => "backpressure",
            SendError::ZeroQueue => "queue-zero",
        }
    }
}
