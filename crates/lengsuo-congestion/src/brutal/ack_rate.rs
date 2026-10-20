//! ACK 率估计（对齐参考 `BrutalSender.updateAckRate` / `OnCongestionEventEx`）。
//!
//! # 参考语义
//!
//! 参考用 5 个**秒级**槽累计（`pktInfoSlots`）本秒被确认的**包**数
//! （`AckCount`）与丢失的**包**数（`LossCount`），然后：
//! - 样本总数 `< minSampleCount`（50）⇒ `ackRate = 1`；
//! - 否则 `rate = ack / (ack + loss)`，并对下界 `minAckRate`（0.8）做钳位。
//!
//! # 与参考的差异
//!
//! 本实现以**字节**为单位统计（参考以包计）。原因：quinn-proto 的
//! `Controller::on_congestion_event` 只给出 `lost_bytes`，**没有**「本批被
//! 确认的包数」这一口径；而 `on_end_acks` 给出的是 `in_flight`（字节），
//! 只能推出被确认的**字节**数。故最小样本阈值相应折算为
//! `minSampleCount × MTU` 字节（等价于参考的 50 个包）。

/// 参考 `minAckRate`：ACK 率下界。
pub const MIN_ACK_RATE: f64 = 0.8;

/// 参考 `pktInfoSlotCount`：ACK 率统计的秒级滑窗长度。
pub const ACK_RATE_SLOT_COUNT: u64 = 5;

/// 参考 `minSampleCount`：ACK 率统计的最小样本数（参考以**包**计）。
pub const MIN_SAMPLE_COUNT: u64 = 50;

/// 单个统计槽（对齐参考 `pktInfo`）。
#[derive(Debug, Clone, Copy, Default)]
struct AckSlot {
    /// 该槽对应的秒序号。
    second: Option<u64>,
    /// 该槽累计的已确认字节。
    ack_bytes: u64,
    /// 该槽累计的丢失字节。
    loss_bytes: u64,
}

/// ACK 率估计器。
#[derive(Debug, Clone)]
pub(crate) struct AckRateTracker {
    slots: [AckSlot; ACK_RATE_SLOT_COUNT as usize],
    rate: f64,
}

impl AckRateTracker {
    /// 构造（初始 ACK 率 = 1，与参考 `ackRate: 1` 一致）。
    pub(crate) fn new() -> Self {
        Self {
            slots: [AckSlot::default(); ACK_RATE_SLOT_COUNT as usize],
            rate: 1.0,
        }
    }

    /// 把本秒的 ACK / 丢包字节计入槽（对齐参考 `OnCongestionEventEx`）。
    pub(crate) fn record(&mut self, second: u64, ack_bytes: u64, loss_bytes: u64) {
        let idx = (second % ACK_RATE_SLOT_COUNT) as usize;
        let slot = &mut self.slots[idx];
        if slot.second != Some(second) {
            // 未初始化的槽或过期的槽 ⇒ 整体重置（对齐参考的 else 分支）。
            *slot = AckSlot {
                second: Some(second),
                ack_bytes,
                loss_bytes,
            };
        } else {
            slot.ack_bytes = slot.ack_bytes.saturating_add(ack_bytes);
            slot.loss_bytes = slot.loss_bytes.saturating_add(loss_bytes);
        }
    }

    /// 重算 ACK 率（对齐参考 `updateAckRate`）。
    pub(crate) fn update(&mut self, second: u64, min_sample_bytes: u64) {
        let min_second = second.saturating_sub(ACK_RATE_SLOT_COUNT);
        let mut ack = 0u64;
        let mut loss = 0u64;
        for slot in &self.slots {
            // 参考：`if info.Timestamp < minTimestamp { continue }`
            let Some(ts) = slot.second else { continue };
            if ts < min_second {
                continue;
            }
            ack = ack.saturating_add(slot.ack_bytes);
            loss = loss.saturating_add(slot.loss_bytes);
        }
        let total = ack.saturating_add(loss);
        if total < min_sample_bytes {
            // 样本不足 ⇒ 视为无丢包（对齐参考 `b.ackRate = 1`）。
            self.rate = 1.0;
            return;
        }
        let rate = ack as f64 / total as f64;
        // 参考：低于 `minAckRate` 则钳位到 `minAckRate`。
        self.rate = if rate < MIN_ACK_RATE {
            MIN_ACK_RATE
        } else {
            rate
        };
    }

    /// 当前 ACK 率（∈ `[MIN_ACK_RATE, 1]`）。
    pub(crate) fn rate(&self) -> f64 {
        self.rate
    }
}
