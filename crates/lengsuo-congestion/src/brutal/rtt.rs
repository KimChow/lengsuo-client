//! 自有 RTT 估计（RFC 6298）——替代 quinn-proto 的 `RttEstimator`。
//!
//! # 为什么不能直接用 quinn 的 RTT
//!
//! `quinn::congestion::Controller::on_ack` 的 `rtt: &RttEstimator` 参数类型
//! 来自 `quinn-proto`，但 **`quinn` 没有 re-export 它**：
//! - `quinn::RttEstimator` 不存在（实测 `E0425`）；
//! - `quinn::congestion::RttEstimator` 是**私有**导入（实测 `E0603`）。
//!
//! 而 `quinn-proto` 不能加入本 crate 的依赖 —— 那会改动 `Cargo.lock`，
//! 超出本卡边界（`Cargo.lock` 由基建卡独占）。
//!
//! 故本模块按 RFC 6298 自行维护 SRTT：调用方在**发送时**登记包号 → 发送时刻，
//! 在**收到 ACK** 时用「最大已确认包号」取样。
//!
//! # 与参考的对应
//!
//! 参考 `BrutalSender` 用 quic-go 的 `congestion.RTTStatsProvider.SmoothedRTT()`，
//! 语义与本模块一致（RFC 6298 的 SRTT）。

use std::time::Duration;

/// RFC 6298 平滑 RTT 估计器。
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RttState {
    /// 平滑 RTT（`None` = 尚未采样）。
    srtt_nanos: Option<u64>,
    /// RTT 偏差（RFC 6298 的 `RTTVAR`）。
    rttvar_nanos: u64,
}

impl RttState {
    /// 采纳一次 RTT 采样（RFC 6298 §2.2 / §2.3）。
    pub(crate) fn sample(&mut self, rtt: Duration) {
        let r = rtt.as_nanos().min(u64::MAX as u128) as u64;
        match self.srtt_nanos {
            // 首次采样：SRTT = R，RTTVAR = R/2。
            None => {
                self.srtt_nanos = Some(r);
                self.rttvar_nanos = r / 2;
            }
            Some(srtt) => {
                // RTTVAR = (1-β)·RTTVAR + β·|SRTT−R|，β = 1/4
                let diff = srtt.abs_diff(r);
                self.rttvar_nanos = self.rttvar_nanos.saturating_mul(3).saturating_add(diff) / 4;
                // SRTT = (1-α)·SRTT + α·R，α = 1/8
                self.srtt_nanos = Some(srtt.saturating_mul(7).saturating_add(r) / 8);
            }
        }
    }

    /// 当前平滑 RTT（未采样时为 `None`）。
    pub(crate) fn smoothed(&self) -> Option<Duration> {
        self.srtt_nanos.map(Duration::from_nanos)
    }
}
