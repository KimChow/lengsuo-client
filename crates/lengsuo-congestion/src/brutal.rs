//! Brutal 拥塞器（固定速率 + 窗口上限）——Hysteria2 Brutal 的 quinn 内核移植。
//!
//! # 参考实现（逐条对齐）
//!
//! 参考源：Xray 内嵌的 Hysteria2 fork
//! `transport/internet/hysteria/congestion/brutal/brutal.go`（`BrutalSender`）
//! 与 `transport/internet/hysteria/congestion/common/pacer.go`（token bucket）。
//! 速率来源：`transport/internet/hysteria/hub.go` 行 187-206 的 `switch congestion`
//! 分支（`UseBrutal(conn, min(BrutalUp, clientDown))` / `UseBrutal(conn, BrutalUp)`）。
//!
//! | 参考（Go, quic-go）                     | 本实现（Rust, quinn-proto）        |
//! |----------------------------------------|------------------------------------|
//! | `NewBrutalSender(bps)`                 | `BrutalConfig::new(bandwidth_bps)` |
//! | `GetCongestionWindow()`                | `Brutal::window()`                 |
//! | `OnPacketSent`                         | `Controller::on_sent`              |
//! | `OnPacketAcked`（参考是 **stub**）     | `Controller::on_ack`（**不覆写**） |
//! | `OnCongestionEvent`（参考是 **stub**） | `Controller::on_congestion_event`  |
//! | `OnCongestionEventEx`（ack/loss 统计） | `Controller::on_end_acks`          |
//! | `SetMaxDatagramSize`                   | `Controller::on_mtu_update`        |
//! | `TimeUntilSend` / `HasPacingBudget`    | 由 quinn 内建 pacer 承担（见下）    |
//!
//! # 单位约定（重要）
//!
//! - `BrutalConfig::bandwidth` = **比特/秒（bps）**，与 `Hysteria-CC-RX` /
//!   `Hysteria-CC-TX` 头的语义单位一致；
//! - 参考实现内部用 **字节/秒**（`congestion.ByteCount`），故本实现内部统一
//!   折算为 `bytes_per_sec = bandwidth / 8`；
//! - `ControllerMetrics::pacing_rate` 按 quinn 约定是**比特/秒**，故直接等于
//!   注入的 `bandwidth`。
//!
//! # 速率如何在 quinn 上真正生效
//!
//! quinn 的发送侧有**两道**闸门（`quinn-proto` `connection/mod.rs`）：
//! 1. **窗口闸门**：`in_flight + bytes_to_send >= window()` ⇒ 阻塞发送；
//! 2. **节奏闸门**（pacer）：按 `window / RTT` 的节奏放行。
//!
//! 两道闸门都只由 `window()` 驱动，故 **quinn 的实际发送速率上限 =
//! `window / RTT`**。把窗口设成 BDP（`bytes_per_sec × RTT`）即得到
//! `bytes_per_sec` 字节/秒 —— **恰是协商出来的速率**。
//!
//! # 与参考的差异（摘要，完整清单见 `docs/congestion-status.md`）
//!
//! 1. **窗口系数取 1 而非参考的 2**（`congestionWindowMultiplier`）：参考的
//!    pacer 单独限速（`bps / ackRate` 字节/秒），窗口只是**缓冲上限**，故
//!    取 2 留出突发余量。quinn 没有独立的「pacer 速率」参数，窗口**就是**
//!    限速器，故取 1 才能让实际速率等于协商值（取 2 会翻倍）。
//! 2. **ack 率统计以字节计**（参考以**包**计）：quinn 的
//!    `on_congestion_event` 只给出 `lost_bytes`，没有「本批被确认的包数」这一
//!    口径；最小样本阈值相应折算为 `50 * MTU` 字节（参考的 50 个包）。
//! 3. **RTT 自行测量**：`quinn` 未 re-export `quinn_proto::RttEstimator`
//!    （`quinn::RttEstimator` 不存在、`quinn::congestion::RttEstimator` 是私有的），
//!    且 `quinn-proto` 不能加入依赖（会改 `Cargo.lock`）。本实现按 RFC 6298
//!    自行维护 SRTT：发送时登记包号 → 发送时刻，收到 ACK 时取样。
//! 4. **未覆写 `on_ack`**：同上，无法命名 `RttEstimator`。参考的
//!    `OnPacketAcked` 本身是 **stub**（空实现），故语义上等价。
//! 5. **窗口不除以 ACK 率**：参考用 `bps / ackRate` 放大窗口来补偿丢包，
//!    目的是维持**有效吞吐**（`ackRate` 越低、窗口越大）。quinn 的窗口**就是**
//!    限速器，放大窗口会**超出**协商速率，违背「协商值真正生效」的要求，
//!    故本实现保持窗口 = BDP；ACK 率仍被跟踪，仅供可观测性与上层决策
//!    （见 [`Brutal::ack_rate`] / [`Brutal::loss_compensated_rate_bps`]）。
//! 6. **窗口不收缩**：参考 `OnCongestionEvent` 是 stub（窗口不缩），本实现
//!    同样不缩。
//!
//! # fail-closed
//!
//! 零速率 / 非法速率**绝不**除零、**绝不**产生无限窗口：`BrutalConfig::new`
//! 直接返回 `Err`；若调用方绕过校验直接构造公开字段，工厂会退化为
//! 「最小窗口」控制器（`2 * MTU`），并 `tracing::warn!` 记录一次。

use std::any::Any;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};

use self::ack_rate::AckRateTracker;
use self::rtt::RttState;

pub mod ack_rate;
pub mod config;
mod rtt;

pub use self::ack_rate::{ACK_RATE_SLOT_COUNT, MIN_ACK_RATE, MIN_SAMPLE_COUNT};
pub use self::config::{BrutalConfig, ConfigError, DEFAULT_INITIAL_WINDOW};

/// 发送时刻表的容量上限（防止长连接无界增长）。
const MAX_SENT_ENTRIES: usize = 4096;

/// Brutal 拥塞器。
///
/// 语义：**固定速率 + 窗口上限**。窗口 = `bytes_per_sec × RTT`（BDP），
/// 下界为当前 MTU；**丢包不激进降速**（参考 `OnCongestionEvent` 是 stub，
/// 窗口不收缩）。
#[derive(Debug, Clone)]
pub struct Brutal {
    config: Arc<BrutalConfig>,
    /// 注入带宽（比特/秒）。
    bandwidth_bps: u64,
    /// 注入带宽折算的字节/秒。
    bytes_per_sec: u64,
    /// 当前 MTU（字节）。
    current_mtu: u64,
    /// 累计发送字节。
    total_sent: u64,
    /// 累计丢失字节。
    total_lost: u64,
    /// 上一次结算时累计已确认字节（用于推导本批确认量）。
    acked_total: u64,
    /// 自有 SRTT。
    rtt: RttState,
    /// ACK 率估计（参考 `updateAckRate`）。
    ack_rate: AckRateTracker,
    /// 发送时刻队列：(发送时刻, 累计发送字节)，用于 RTT 采样。
    sent_queue: VecDeque<(Instant, u64)>,
    /// 控制器首个观测时刻（用于换算「秒」）。
    epoch: Option<Instant>,
    /// 非法速率 ⇒ 退化模式（最小窗口，绝不无限窗口）。
    degraded: bool,
}

impl Brutal {
    /// 构造一个拥塞器（通常由 [`BrutalConfig`] 工厂调用）。
    pub fn new(config: Arc<BrutalConfig>, current_mtu: u16) -> Self {
        let degraded = !config.is_valid();
        if degraded {
            tracing::warn!(
                bandwidth_bps = config.bandwidth,
                "Brutal 速率非法，退化为最小窗口（fail-closed）"
            );
        }
        let mtu = u64::from(current_mtu.max(1));
        Self {
            bandwidth_bps: config.bandwidth,
            bytes_per_sec: config.bytes_per_sec(),
            current_mtu: mtu,
            total_sent: 0,
            total_lost: 0,
            acked_total: 0,
            rtt: RttState::default(),
            ack_rate: AckRateTracker::new(),
            sent_queue: VecDeque::new(),
            epoch: None,
            degraded,
            config,
        }
    }

    /// 当前允许的在途窗口上限（字节）。
    ///
    /// 对齐参考 `GetCongestionWindow()` 的 `bps × rtt.Seconds() × 系数`，
    /// 且 `cwnd < maxDatagramSize` 时取 `maxDatagramSize`。本实现系数取 **1**
    /// （见模块文档差异清单第 1 条），**不**除以 ACK 率
    /// （见模块文档差异清单第 5 条）。
    fn cap(&self) -> u64 {
        if self.degraded {
            // fail-closed：最小可发窗口，绝不 0（quinn 的 pacer 对 0 窗口有断言），
            // 绝不使用户配置的非法速率。
            return 2 * self.current_mtu;
        }
        let Some(rtt) = self.rtt.smoothed() else {
            // 参考 `rtt <= 0` 分支：窗口取缺省 10240。
            return self.config.effective_initial_window().max(self.current_mtu);
        };
        let bytes = self.bytes_per_sec as f64 * rtt.as_secs_f64();
        let cap = if bytes.is_finite() && bytes > 0.0 {
            bytes as u64
        } else {
            0
        };
        cap.max(self.current_mtu)
    }

    /// 当前 ACK 率（∈ `[MIN_ACK_RATE, 1]`）。
    ///
    /// 对齐参考 `BrutalSender.ackRate`：样本不足时为 1，丢包时下限 0.8。
    /// 参考用它放大窗口以维持**有效吞吐**；本实现**不**用它放大窗口
    /// （差异清单第 5 条），故本值仅供可观测性与上层决策使用。
    pub fn ack_rate(&self) -> f64 {
        self.ack_rate.rate()
    }

    /// 丢包补偿后的目标速率（**比特/秒**）= `bandwidth / ack_rate`。
    ///
    /// 这是参考实现实际使用的 pacer 速率（`bps / ackRate` 字节/秒），
    /// 供可观测性使用；quinn 的实际限速仍由 `window()` 驱动（见模块文档）。
    pub fn loss_compensated_rate_bps(&self) -> u64 {
        let rate = self.ack_rate.rate();
        if rate <= 0.0 {
            return self.bandwidth_bps;
        }
        (self.bandwidth_bps as f64 / rate) as u64
    }

    /// 自「控制器首个观测时刻」起经过的秒数（参考用 `eventTime / time.Second`，
    /// 语义等价：只看相对差值）。
    fn second(&mut self, now: Instant) -> u64 {
        let epoch = *self.epoch.get_or_insert(now);
        now.saturating_duration_since(epoch).as_secs()
    }

    /// ACK 率统计的最小样本阈值（字节）＝ 参考的 50 个包折算为 `50 × MTU`。
    fn min_sample_bytes(&self) -> u64 {
        MIN_SAMPLE_COUNT.saturating_mul(self.current_mtu)
    }
}

impl Controller for Brutal {
    fn on_sent(&mut self, now: Instant, bytes: u64, _last_packet_number: u64) {
        self.total_sent = self.total_sent.saturating_add(bytes);

        // quinn 的包号**按包号空间（space）各自计数**，且 `on_sent` 的
        // `last_packet_number` 与 `on_end_acks` 的 `largest_packet_num_acked`
        // 可能来自**不同的 space**，二者不可直接比对。故这里用一个
        // **FIFO 队列**登记「发送时刻 → 累计发送字节」，
        // `on_end_acks` 时用「已确认字节数」反查该队列，定位被确认的字节
        // 落在哪一次发送里，从而取到正确的 RTT 采样点。
        //
        // 参考实现不需要这一步：quic-go 直接把 `eventTime` 传给
        // `OnCongestionEventEx`，RTT 由 quic-go 自己维护。
        let cumulative = self.total_sent;
        self.sent_queue.push_back((now, cumulative));
        while self.sent_queue.len() > MAX_SENT_ENTRIES {
            self.sent_queue.pop_front();
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        // 已确认字节恒等式：acked = sent − lost − in_flight（quinn 在 ack 与
        // 丢包时都会把包从 `in_flight` 中摘除）。
        let acked_cumulative = self
            .total_sent
            .saturating_sub(self.total_lost)
            .saturating_sub(in_flight);
        let acked_delta = acked_cumulative.saturating_sub(self.acked_total);
        self.acked_total = acked_cumulative;

        // RTT 采样（RFC 6298）：找出「累计发送字节 ≤ 已确认字节」的最后一次
        // 发送 —— 它的发送时刻即被确认字节的近似发出时刻。
        if let Some((sent_at, _)) = self
            .sent_queue
            .iter()
            .rfind(|(_, cumulative)| *cumulative <= acked_cumulative)
        {
            let sent_at = *sent_at;
            let rtt = now.saturating_duration_since(sent_at);
            if !rtt.is_zero() {
                self.rtt.sample(rtt);
            }
        }

        let second = self.second(now);
        self.ack_rate.record(second, acked_delta, 0);
        self.ack_rate.update(second, self.min_sample_bytes());
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // 参考 `OnCongestionEvent` 是 **stub**：窗口不收缩、速率不下降。
        // 丢包只用于 ACK 率统计（参考 `OnCongestionEventEx` 的 loss 计数）。
        self.total_lost = self.total_lost.saturating_add(lost_bytes);
        let second = self.second(now);
        self.ack_rate.record(second, 0, lost_bytes);
        self.ack_rate.update(second, self.min_sample_bytes());
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = u64::from(new_mtu.max(1));
    }

    fn window(&self) -> u64 {
        self.cap()
    }

    fn metrics(&self) -> ControllerMetrics {
        // `ControllerMetrics` 是 `#[non_exhaustive]`，跨 crate 只能用
        // `Default` + 逐字段赋值构造（不能用具名字段语法）。
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        // Brutal 没有慢启动阈值概念（参考 `InSlowStart()` 恒为 false），
        // 故 `ssthresh` 保持 `None`。
        // quinn 约定：比特/秒；等于注入的协商带宽。
        metrics.pacing_rate = Some(self.bandwidth_bps);
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.config.effective_initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self, current_mtu))
    }
}
