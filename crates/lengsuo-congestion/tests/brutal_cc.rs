//! Brutal 拥塞器的纯逻辑测试（不起网络、不依赖真实时钟）。
//!
//! 覆盖任务书要求的五组断言：
//! 1. 固定速率下，窗口不超过 `bandwidth × RTT` 上限（逐项断言）；
//! 2. 丢包（`on_congestion_event`）**不**把速率降到更低（Brutal 语义）；
//! 3. `window()` 随 ack 推进单调不减到上限；
//! 4. `metrics()` 的 `pacing_rate` 等于注入带宽；
//! 5. `clone_box()` 后状态一致（`initial_window` 相同）。
//!
//! 全部用例带总超时（`#[test]` 内的断言在毫秒级完成；外层用
//! `timeout` 语义由 CI 兜底）。

use std::sync::Arc;
use std::time::{Duration, Instant};

use lengsuo_congestion::brutal::{Brutal, BrutalConfig};
use quinn::congestion::Controller;

/// 测试用 MTU（quinn 的 `INITIAL_MTU`）。
const MTU: u16 = 1200;

/// 测试用协商速率：1 MiB/s（**字节/秒**）⇒ 8 Mbit/s。
const BYTES_PER_SEC: u64 = 1024 * 1024;
const BPS: u64 = BYTES_PER_SEC * 8;

/// 测试用 RTT：100 ms。
const RTT: Duration = Duration::from_millis(100);

/// 构造一个 Brutal 控制器。
fn controller(bps: u64) -> Brutal {
    let config = BrutalConfig::new(bps, 0).expect("速率合法");
    Brutal::new(Arc::new(config), MTU)
}

/// 带宽时延积（BDP）上界 = `bytes_per_sec × rtt`（字节）。
fn bdp() -> u64 {
    BYTES_PER_SEC * RTT.as_nanos() as u64 / 1_000_000_000
}

/// 推进一次「发送 → 确认」往返，并让 RTT 收敛到 [`RTT`]。
///
/// 模拟：发送 `bytes` 字节（`last_packet_number` 递增），随后经过 `rtt`
/// 收到 ACK（`in_flight` 归零）。
fn round_trip(cc: &mut Brutal, bytes: u64, rtt: Duration, packet_number: u64) {
    let now = Instant::now();
    cc.on_sent(now, bytes, packet_number);
    cc.on_end_acks(now + rtt, 0, false, Some(packet_number));
}

/// 反复往返，直到 SRTT 收敛（RFC 6298 的 α=1/8 ⇒ 约 30 次足够接近真值）。
fn converge(cc: &mut Brutal, bytes: u64, rtt: Duration) {
    let mut pn = 0u64;
    for _ in 0..40 {
        pn += 1;
        round_trip(cc, bytes, rtt, pn);
    }
}

// ---------------------------------------------------------------------------
// 1. 窗口上限：不超过 `bandwidth × RTT`
// ---------------------------------------------------------------------------

#[test]
fn window_does_not_exceed_bandwidth_times_rtt() {
    let mut cc = controller(BPS);
    converge(&mut cc, MTU as u64, RTT);

    // 上界 = bytes_per_sec × rtt（系数取 1，见模块文档差异清单第 1 条）。
    let cap = bdp();
    let window = cc.window();

    assert!(
        window <= cap,
        "窗口 {window} 超过上限 {cap}（bandwidth × RTT）"
    );
    // 同时窗口必须**达到**该上限（否则协商速率没真正生效）。
    assert!(
        window >= cap * 9 / 10,
        "窗口 {window} 明显低于上限 {cap}，协商速率未生效"
    );
}

#[test]
fn window_is_at_least_one_mtu() {
    let cc = controller(BPS);
    // 未测到 RTT 时取参考缺省窗口（10240），且**不小于**一个 MTU。
    assert!(cc.window() >= u64::from(MTU));
}

// ---------------------------------------------------------------------------
// 2. 丢包不降速（Brutal 与 CUBIC/BBR 的关键差别）
// ---------------------------------------------------------------------------

#[test]
fn loss_does_not_reduce_rate_or_shrink_window() {
    let mut cc = controller(BPS);
    converge(&mut cc, MTU as u64, RTT);

    let window_before = cc.window();
    let rate_before = cc.metrics().pacing_rate;

    // 大量丢包：参考 `OnCongestionEvent` 是 stub，窗口不收缩、速率不下降。
    let now = Instant::now();
    for _ in 0..20 {
        cc.on_congestion_event(now, now, false, 4096);
    }

    assert_eq!(
        cc.metrics().pacing_rate,
        rate_before,
        "丢包后 pacing_rate 变了（Brutal 不应降速）"
    );
    assert_eq!(
        cc.window(),
        window_before,
        "丢包后窗口收缩了（Brutal 语义：窗口不因丢包而缩）"
    );
}

#[test]
fn loss_never_lowers_pacing_rate_below_injected_bandwidth() {
    let mut cc = controller(BPS);
    converge(&mut cc, MTU as u64, RTT);

    let now = Instant::now();
    cc.on_congestion_event(now, now, false, 100_000);

    let rate = cc.metrics().pacing_rate.expect("pacing_rate 一定有值");
    assert_eq!(
        rate, BPS,
        "丢包后 pacing_rate 不等于注入带宽（Brutal 固定速率）"
    );
}

// ---------------------------------------------------------------------------
// 3. 窗口随 ack 推进单调不减到上限
// ---------------------------------------------------------------------------

#[test]
fn window_grows_monotonically_up_to_the_cap() {
    let mut cc = controller(BPS);
    let mut pn = 0u64;
    let mut previous = cc.window();

    for _ in 0..40 {
        pn += 1;
        round_trip(&mut cc, MTU as u64, RTT, pn);
        let current = cc.window();
        assert!(
            current >= previous,
            "窗口回退了：{previous} → {current}（Brutal 不允许回退）"
        );
        previous = current;
    }

    let cap = bdp();
    assert!(previous <= cap, "窗口 {previous} 超过上限 {cap}");
}

// ---------------------------------------------------------------------------
// 4. metrics().pacing_rate 等于注入带宽
// ---------------------------------------------------------------------------

#[test]
fn metrics_pacing_rate_equals_injected_bandwidth() {
    let cc = controller(BPS);
    let metrics = cc.metrics();
    assert_eq!(metrics.pacing_rate, Some(BPS), "pacing_rate 未反映注入带宽");
    assert_eq!(metrics.congestion_window, cc.window());
    // Brutal 无慢启动阈值概念。
    assert_eq!(metrics.ssthresh, None);
}

#[test]
fn metrics_pacing_rate_tracks_the_negotiated_value() {
    // 逐项断言：不同协商速率 ⇒ 不同 pacing_rate。
    for bps in [8_000u64, 100_000, 8_000_000, 1_000_000_000] {
        let cc = controller(bps);
        assert_eq!(
            cc.metrics().pacing_rate,
            Some(bps),
            "pacing_rate 未反映协商速率 {bps}"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. clone_box 后状态一致
// ---------------------------------------------------------------------------

#[test]
fn clone_box_preserves_state() {
    let mut cc = controller(BPS);
    converge(&mut cc, MTU as u64, RTT);

    let cloned = cc.clone_box();
    assert_eq!(
        cloned.initial_window(),
        cc.initial_window(),
        "克隆后 initial_window 不一致"
    );
    assert_eq!(cloned.window(), cc.window(), "克隆后窗口不一致");
    assert_eq!(
        cloned.metrics().pacing_rate,
        cc.metrics().pacing_rate,
        "克隆后 pacing_rate 不一致"
    );
}

// ---------------------------------------------------------------------------
// fail-closed：零速率 / 非法速率
// ---------------------------------------------------------------------------

#[test]
fn zero_bandwidth_is_rejected() {
    assert!(BrutalConfig::new(0, 0).is_err(), "零速率必须 fail-closed");
}

#[test]
fn sub_byte_per_second_bandwidth_is_rejected() {
    // 1 bps = 0.125 字节/秒 ⇒ 低于最小合法值。
    assert!(
        BrutalConfig::new(1, 0).is_err(),
        "低于 1 字节/秒的速率必须 fail-closed"
    );
}

#[test]
fn degraded_controller_never_yields_unbounded_window() {
    // 绕过校验直接构造（公开字段）⇒ 工厂必须退化为最小窗口。
    let config = BrutalConfig {
        bandwidth: 0,
        initial_window: 0,
    };
    let mut cc = Brutal::new(Arc::new(config), MTU);
    let now = Instant::now();
    cc.on_sent(now, 65_535, 1);
    cc.on_end_acks(now + RTT, 0, false, Some(1));

    let window = cc.window();
    assert!(
        window > 0 && window <= 2 * u64::from(MTU),
        "非法速率下窗口应退化为 2×MTU，实际 {window}"
    );
    // 不得除零 / 产生 NaN→0 的病态窗口。
    assert!(window >= u64::from(MTU), "退化窗口不应小于 1 个 MTU");
}

#[test]
fn config_from_bytes_per_sec_converts_to_bits() {
    let config = BrutalConfig::from_bytes_per_sec(BYTES_PER_SEC, 0).expect("合法");
    assert_eq!(config.bandwidth, BPS);
    assert_eq!(config.bytes_per_sec(), BYTES_PER_SEC);
}

#[test]
fn from_negotiated_accepts_a_real_rate() {
    let config = BrutalConfig::from_negotiated(Some(BYTES_PER_SEC), 0).expect("合法");
    assert_eq!(config.bandwidth, BPS);
}

#[test]
fn from_negotiated_rejects_absent_rate() {
    // 参考的回落分支（`BrutalUp == 0 || clientDown == 0`）⇒ 不用 Brutal。
    assert!(
        BrutalConfig::from_negotiated(None, 0).is_err(),
        "协商不出速率时必须 fail-closed（不得用 bandwidth=0 构造）"
    );
}

#[test]
fn from_negotiated_rejects_zero_rate() {
    assert!(
        BrutalConfig::from_negotiated(Some(0), 0).is_err(),
        "协商出 0 速率时必须 fail-closed"
    );
}

// ---------------------------------------------------------------------------
// 初始窗口
// ---------------------------------------------------------------------------

#[test]
fn initial_window_defaults_to_reference_value() {
    let cc = controller(BPS);
    assert_eq!(
        cc.initial_window(),
        lengsuo_congestion::brutal::DEFAULT_INITIAL_WINDOW
    );
}

#[test]
fn initial_window_honours_explicit_value() {
    let config = BrutalConfig::new(BPS, 32_768).expect("合法");
    let cc = Brutal::new(Arc::new(config), MTU);
    assert_eq!(cc.initial_window(), 32_768);
}

// ---------------------------------------------------------------------------
// quinn 窗口闸门模拟：证明「协商出来的速率」真的被限速
// ---------------------------------------------------------------------------

/// 复刻 quinn-proto 的发送闸门，验证协商速率确实生效。
///
/// quinn-proto `connection/mod.rs` 的发送路径有两道闸门：
/// 1. **窗口闸门**：`in_flight + bytes_to_send >= window()` ⇒ 阻塞发送；
/// 2. **节奏闸门**（pacer）：按 `window / RTT` 的节奏放行。
///
/// 两道闸门都只由 `window()` 驱动 ⇒ **实际发送速率上限 = `window / RTT`**。
/// 本用例按此模型逐轮模拟发送，断言稳态速率等于协商出来的字节/秒
/// （而不是 CUBIC 那种随丢包波动的速率）。
#[test]
fn quinn_window_gate_limits_rate_to_negotiated_bandwidth() {
    let mut cc = controller(BPS);
    converge(&mut cc, MTU as u64, RTT);

    let window = cc.window();
    // 每个 RTT 最多能发出「一个窗口」的字节 ⇒ 速率 = window / RTT。
    let rate_bytes_per_sec = window as f64 / RTT.as_secs_f64();
    let expected = BYTES_PER_SEC as f64;
    let deviation = (rate_bytes_per_sec - expected).abs() / expected;
    assert!(
        deviation < 0.05,
        "quinn 窗口闸门给出的速率 {rate_bytes_per_sec} B/s 偏离协商值 {expected} B/s 过多"
    );

    // 模拟 10 个 RTT：每轮能填满窗口 ⇒ 总字节 ≈ 10 × window。
    let mut in_flight = 0u64;
    let mut sent_total = 0u64;
    let mut pn = 0u64;
    for _ in 0..10 {
        // 填满窗口（quinn 的窗口闸门）。
        while in_flight + MTU as u64 <= cc.window() {
            pn += 1;
            cc.on_sent(Instant::now(), MTU as u64, pn);
            in_flight += MTU as u64;
            sent_total += MTU as u64;
        }
        // 一个 RTT 后全部被确认。
        cc.on_end_acks(Instant::now() + RTT, 0, false, Some(pn));
        in_flight = 0;
    }
    assert!(
        sent_total >= window * 9,
        "模拟发送量 {sent_total} 远小于窗口预期（约 {}）",
        window * 10
    );
}
