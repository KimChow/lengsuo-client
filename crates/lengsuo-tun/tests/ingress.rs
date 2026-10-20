//! 设备 → 分类 → 出口接线的默认套件测试。
//!
//! 全部使用内存假设备、假分类器与假出口，不创建 TUN、不碰网卡、不访问网络。
//! 生产设备适配是 Windows 上的 `impl PacketSource for Device`，不在本文件覆盖。

use std::collections::VecDeque;
use std::time::Duration;

use lengsuo_tun::ingress::{
    Classifier, DenyReason, EgressSink, Ingress, IngressLimits, PacketSource, Receipt, Step,
    StopReason,
};
use lengsuo_tun::packet::PacketInfo;

/// 内存收包队列：队列空时返回超时；可注入一次设备错误。
struct FakeSource {
    queue: VecDeque<Vec<u8>>,
    error: Option<String>,
}

impl FakeSource {
    fn with(packets: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            queue: packets.into_iter().collect(),
            error: None,
        }
    }

    fn failing(message: &str) -> Self {
        Self {
            queue: VecDeque::new(),
            error: Some(message.to_string()),
        }
    }
}

impl PacketSource for FakeSource {
    type Error = String;

    fn receive(&mut self, _timeout: Duration) -> Result<Receipt, Self::Error> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        Ok(self
            .queue
            .pop_front()
            .map_or(Receipt::Timeout, Receipt::Packet))
    }
}

/// 分类决定：命中（带出口标签）、无归属、分类失败。
enum Decision {
    Hit(&'static str),
    Miss,
    Fail(&'static str),
}

struct FakeClassifier {
    decisions: VecDeque<Decision>,
    seen: Vec<PacketInfo>,
    calls: usize,
}

impl FakeClassifier {
    fn new(decisions: impl IntoIterator<Item = Decision>) -> Self {
        Self {
            decisions: decisions.into_iter().collect(),
            seen: Vec::new(),
            calls: 0,
        }
    }
}

impl Classifier for FakeClassifier {
    type Attribution = &'static str;
    type Error = String;

    fn classify(&mut self, info: &PacketInfo) -> Result<Option<Self::Attribution>, Self::Error> {
        self.calls += 1;
        self.seen.push(*info);
        match self.decisions.pop_front().unwrap_or(Decision::Miss) {
            Decision::Hit(egress) => Ok(Some(egress)),
            Decision::Miss => Ok(None),
            Decision::Fail(detail) => Err(detail.to_string()),
        }
    }
}

#[derive(Default)]
struct RecordingSink {
    fail: bool,
    delivered: Vec<(&'static str, Vec<u8>, PacketInfo)>,
}

impl RecordingSink {
    fn failing() -> Self {
        Self {
            fail: true,
            delivered: Vec::new(),
        }
    }
}

impl EgressSink<&'static str> for RecordingSink {
    type Error = String;

    fn deliver(
        &mut self,
        packet: &[u8],
        info: &PacketInfo,
        attribution: &'static str,
    ) -> Result<(), Self::Error> {
        if self.fail {
            return Err("出口离线".to_string());
        }
        self.delivered.push((attribution, packet.to_vec(), *info));
        Ok(())
    }
}

/// 最小合法 IPv4/TCP 报文：20 字节 IP 头 + 20 字节 TCP 头 + 3 字节载荷。
///
/// 只在本测试文件内构造，避免为一个用例拉入共享测试辅助模块而触发
/// 未使用函数告警。
fn valid_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 20 + 20 + 3];
    packet[0] = 0x45; // IPv4, IHL=5
    let total = packet.len() as u16;
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[6] = 0x40; // DF
    packet[8] = 64; // TTL
    packet[9] = 6; // TCP
    packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
    packet[16..20].copy_from_slice(&[198, 51, 100, 7]);
    packet[20..22].copy_from_slice(&5000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443u16.to_be_bytes());
    packet[32] = 5 << 4; // TCP data offset = 5 words
    let mut sum: u32 = 0;
    for word in packet[..20].as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes(*word));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn step(ingress: &mut Ingress<FakeSource, FakeClassifier, RecordingSink>) -> Step {
    ingress.step(Duration::from_millis(1))
}

#[test]
fn hit_is_delivered_with_attribution() {
    let packet = valid_packet();
    let mut ingress = Ingress::new(
        FakeSource::with([packet.clone()]),
        FakeClassifier::new([Decision::Hit("env-a")]),
        RecordingSink::default(),
    );

    assert_eq!(step(&mut ingress), Step::Delivered);
    let stats = ingress.stats();
    assert_eq!(stats.received, 1);
    assert_eq!(stats.delivered, 1);
    assert_eq!(stats.denied_no_attribution, 0);
    assert_eq!(stats.egress_errors, 0);

    let delivered = &ingress.sink().delivered;
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].0, "env-a");
    assert_eq!(delivered[0].1, packet);
    assert_eq!(delivered[0].2.destination_port, 443);
}

#[test]
fn miss_is_dropped_and_counted_by_reason() {
    let mut ingress = Ingress::new(
        FakeSource::with([valid_packet()]),
        FakeClassifier::new([Decision::Miss]),
        RecordingSink::default(),
    );

    assert_eq!(
        step(&mut ingress),
        Step::Denied {
            reason: DenyReason::NoAttribution,
            detail: None,
        }
    );
    let stats = ingress.stats();
    assert_eq!(stats.received, 1);
    assert_eq!(stats.delivered, 0);
    assert_eq!(stats.denied_no_attribution, 1);
    assert_eq!(stats.denied(DenyReason::NoAttribution), 1);
    assert_eq!(stats.denied(DenyReason::ClassifierError), 0);
    assert!(ingress.sink().delivered.is_empty());
}

#[test]
fn classifier_error_is_denied_not_delivered() {
    let mut ingress = Ingress::new(
        FakeSource::with([valid_packet()]),
        FakeClassifier::new([Decision::Fail("分类器内部错误")]),
        RecordingSink::default(),
    );

    let outcome = step(&mut ingress);
    let Step::Denied { reason, detail } = outcome else {
        panic!("分类器报错必须丢弃，实际 {outcome:?}");
    };
    assert_eq!(reason, DenyReason::ClassifierError);
    assert_eq!(detail.as_deref(), Some("分类器内部错误"));

    let stats = ingress.stats();
    assert_eq!(stats.received, 1);
    assert_eq!(stats.delivered, 0, "分类器报错不得投递");
    assert_eq!(
        stats.denied_no_attribution, 1,
        "分类器报错计入 denied_no_attribution"
    );
    assert_eq!(stats.denied(DenyReason::ClassifierError), 1);
    assert_eq!(stats.denied(DenyReason::NoAttribution), 0);
    assert_eq!(stats.last_deny_detail.as_deref(), Some("分类器内部错误"));
    assert!(ingress.sink().delivered.is_empty());
}

#[test]
fn egress_error_is_counted_separately() {
    let mut ingress = Ingress::new(
        FakeSource::with([valid_packet()]),
        FakeClassifier::new([Decision::Hit("env-b")]),
        RecordingSink::failing(),
    );

    let outcome = step(&mut ingress);
    assert!(matches!(outcome, Step::EgressFailed { .. }), "{outcome:?}");
    let stats = ingress.stats();
    assert_eq!(stats.received, 1);
    assert_eq!(stats.delivered, 0);
    assert_eq!(stats.egress_errors, 1);
    assert_eq!(stats.denied_no_attribution, 0, "出口失败不算未归属");
    assert_eq!(stats.last_egress_detail.as_deref(), Some("出口离线"));
}

#[test]
fn receive_timeout_is_idle_not_an_error() {
    let mut ingress = Ingress::new(
        FakeSource::with(Vec::new()),
        FakeClassifier::new(Vec::new()),
        RecordingSink::default(),
    );

    assert_eq!(step(&mut ingress), Step::Idle);
    let stats = ingress.stats();
    assert_eq!(stats.received, 0);
    assert_eq!(stats.receive_timeouts, 1);
    assert_eq!(stats.device_errors, 0);
    assert_eq!(stats.delivered, 0);
    assert_eq!(stats.denied_no_attribution, 0);
    assert_eq!(stats.egress_errors, 0);
    assert_eq!(ingress.classifier().calls, 0, "超时不得进入分类器");
}

#[test]
fn malformed_packet_is_dropped_before_classification() {
    let mut ingress = Ingress::new(
        FakeSource::with([vec![0xff; 7]]),
        FakeClassifier::new([Decision::Hit("never")]),
        RecordingSink::default(),
    );

    assert!(matches!(step(&mut ingress), Step::Malformed(_)));
    let stats = ingress.stats();
    assert_eq!(stats.received, 1);
    assert_eq!(stats.malformed, 1);
    assert_eq!(stats.delivered, 0);
    assert_eq!(stats.denied_no_attribution, 0);
    assert_eq!(ingress.classifier().calls, 0, "解析失败不得进入分类器");
    assert!(ingress.sink().delivered.is_empty());
}

#[test]
fn device_error_is_terminal_and_counted() {
    let mut ingress = Ingress::new(
        FakeSource::failing("设备已移除"),
        FakeClassifier::new(Vec::new()),
        RecordingSink::default(),
    );

    let outcome = step(&mut ingress);
    let Step::DeviceFailed { detail } = outcome else {
        panic!("设备错误必须显式返回，实际 {outcome:?}");
    };
    assert_eq!(detail, "设备已移除");
    assert_eq!(ingress.stats().device_errors, 1);

    // 新开一个会持续报错的设备：事件循环必须立即以 DeviceFailed 停止。
    let mut failing = Ingress::new(
        FakeSource::failing("设备已移除"),
        FakeClassifier::new(Vec::new()),
        RecordingSink::default(),
    );
    let limits = IngressLimits {
        timeout: Duration::from_millis(1),
        max_packets: 100,
        max_steps: 100,
    };
    let run = failing.run(limits);
    assert_eq!(
        run.stopped,
        StopReason::DeviceFailed {
            detail: "设备已移除".to_string()
        }
    );
    assert_eq!(run.stats.device_errors, 1);
}

#[test]
fn run_respects_packet_and_step_budgets() {
    let mut ingress = Ingress::new(
        FakeSource::with([valid_packet(), valid_packet()]),
        FakeClassifier::new([Decision::Hit("env-a"), Decision::Hit("env-a")]),
        RecordingSink::default(),
    );
    let run = ingress.run(IngressLimits {
        timeout: Duration::from_millis(1),
        max_packets: 1,
        max_steps: 10,
    });
    assert_eq!(run.stopped, StopReason::PacketBudget);
    assert_eq!(run.stats.received, 1);
    assert_eq!(run.stats.delivered, 1);

    let mut idle = Ingress::new(
        FakeSource::with(Vec::new()),
        FakeClassifier::new(Vec::new()),
        RecordingSink::default(),
    );
    let run = idle.run(IngressLimits {
        timeout: Duration::from_millis(1),
        max_packets: 10,
        max_steps: 3,
    });
    assert_eq!(run.stopped, StopReason::StepBudget);
    assert_eq!(run.stats.receive_timeouts, 3);
    assert_eq!(run.stats.device_errors, 0);
}

#[test]
fn denial_reasons_stay_enumerable_across_a_mixed_run() {
    let mut ingress = Ingress::new(
        FakeSource::with([valid_packet(), valid_packet(), valid_packet()]),
        FakeClassifier::new([
            Decision::Miss,
            Decision::Fail("分类器拒绝"),
            Decision::Hit("env-c"),
        ]),
        RecordingSink::default(),
    );
    let run = ingress.run(IngressLimits {
        timeout: Duration::from_millis(1),
        max_packets: 3,
        max_steps: 10,
    });

    assert_eq!(run.stopped, StopReason::PacketBudget);
    assert_eq!(run.stats.received, 3);
    assert_eq!(run.stats.delivered, 1);
    assert_eq!(run.stats.denied_no_attribution, 2);
    assert_eq!(run.stats.denied(DenyReason::NoAttribution), 1);
    assert_eq!(run.stats.denied(DenyReason::ClassifierError), 1);
    assert_eq!(run.stats.denied_by_reason.len(), 2);
    assert_eq!(run.stats.egress_errors, 0);
    assert_eq!(run.stats.malformed, 0);
}
