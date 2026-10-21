//! 事件循环与统计：设备收包 → 解析 → 分类 → 投递。

use std::collections::BTreeMap;
use std::time::Duration;

use crate::packet;

use super::traits::{Classifier, EgressSink, PacketSource, Receipt};

/// 报文被丢弃的原因，作为 [`IngressStats::denied_by_reason`] 的枚举键。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DenyReason {
    /// 分类器明确表示该五元组没有环境归属。
    NoAttribution,
    /// 分类器返回错误，无法判定归属。
    ClassifierError,
}

impl DenyReason {
    /// 固定的短标签，便于日志与指标输出。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoAttribution => "no-attribution",
            Self::ClassifierError => "classifier-error",
        }
    }
}

/// 单步处理结果。每一步都能被调用方观测，不需要解析日志。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// 超时窗口内没有报文。
    Idle,
    /// 解析失败，报文被丢弃。
    Malformed(packet::Error),
    /// 未归属或分类失败，报文被丢弃。
    Denied {
        reason: DenyReason,
        detail: Option<String>,
    },
    /// 已投递给出口。
    Delivered,
    /// 出口投递失败。
    EgressFailed { detail: String },
    /// 设备层面错误；事件循环应以 [`StopReason::DeviceFailed`] 停止。
    DeviceFailed { detail: String },
}

/// 计数与可读原因。字段按「收到 / 拒绝 / 投递 / 出口失败」四分，另附明细。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngressStats {
    /// 从设备成功收到的报文数（含随后被解析拒绝的）。
    pub received: u64,
    /// 未归属 + 分类失败的报文数。
    pub denied_no_attribution: u64,
    /// 成功投递给出口的报文数。
    pub delivered: u64,
    /// 出口投递失败的报文数。
    pub egress_errors: u64,
    /// 解析失败的报文数。
    pub malformed: u64,
    /// 设备收包超时次数（正常空闲，不计入错误）。
    pub receive_timeouts: u64,
    /// 设备层面错误次数。
    pub device_errors: u64,
    /// 按原因枚举的拒绝分布；只包含出现过的原因。
    pub denied_by_reason: BTreeMap<DenyReason, u64>,
    /// 最近一次分类失败的详情（若有）。
    pub last_deny_detail: Option<String>,
    /// 最近一次出口失败的详情（若有）。
    pub last_egress_detail: Option<String>,
}

impl IngressStats {
    /// 某类拒绝的次数，未出现时为 0。
    #[must_use]
    pub fn denied(&self, reason: DenyReason) -> u64 {
        self.denied_by_reason.get(&reason).copied().unwrap_or(0)
    }

    fn record_denial(&mut self, reason: DenyReason, detail: Option<String>) {
        self.denied_no_attribution += 1;
        *self.denied_by_reason.entry(reason).or_insert(0) += 1;
        self.last_deny_detail = detail;
    }
}

/// 事件循环的停止条件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressLimits {
    /// 单次收包等待上限。
    pub timeout: Duration,
    /// 收到这么多报文后停止。
    pub max_packets: u64,
    /// 最多执行这么多步（防止持续超时时死循环）；0 表示不执行。
    pub max_steps: u64,
}

impl Default for IngressLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(10),
            max_packets: 64,
            max_steps: 1_000,
        }
    }
}

/// 事件循环停止原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// 达到报文预算。
    PacketBudget,
    /// 达到步数预算。
    StepBudget,
    /// 设备报错，循环终止。
    DeviceFailed { detail: String },
}

/// 运行结果：统计快照 + 停止原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    pub stats: IngressStats,
    pub stopped: StopReason,
}

/// 设备 → 分类 → 出口的最小运行时。
#[derive(Debug)]
pub struct Ingress<D, C, E> {
    source: D,
    classifier: C,
    sink: E,
    stats: IngressStats,
}

impl<D, C, E> Ingress<D, C, E>
where
    D: PacketSource,
    C: Classifier,
    E: EgressSink<C::Attribution>,
{
    /// 组装接线。不启动任何后台任务，也不读取系统状态。
    pub fn new(source: D, classifier: C, sink: E) -> Self {
        Self {
            source,
            classifier,
            sink,
            stats: IngressStats::default(),
        }
    }

    /// 只读统计快照。
    #[must_use]
    pub fn stats(&self) -> &IngressStats {
        &self.stats
    }

    /// 只读设备来源，便于调用方取回注入的假设备或查询设备状态。
    #[must_use]
    pub fn source(&self) -> &D {
        &self.source
    }

    /// 只读分类器，便于调用方取回注入的假分类器或检查其观察记录。
    #[must_use]
    pub fn classifier(&self) -> &C {
        &self.classifier
    }

    /// 只读出口，便于调用方取回注入的假出口或检查投递记录。
    #[must_use]
    pub fn sink(&self) -> &E {
        &self.sink
    }

    /// 处理一步：收一个包（或超时），并完成解析、分类、投递与计数。
    ///
    /// 本方法不 panic；所有失败都以 [`Step`] 返回。
    pub fn step(&mut self, timeout: Duration) -> Step {
        let packet = match self.source.receive(timeout) {
            Ok(Receipt::Packet(packet)) => packet,
            Ok(Receipt::Timeout) => {
                self.stats.receive_timeouts += 1;
                return Step::Idle;
            }
            Err(error) => {
                self.stats.device_errors += 1;
                return Step::DeviceFailed {
                    detail: error.to_string(),
                };
            }
        };
        self.stats.received += 1;

        let info = match packet::inspect(&packet) {
            Ok(info) => info,
            Err(error) => {
                self.stats.malformed += 1;
                return Step::Malformed(error);
            }
        };

        let attribution = match self.classifier.classify(&info) {
            Ok(Some(attribution)) => attribution,
            Ok(None) => {
                self.stats.record_denial(DenyReason::NoAttribution, None);
                return Step::Denied {
                    reason: DenyReason::NoAttribution,
                    detail: None,
                };
            }
            Err(error) => {
                let detail = error.to_string();
                self.stats
                    .record_denial(DenyReason::ClassifierError, Some(detail.clone()));
                return Step::Denied {
                    reason: DenyReason::ClassifierError,
                    detail: Some(detail),
                };
            }
        };

        match self.sink.deliver(&packet, &info, attribution) {
            Ok(()) => {
                self.stats.delivered += 1;
                Step::Delivered
            }
            Err(error) => {
                let detail = error.to_string();
                self.stats.egress_errors += 1;
                self.stats.last_egress_detail = Some(detail.clone());
                Step::EgressFailed { detail }
            }
        }
    }

    /// 按预算运行事件循环，返回统计与停止原因。设备错误是终止性的。
    pub fn run(&mut self, limits: IngressLimits) -> RunOutcome {
        let mut steps = 0;
        let stopped = loop {
            if self.stats.received >= limits.max_packets {
                break StopReason::PacketBudget;
            }
            if steps >= limits.max_steps {
                break StopReason::StepBudget;
            }
            steps += 1;
            if let Step::DeviceFailed { detail } = self.step(limits.timeout) {
                break StopReason::DeviceFailed { detail };
            }
        };
        RunOutcome {
            stats: self.stats.clone(),
            stopped,
        }
    }
}
