//! 设备 → 分类 → 出口的最小接线与统计。
//!
//! 本模块**不做业务转发**：它只从设备收包、解析元数据、把元数据交给注入的
//! [`Classifier`]，命中后把原包与归属交给注入的 [`EgressSink`]。真正的分类策略
//! （`lengsuo-environment::classify`）与出口拨号都不在本 crate 内，也不由本模块
//! 复制；本模块只依赖两个 trait，因此不引入对 `lengsuo-environment` 的运行时依赖。
//!
//! 安全语义（全部 fail-closed）：
//! - 分类器返回 `Ok(None)`（无归属）或 `Err`（分类失败）时，报文**一律丢弃**，
//!   分别计入 [`DenyReason::NoAttribution`] 与 [`DenyReason::ClassifierError`]；
//!   两者都汇总进 [`IngressStats::denied_no_attribution`]。不存在「未命中就直连」。
//! - 解析失败（[`crate::packet::inspect`]）的报文单独计入
//!   [`IngressStats::malformed`]，不进入分类器。
//! - 出口投递失败计入 [`IngressStats::egress_errors`]，与「未归属」分开可读。
//! - 设备收包超时是正常空闲，计入 [`IngressStats::receive_timeouts`]，不算错误。
//! - 所有拒绝原因以枚举键存放于 [`IngressStats::denied_by_reason`]，调用方无需
//!   解析日志即可读出分布。

use std::collections::BTreeMap;
use std::fmt::Display;
use std::time::Duration;

use crate::egress::{
    Attribution, BindingAuthority, EgressDecision, EgressError, EgressSelector, OutboundRuntime,
};
use crate::packet::{self, PacketInfo};
use crate::session::{Clock, SessionKey};

/// 一次设备收包的结果。把「超时」与「错误」显式分开，避免按错误文本猜语义。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Receipt {
    /// 收到一个完整 IP 报文。
    Packet(Vec<u8>),
    /// 在超时窗口内没有报文，属于正常空闲。
    Timeout,
}

/// 设备收包来源。生产实现见 [`crate::device::Device`]（Windows）。
pub trait PacketSource {
    /// 收包失败的类型；必须可读，便于统计与排障。
    type Error: Display;

    /// 在 `timeout` 内尝试收一个报文。超时必须返回 [`Receipt::Timeout`]。
    fn receive(&mut self, timeout: Duration) -> Result<Receipt, Self::Error>;
}

/// 五元组分类器。实现方负责把环境归属策略（例如 `lengsuo-environment`）接进来。
///
/// 返回 `Ok(None)` 表示「没有归属」，`Err` 表示分类过程失败；两者都会被丢弃，
/// 但按不同原因计数。
pub trait Classifier {
    /// 归属标识。本模块不解释其内容，只原样交给出口。
    type Attribution;
    /// 分类失败的错误类型。
    type Error: Display;

    /// 对已解析的报文元数据给出归属。
    fn classify(&mut self, info: &PacketInfo) -> Result<Option<Self::Attribution>, Self::Error>;
}

/// 出口投递端。实现方负责实际转发，本模块只做投递与计数。
pub trait EgressSink<A> {
    /// 投递失败的错误类型。
    type Error: Display;

    /// 投递原包、元数据与归属。失败表示本包未被送出。
    fn deliver(
        &mut self,
        packet: &[u8],
        info: &PacketInfo,
        attribution: A,
    ) -> Result<(), Self::Error>;
}

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

/// Windows 上真实设备的收包适配：把设备的类型化超时映射为 [`Receipt::Timeout`]。
///
/// 其他平台没有 `device::Device`，真实接线由宿主在有设备实现的平台上完成。
#[cfg(windows)]
impl PacketSource for crate::device::Device {
    type Error = crate::device::Error;

    fn receive(&mut self, timeout: Duration) -> Result<Receipt, Self::Error> {
        match crate::device::Device::receive(self, timeout) {
            Ok(packet) => Ok(Receipt::Packet(packet)),
            Err(crate::device::Error::Timeout { .. }) => Ok(Receipt::Timeout),
            Err(error) => Err(error),
        }
    }
}

/// 接线层：把 [`crate::egress::EgressSelector`] 实现成 [`EgressSink`]，供
/// `Ingress<D, C, E>` 直接使用——**不重写** ingress 的事件循环。
///
/// 归因由分类器给出（[`Attribution`]）；本 sink 只做「选出口 →
/// 交给运行时」。时钟由注入的闭包提供：测试可给固定值，生产可接系统单调时钟。
///
/// 与路由层的分工：`crate::tcp::connector::route` 选的是**出接口**（网卡），
/// 本模块选的是**协议出口**（trojan/anytls/… 的哪一条）。两者不重叠。
pub struct SelectorSink<A, R> {
    selector: EgressSelector<A, R>,
    now: Box<dyn FnMut() -> Clock>,
}

impl<A, R> std::fmt::Debug for SelectorSink<A, R>
where
    A: BindingAuthority,
    R: OutboundRuntime,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectorSink")
            .field("session_count", &self.selector.session_count())
            .finish_non_exhaustive()
    }
}

impl<A, R> SelectorSink<A, R>
where
    A: BindingAuthority,
    R: OutboundRuntime,
{
    /// 组装 sink：选择器 + 时钟来源。
    pub fn new(selector: EgressSelector<A, R>, now: impl FnMut() -> Clock + 'static) -> Self {
        Self {
            selector,
            now: Box::new(now),
        }
    }

    /// 只读选择器，便于调用方观察会话数与运行时状态。
    #[must_use]
    pub fn selector(&self) -> &EgressSelector<A, R> {
        &self.selector
    }

    /// 可变选择器，便于调用方在会话结束时显式关闭出口。
    pub fn selector_mut(&mut self) -> &mut EgressSelector<A, R> {
        &mut self.selector
    }
}

impl<A, R> EgressSink<Attribution> for SelectorSink<A, R>
where
    A: BindingAuthority,
    R: OutboundRuntime,
{
    type Error = EgressError;

    /// 选出出口并把原包交给它；选不出出口即拒绝（**不回落直连**）。
    fn deliver(
        &mut self,
        packet: &[u8],
        info: &PacketInfo,
        attribution: Attribution,
    ) -> Result<(), Self::Error> {
        let key = SessionKey::from_info(*info);
        let now = (self.now)();
        let decision = self.selector.select(info, key, attribution, now);
        let handle = match decision {
            EgressDecision::Denied {
                reason,
                binding,
                detail,
            } => {
                return Err(EgressError {
                    reason,
                    binding,
                    detail,
                });
            }
            EgressDecision::Selected { handle, .. } => handle,
        };
        self.selector
            .forward(&handle, packet)
            .map_err(|error| EgressError {
                reason: crate::egress::DenyReason::ForwardFailed,
                binding: Some(handle.binding),
                detail: Some(error.to_string()),
            })
    }
}
