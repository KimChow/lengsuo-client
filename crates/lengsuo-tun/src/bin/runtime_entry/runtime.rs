//! 事件循环、统计与可观测点。
//!
//! 一步（[`Runtime::step`]）的处理链严格照 Xray `proxy/tun/handler.go` 的
//! `HandleConnection` + `app/dispatcher/default.go` 的 `DispatchLink` 对应：
//!
//! ```text
//! 设备收包 ──► checksum::verify ──► ingress::Classifier 归因
//!                                        │
//!                                        ▼
//!                          egress::EgressSelector 选出口（路由表 + 权威租约）
//!                                        │
//!                                        ▼
//!                        tcp::listener::TcpListener 用户态 TCP 栈
//!                                        │
//!                                        ▼
//!                                  写回设备
//! ```
//!
//! 所有拒绝路径都 fail-closed：校验失败、无归属、查不到出接口、租约失效、
//! 协议出口不可用——一律**丢弃**，绝不「未命中就直连」。
//!
//! 本模块**不重写**上述任何一块：全部复用既有模块，本文件只做接线与计数。

use std::collections::BTreeMap;
use std::time::Duration;

use lengsuo_tun::egress::{
    Attribution, BindingAuthority, DenyReason, EgressDecision, EgressSelector, OutboundRuntime,
    OutboundSession,
};
use lengsuo_tun::ingress::{Classifier, PacketSource, Receipt};
use lengsuo_tun::session::{Clock, SessionKey};
use lengsuo_tun::tcp::listener::TcpListener;

use super::device::{DeviceError, TunDevice};

/// 出口运行时需要额外提供的「回程字节」取回能力。
///
/// `egress::OutboundRuntime` 只覆盖去程（建连、转发）；回程字节（对端发来的应用
/// 数据）由本 trait 单独承载。真实实现接节点/出口的读端；测试用内存替身。
pub trait OutboundExchange {
    /// 取回某个会话已就绪的回程字节；没有就绪数据时返回 `None`。
    fn take_response(&mut self, session: OutboundSession) -> Option<Vec<u8>>;
}

/// 事件循环的预算。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    /// 收到这么多报文后停止（0 表示不限）。
    pub max_packets: u64,
    /// 最多执行这么多步（0 表示不限）。防止持续超时时死循环。
    pub max_steps: u64,
}

/// 单步处理结果。每一步都能被调用方观测，不需要解析日志。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// 超时窗口内没有报文：正常空闲。
    Idle,
    /// 报文校验失败，已丢弃（未进归因器）。
    Malformed { detail: String },
    /// 无归属或分类失败，已丢弃。
    Denied {
        reason: DenyReason,
        detail: Option<String>,
    },
    /// 已处理。`written` 是写回设备的报文数，`delivered` 是交给出口的载荷字节数。
    Forwarded { written: usize, delivered: usize },
    /// 设备层面错误；事件循环应以 [`StopReason::DeviceFailed`] 停止。
    DeviceFailed { detail: String },
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

/// 统计快照。全部可观测点都不需要解析日志。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeStats {
    /// 从设备收到的报文数。
    pub received: u64,
    /// 写回设备的报文数。
    pub written: u64,
    /// 交给出口运行时的应用载荷字节数。
    pub delivered: u64,
    /// 被拒绝的报文数（无归属 + 出口层拒绝）。
    pub denied: u64,
    /// 校验失败的报文数。
    pub malformed: u64,
    /// 出口转发失败的次数。
    pub egress_errors: u64,
    /// 设备收包超时次数（正常空闲，不计入错误）。
    pub timeouts: u64,
    /// 设备层面错误次数。
    pub device_errors: u64,
    /// 当前活跃连接数（用户态 TCP 栈的会话数）。
    pub active_connections: u64,
}

/// 运行结果：统计快照 + 停止原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    /// 统计快照。
    pub stats: RuntimeStats,
    /// 停止原因。
    pub stopped: StopReason,
}

/// TUN 运行时：把设备、归因器、出口选择器与用户态 TCP 栈接成一条链。
pub struct Runtime<D, C, A, R>
where
    D: PacketSource<Error = DeviceError> + TunDevice,
    C: Classifier<Attribution = Attribution>,
    A: BindingAuthority,
    R: OutboundRuntime + OutboundExchange,
{
    device: D,
    classifier: C,
    selector: EgressSelector<A, R>,
    listener: TcpListener,
    /// 出口会话句柄 → 入站会话键。回程字节要送回**对应的** TCP 会话，
    /// `egress::EgressSelector` 没有暴露会话表内容，故由本层记账。
    outbound_keys: BTreeMap<u64, SessionKey>,
    stats: RuntimeStats,
}

impl<D, C, A, R> Runtime<D, C, A, R>
where
    D: PacketSource<Error = DeviceError> + TunDevice,
    C: Classifier<Attribution = Attribution>,
    A: BindingAuthority,
    R: OutboundRuntime + OutboundExchange,
{
    /// 组装接线。不启动任何后台任务，也不读取系统状态。
    pub fn new(
        device: D,
        classifier: C,
        selector: EgressSelector<A, R>,
        listener: TcpListener,
    ) -> Self {
        Self {
            device,
            classifier,
            selector,
            listener,
            outbound_keys: BTreeMap::new(),
            stats: RuntimeStats::default(),
        }
    }

    /// 只读统计快照。
    #[must_use]
    pub fn stats(&self) -> &RuntimeStats {
        &self.stats
    }

    /// 只读设备，便于调用方观察写回的报文。
    #[must_use]
    pub fn device(&self) -> &D {
        &self.device
    }

    /// 只读出口选择器。
    #[must_use]
    pub fn selector(&self) -> &EgressSelector<A, R> {
        &self.selector
    }

    /// 可变出口选择器。
    pub fn selector_mut(&mut self) -> &mut EgressSelector<A, R> {
        &mut self.selector
    }

    /// 当前活跃连接数。
    #[must_use]
    pub fn active_connections(&self) -> u64 {
        self.listener.session_count() as u64
    }

    /// 处理一步：收一个包（或超时），完成校验、归因、选出口、TCP 栈处理与写回。
    ///
    /// 本方法不 panic；所有失败都以 [`Step`] 返回。设备错误是**终止性**的。
    pub fn step(&mut self, timeout: Duration, now: Clock) -> Step {
        let step = self.step_inner(timeout, now);
        // 活跃连接数在每一步之后刷新：会话可能在本步内建立或释放。
        self.stats.active_connections = self.active_connections();
        step
    }

    /// 一步的实质处理。
    fn step_inner(&mut self, timeout: Duration, now: Clock) -> Step {
        let packet = match self.device.receive(timeout) {
            Ok(Receipt::Packet(packet)) => packet,
            Ok(Receipt::Timeout) => {
                self.stats.timeouts += 1;
                // 空闲时也把出口侧已就绪的回程字节取回写回（回程闭环）。
                self.pump_response(now);
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

        // ① 校验：`checksum::verify` 内部先 `packet::inspect`，两者都 fail-closed。
        let info = match lengsuo_tun::checksum::verify(&packet) {
            Ok(info) => info,
            Err(error) => {
                self.stats.malformed += 1;
                return Step::Malformed {
                    detail: error.to_string(),
                };
            }
        };

        // ② 归因：无归属或分类失败一律丢弃，**不回落直连**。
        let attribution = match self.classifier.classify(&info) {
            Ok(Some(attribution)) => attribution,
            Ok(None) => {
                self.stats.denied += 1;
                return Step::Denied {
                    reason: DenyReason::NoAttribution,
                    detail: None,
                };
            }
            Err(error) => {
                let detail = error.to_string();
                self.stats.denied += 1;
                return Step::Denied {
                    reason: DenyReason::NoAttribution,
                    detail: Some(detail),
                };
            }
        };

        // ③ 选出口：路由表 + 权威租约 + 协议可用性，任一不满足即拒绝。
        let key = SessionKey::from_info(info);
        let decision = self.selector.select(&info, key, attribution, now);
        let handle = match decision {
            EgressDecision::Selected { handle, .. } => handle,
            EgressDecision::Denied { reason, detail, .. } => {
                self.stats.denied += 1;
                return Step::Denied { reason, detail };
            }
        };
        self.outbound_keys.insert(handle.session.0, key);

        // ④ 用户态 TCP 栈：处理报文、产出回包与交付载荷。
        let feed = match self.listener.feed(&packet, now) {
            Ok(feed) => feed,
            Err(error) => {
                // 校验已在 ① 做过，这里失败说明解析层与栈层口径不一致：丢弃，
                // 不写回半成品，也不建连。
                self.stats.malformed += 1;
                self.selector.close(key);
                return Step::Malformed {
                    detail: error.to_string(),
                };
            }
        };

        // ⑤ 应用载荷交给出口运行时（去程）。
        let mut delivered = 0usize;
        if !feed.delivered.is_empty() {
            match self.selector.forward(&handle, &feed.delivered) {
                Ok(()) => {
                    delivered = feed.delivered.len();
                    self.stats.delivered += delivered as u64;
                }
                Err(error) => {
                    self.stats.egress_errors += 1;
                    return Step::Denied {
                        reason: DenyReason::ForwardFailed,
                        detail: Some(error.to_string()),
                    };
                }
            }
        }

        // ⑥ 回包写回设备。
        let mut written = 0usize;
        for reply in &feed.replies {
            if let Err(error) = self.device.send(reply) {
                self.stats.device_errors += 1;
                return Step::DeviceFailed {
                    detail: error.to_string(),
                };
            }
            written += 1;
            self.stats.written += 1;
        }
        Step::Forwarded { written, delivered }
    }

    /// 按预算运行事件循环，返回统计与停止原因。设备错误是终止性的。
    pub fn run(&mut self, timeout: Duration, limits: Limits, now: Clock) -> RunOutcome {
        let mut steps = 0u64;
        let stopped = loop {
            if limits.max_packets != 0 && self.stats.received >= limits.max_packets {
                break StopReason::PacketBudget;
            }
            if limits.max_steps != 0 && steps >= limits.max_steps {
                break StopReason::StepBudget;
            }
            steps += 1;
            if let Step::DeviceFailed { detail } = self.step(timeout, now) {
                break StopReason::DeviceFailed { detail };
            }
        };
        RunOutcome {
            stats: self.stats.clone(),
            stopped,
        }
    }

    /// 取回出口侧已就绪的回程字节并写回设备。
    ///
    /// 回程按**出口会话**逐个取；取到就编成一个 TCP 数据段写回（本端 → 对端）。
    /// 没有对应 TCP 会话的会话不写回（无处可送），也不静默丢弃计数以外的痕迹。
    fn pump_response(&mut self, now: Clock) {
        let mut pending: Vec<(SessionKey, Vec<u8>)> = Vec::new();
        for (session, key) in &self.outbound_keys {
            let handle = OutboundSession(*session);
            if let Some(bytes) = self.selector.runtime_mut().take_response(handle) {
                pending.push((*key, bytes));
            }
        }
        for (key, bytes) in pending {
            for reply in self.listener.send(key, &bytes, now) {
                if self.device.send(&reply).is_ok() {
                    self.stats.written += 1;
                }
            }
        }
    }
}
