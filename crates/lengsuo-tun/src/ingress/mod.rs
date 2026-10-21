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

mod pipeline;
mod selector_sink;
mod traits;

pub use pipeline::{
    DenyReason, Ingress, IngressLimits, IngressStats, RunOutcome, Step, StopReason,
};
pub use selector_sink::SelectorSink;
pub use traits::{Classifier, EgressSink, PacketSource, Receipt};
