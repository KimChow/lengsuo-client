//! 接线层：把 [`crate::egress::EgressSelector`] 实现成 [`EgressSink`]。

use crate::egress::{
    Attribution, BindingAuthority, EgressDecision, EgressError, EgressSelector, OutboundRuntime,
};
use crate::packet::PacketInfo;
use crate::session::{Clock, SessionKey};

use super::traits::EgressSink;

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

/// Windows 上真实设备的收包适配：把设备的类型化超时映射为 [`Receipt::Timeout`]。
///
/// 其他平台没有 `device::Device`，真实接线由宿主在有设备实现的平台上完成。
#[cfg(windows)]
impl super::traits::PacketSource for crate::device::Device {
    type Error = crate::device::Error;

    fn receive(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<super::traits::Receipt, Self::Error> {
        match crate::device::Device::receive(self, timeout) {
            Ok(packet) => Ok(super::traits::Receipt::Packet(packet)),
            Err(crate::device::Error::Timeout { .. }) => Ok(super::traits::Receipt::Timeout),
            Err(error) => Err(error),
        }
    }
}
