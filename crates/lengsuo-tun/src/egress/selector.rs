//! 出口选择层：把「已归因的包」映射到「一条具体的协议出口」。

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::packet::PacketInfo;
use crate::session::{Clock, SessionKey, SessionTable};
use crate::tcp::connector::RouteTable;

use super::authority::{Attribution, AuthorityError, BindingAuthority, BindingId, DeviceId, Lease};
use super::runtime::{OutboundProtocol, OutboundRuntime, OutboundSession, RuntimeError};

/// 已选中的出口句柄：协议出口 + 出接口 + 命中的绑定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressHandle {
    /// 命中的绑定（审计用）。
    pub binding: BindingId,
    /// 选中的协议出口。
    pub protocol: OutboundProtocol,
    /// 出接口索引：由路由表选定（路由层职责，本模块不重做路由表）。
    pub interface_index: u32,
    /// 出接口的源地址。
    pub source: IpAddr,
    /// 运行时会话句柄。
    pub session: OutboundSession,
}

/// 拒绝原因。全部为拒绝，**不存在「未命中就直连」的第三种结果**。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DenyReason {
    /// 归因不到环境。
    NoAttribution,
    /// 环境没有出口绑定。
    UnknownEnvironment,
    /// 绑定的出口设备离线。
    DeviceOffline,
    /// 归因的设备/代次落后于当前权威绑定。
    StaleAttribution,
    /// 会话持有的租约不再有效。
    StaleLease,
    /// 该设备配置的协议出口不可用（不静默换协议）。
    ProtocolUnavailable,
    /// 查不到出接口。
    NoRoute,
    /// 会话表已满。
    Capacity,
    /// 出口建连失败。
    DialFailed,
    /// 出口转发失败。
    ForwardFailed,
}

impl DenyReason {
    /// 固定的短标签，便于日志与指标输出。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoAttribution => "no-attribution",
            Self::UnknownEnvironment => "unknown-environment",
            Self::DeviceOffline => "device-offline",
            Self::StaleAttribution => "stale-attribution",
            Self::StaleLease => "stale-lease",
            Self::ProtocolUnavailable => "protocol-unavailable",
            Self::NoRoute => "no-route",
            Self::Capacity => "capacity",
            Self::DialFailed => "dial-failed",
            Self::ForwardFailed => "forward-failed",
        }
    }
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 选中出口的理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionReason {
    /// 本次新建了出口会话。
    Selected,
    /// 复用了同一会话键已有的出口（未重复建连）。
    Reused,
}

/// 一次出口选择的结论。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDecision {
    /// 选中了一条出口。
    Selected {
        handle: EgressHandle,
        reason: SelectionReason,
    },
    /// 拒绝：给出原因与（若有）命中的绑定 id。
    Denied {
        reason: DenyReason,
        binding: Option<BindingId>,
        detail: Option<String>,
    },
}

impl EgressDecision {
    /// 拒绝时的原因；选中时为 `None`。
    #[must_use]
    pub fn deny_reason(&self) -> Option<DenyReason> {
        match self {
            Self::Denied { reason, .. } => Some(*reason),
            Self::Selected { .. } => None,
        }
    }

    /// 选中时的句柄；拒绝时为 `None`。
    #[must_use]
    pub fn handle(&self) -> Option<EgressHandle> {
        match self {
            Self::Selected { handle, .. } => Some(*handle),
            Self::Denied { .. } => None,
        }
    }
}

/// 出口投递失败：决策层拒绝或运行时转发失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("出口拒绝：{reason}")]
pub struct EgressError {
    pub reason: DenyReason,
    /// 命中的绑定 id（若有）；只含环境/设备/代次。
    pub binding: Option<BindingId>,
    /// 失败详情；由本模块生成时**不含**口令、密钥或完整配置。
    pub detail: Option<String>,
}

/// 会话表里保存的出口条目：句柄 + 建连时的租约（供后续复用时校验）。
///
/// `device` 单独记录而不再从 `handle.binding` 反推：设备失效时要在**不解析
/// 绑定**的前提下扫表，字段直接可比。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionEntry {
    handle: EgressHandle,
    lease: Lease,
    device: DeviceId,
}

/// 出口选择层：把「已归因的包」映射到「一条具体的协议出口」。
///
/// 纯内存、无 IO、无系统调用；时钟由调用方传入，因此过期行为完全确定。
pub struct EgressSelector<A, R> {
    authority: A,
    runtime: R,
    routes: RouteTable,
    sessions: SessionTable<SessionEntry>,
}

impl<A, R> EgressSelector<A, R>
where
    A: BindingAuthority,
    R: OutboundRuntime,
{
    /// 组装选择层：权威来源、出口运行时、出接口路由表、会话容量与 TTL。
    pub fn new(authority: A, runtime: R, routes: RouteTable, capacity: usize, ttl: Clock) -> Self {
        Self {
            authority,
            runtime,
            routes,
            sessions: SessionTable::new(capacity, ttl),
        }
    }

    /// 只读权威来源。
    #[must_use]
    pub fn authority(&self) -> &A {
        &self.authority
    }

    /// 可变权威来源：上层据此上报设备在线状态与绑定变更。
    pub fn authority_mut(&mut self) -> &mut A {
        &mut self.authority
    }

    /// 只读出口运行时。
    #[must_use]
    pub fn runtime(&self) -> &R {
        &self.runtime
    }

    /// 可变出口运行时：上层据此上报协议出口的可用性变化。
    pub fn runtime_mut(&mut self) -> &mut R {
        &mut self.runtime
    }

    /// 只读出接口路由表。
    #[must_use]
    pub fn routes(&self) -> &RouteTable {
        &self.routes
    }

    /// 当前持有的出口会话数（诊断「是否泄漏」用）。
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// 为一条已归因的包选择出口。
    ///
    /// 顺序：复用（校验旧租约）→ 出接口查表 → 权威租约解析 → 代次核对 →
    /// 协议出口可用性 → 建连 → 登记会话。任一步不满足即拒绝并给出原因。
    pub fn select(
        &mut self,
        info: &PacketInfo,
        key: SessionKey,
        attribution: Attribution,
        now: Clock,
    ) -> EgressDecision {
        // ① 复用：同一会话键已有出口时，先确认它持有的租约仍然有效。
        if let Some(entry) = self.sessions.get(key, now) {
            let entry = *entry;
            if let Err(error) = self.authority.validate(entry.lease) {
                return denied(
                    authority_reason(&error),
                    Some(entry.handle.binding),
                    Some(error.to_string()),
                );
            }
            return EgressDecision::Selected {
                handle: entry.handle,
                reason: SelectionReason::Reused,
            };
        }

        // ② 出接口由路由层选定（最长前缀匹配）；查不到即拒绝，不走默认路由。
        let Some(route) = self.routes.lookup(info.destination) else {
            return denied(DenyReason::NoRoute, None, None);
        };
        let (interface_index, source) = (route.interface_index, route.source);

        // ③ 权威租约：环境无绑定或设备离线 ⇒ 拒绝。
        let lease = match self.authority.resolve(attribution.environment) {
            Ok(lease) => lease,
            Err(error) => {
                return denied(authority_reason(&error), None, Some(error.to_string()));
            }
        };
        let binding = BindingId {
            environment: lease.environment,
            device: lease.device,
            epoch: lease.epoch,
        };

        // ④ 归因的设备与代次必须与权威绑定一致（换绑过的旧归因一律拒绝）。
        if lease.device != attribution.device || lease.epoch != attribution.epoch {
            return denied(DenyReason::StaleAttribution, Some(binding), None);
        }

        // ⑤ 协议出口：该设备配置哪个协议就走哪个；不可用即拒绝，不换协议。
        let Some(protocol) = self.runtime.protocol_of(lease.device) else {
            return denied(DenyReason::ProtocolUnavailable, Some(binding), None);
        };
        if !self.runtime.is_available(lease.device, protocol) {
            return denied(DenyReason::ProtocolUnavailable, Some(binding), None);
        }

        // ⑥ 建连并登记会话；表满则释放刚建的出口（不泄漏）。
        let target = SocketAddr::new(info.destination, info.destination_port);
        let session = match self.runtime.open(lease.device, protocol, target) {
            Ok(session) => session,
            Err(error) => {
                return denied(
                    DenyReason::DialFailed,
                    Some(binding),
                    Some(error.to_string()),
                );
            }
        };
        let handle = EgressHandle {
            binding,
            protocol,
            interface_index,
            source,
            session,
        };
        let entry = SessionEntry {
            handle,
            lease,
            device: lease.device,
        };
        match self.sessions.open(key, entry, now) {
            Ok(_) => EgressDecision::Selected {
                handle,
                reason: SelectionReason::Selected,
            },
            Err(error) => {
                let entry = error.into_value();
                self.runtime.release(entry.handle.session);
                denied(DenyReason::Capacity, Some(entry.handle.binding), None)
            }
        }
    }

    /// 把报文交给已选中的出口会话。
    pub fn forward(&mut self, handle: &EgressHandle, packet: &[u8]) -> Result<(), RuntimeError> {
        self.runtime.forward(handle.session, packet)
    }

    /// 关闭会话并释放其出口，返回被释放的句柄。
    pub fn close(&mut self, key: SessionKey) -> Option<EgressHandle> {
        let entry = self.sessions.close(key)?;
        self.runtime.release(entry.handle.session);
        Some(entry.handle)
    }

    /// 设备断开：立即移出该设备的全部会话并逐条释放出口，返回释放数量。
    ///
    /// 语义与 [`DenyReason::DeviceOffline`] 一致，全部 fail-closed：
    /// - **不等 TTL**：在途会话此刻就失效，不靠过期兜底；
    /// - **不静默换出口**：不重拨、不改协议；
    /// - **不直连**：新包由 `select` 依权威状态拒绝，由上层自行重连。
    ///
    /// 设备名下没有会话时返回 0，不 panic。
    pub fn invalidate_device(&mut self, device: DeviceId) -> usize {
        let drained = self.sessions.drain_where(|_, entry| entry.device == device);
        for (_, entry) in &drained {
            self.runtime.release(entry.handle.session);
        }
        drained.len()
    }

    /// 回收已过期会话并释放其出口，返回释放数量。
    pub fn gc(&mut self, now: Clock) -> usize {
        let expired = self.sessions.gc(now);
        for entry in &expired {
            self.runtime.release(entry.handle.session);
        }
        expired.len()
    }
}

/// 构造一条拒绝结论。
fn denied(
    reason: DenyReason,
    binding: Option<BindingId>,
    detail: Option<String>,
) -> EgressDecision {
    EgressDecision::Denied {
        reason,
        binding,
        detail,
    }
}

/// 把权威来源的拒绝原因映射为出口层的拒绝原因。
fn authority_reason(error: &AuthorityError) -> DenyReason {
    match error {
        AuthorityError::UnknownEnvironment(_) => DenyReason::UnknownEnvironment,
        AuthorityError::DeviceOffline(_) => DenyReason::DeviceOffline,
        AuthorityError::StaleLease => DenyReason::StaleLease,
        AuthorityError::Rejected => DenyReason::UnknownEnvironment,
    }
}
