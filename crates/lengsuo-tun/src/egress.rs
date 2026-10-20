//! 出口方向接线：包 → 环境归因 → 选协议出口 → 交给出口运行时。
//!
//! 本模块**不碰真实网卡、不自己拨号**：它只做决策层——把「已归因的包」映射到
//! 「一条具体的协议出口」，并把决策过程变成可审计的结构（`reason` 枚举 + 命中的
//! 绑定 id）。真实协议栈的建连由注入的 [`OutboundRuntime`] 承担。
//!
//! ## 依赖方向（重要，已实测）
//!
//! `lengsuo-environment` **依赖**本 crate（它复用 [`crate::packet::PacketInfo`]），
//! 因此本 crate 若反向依赖它会构成 **cargo 依赖环**、cargo 直接拒绝构建（本卡已
//! 用最小复现工程实测复现）。本模块因此只定义两个 trait（[`BindingAuthority`] /
//! [`OutboundRuntime`]）并由上层注入实现；真实 `lengsuo_environment::Router` 的
//! 适配见 `tests/egress_wiring.rs`。
//!
//! ## 安全语义（全部 fail-closed，**没有第三种「直连」出口**）
//!
//! - 归因不到环境 ⇒ [`DenyReason::NoAttribution`]，**不回落默认直连**。
//! - 环境无绑定 ⇒ [`DenyReason::UnknownEnvironment`]。
//! - 绑定设备离线 ⇒ [`DenyReason::DeviceOffline`]。
//! - 归因的设备/代次落后于权威绑定 ⇒ [`DenyReason::StaleAttribution`]。
//! - 会话持有的租约不再有效（`validate` 失败）⇒ [`DenyReason::StaleLease`]。
//! - 该设备配置的协议出口不可用 ⇒ [`DenyReason::ProtocolUnavailable`]，
//!   **不静默改用别的协议**。
//! - 查不到出接口 ⇒ [`DenyReason::NoRoute`]（出接口由路由表选定）。
//! - 会话表满 ⇒ [`DenyReason::Capacity`]（不驱逐既有会话，且释放刚建的出口）。
//!
//! 决策结果与绑定 id 只含环境号、设备号、代次、协议名与出接口索引，**不含**口令、
//! 密钥或完整配置。
//!
//! ## 与既有路径的分工
//!
//! - `crate::tcp::connector::route` 选的是**出接口**（哪块网卡）；本模块选的是
//!   **协议出口**（trojan/anytls/… 的哪一条）。两者职责不重叠、不重复实现路由表。
//! - `crate::ingress` 的 `Ingress<D, C, E>` 是既有的三段式管道；本模块的
//!   [`EgressSelector`] 通过 `crate::ingress::SelectorSink` 接进它的 sink 侧，
//!   **不重写** ingress 的事件循环。

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::packet::PacketInfo;
use crate::session::{Clock, SessionKey, SessionTable};
use crate::tcp::connector::RouteTable;

/// 环境身份。与 `lengsuo-environment::EnvironmentId` 同构；本 crate 不反向依赖它。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvironmentId(pub u64);

/// 出口设备身份。与 `lengsuo-environment::DeviceId` 同构。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub u64);

/// 出口协议：与 `lengsuo-node` 的八协议出口一一对应。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OutboundProtocol {
    Trojan,
    AnyTls,
    Vless,
    Vmess,
    Shadowsocks,
    Ss2022,
    Hysteria,
    Wireguard,
}

impl OutboundProtocol {
    /// 稳定的短标签，供日志与指标输出（不含任何凭据）。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trojan => "trojan",
            Self::AnyTls => "anytls",
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Shadowsocks => "shadowsocks",
            Self::Ss2022 => "ss2022",
            Self::Hysteria => "hysteria",
            Self::Wireguard => "wireguard",
        }
    }
}

/// 权威租约：与 `lengsuo-environment::Lease` 同构（含路由器实例命名空间）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub instance: [u8; 16],
    pub environment: EnvironmentId,
    pub device: DeviceId,
    pub epoch: u64,
}

/// 分类器给出的环境归因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribution {
    pub environment: EnvironmentId,
    pub device: DeviceId,
    pub epoch: u64,
}

/// 权威绑定来源的拒绝原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    /// 该环境没有任何绑定。
    #[error("环境 {0:?} 没有出口绑定")]
    UnknownEnvironment(EnvironmentId),
    /// 环境已绑定，但承接它的设备离线。
    #[error("出口设备 {0:?} 离线")]
    DeviceOffline(DeviceId),
    /// 租约已失效（实例、设备或代次与当前权威状态不一致）。
    #[error("租约已失效")]
    StaleLease,
    /// 其它权威拒绝，原因不明时同样拒绝。
    #[error("权威状态拒绝")]
    Rejected,
}

/// 出口运行时的拒绝原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeError {
    #[error("该设备未配置出口协议")]
    NoProtocol,
    #[error("协议出口当前不可用")]
    Unavailable,
    #[error("出口建连失败")]
    Dial,
    #[error("出口转发失败")]
    Forward,
    #[error("出口会话句柄无效")]
    UnknownSession,
}

/// 权威绑定来源：由环境路由核心（如 `lengsuo-environment::Router`）实现。
///
/// 实现方的错误描述**不得**包含口令、密钥或完整配置。
pub trait BindingAuthority {
    /// 解析环境当前的权威租约：环境无绑定或设备离线 ⇒ `Err`。
    fn resolve(&self, environment: EnvironmentId) -> Result<Lease, AuthorityError>;

    /// 校验租约是否仍代表当前权威状态（实例、设备、代次一致且设备在线）。
    fn validate(&self, lease: Lease) -> Result<(), AuthorityError>;
}

/// 出口运行时：决定某台设备承担哪个协议出口、该出口是否可用，并建立/释放会话。
///
/// 真实实现对应 `lengsuo-node` 的八协议拨号；本 trait 不含任何凭据字段。
pub trait OutboundRuntime {
    /// 该设备配置的出口协议；未配置 ⇒ `None`（拒绝，不回落直连）。
    fn protocol_of(&self, device: DeviceId) -> Option<OutboundProtocol>;

    /// 该协议出口此刻是否可用（配置齐备、凭据有效、节点可达等）。
    fn is_available(&self, device: DeviceId, protocol: OutboundProtocol) -> bool;

    /// 建立一条到 `target` 的出口会话。
    fn open(
        &mut self,
        device: DeviceId,
        protocol: OutboundProtocol,
        target: SocketAddr,
    ) -> Result<OutboundSession, RuntimeError>;

    /// 把应用报文交给已建立的出口会话。
    fn forward(&mut self, session: OutboundSession, packet: &[u8]) -> Result<(), RuntimeError>;

    /// 释放一条出口会话（会话结束或建连失败回滚时调用）。
    fn release(&mut self, session: OutboundSession);
}

/// 运行时分配的出口会话句柄。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundSession(pub u64);

/// 命中的绑定标识（审计用）：只含环境、设备与代次，**不含**任何凭据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingId {
    pub environment: EnvironmentId,
    pub device: DeviceId,
    pub epoch: u64,
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionEntry {
    handle: EgressHandle,
    lease: Lease,
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
        let entry = SessionEntry { handle, lease };
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
