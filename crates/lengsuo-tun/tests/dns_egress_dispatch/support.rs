//! 共享夹具：记录式内存出口运行时、固定权威来源、时钟与报文构造。
//!
//! 全部是纯内存替身：不建真实 socket、不碰网卡、不需要 root。本文件**不是**
//! `tests/egress_wiring/support.rs` 的替代，也不修改它。

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use lengsuo_tun::egress::{
    Attribution, AuthorityError, BindingAuthority, DeviceId, EgressSelector, EnvironmentId, Lease,
    OutboundProtocol, OutboundRuntime, OutboundSession, RuntimeError,
};
use lengsuo_tun::session::{Clock, SessionKey};
use lengsuo_tun::tcp::connector::RouteTable;
use lengsuo_tun::Transport;

use lengsuo_tun::dns::upstream::Table;

/// 会话表 TTL（毫秒）：固定时钟推进，过期行为确定。
pub const TTL: Clock = 60_000;
/// 测试统一使用的时钟刻度。
pub const NOW: Clock = 1_000;
/// 默认环境号。
pub const ENV: u64 = 7;
/// 第二个环境号（隔离用例）。
pub const ENV_B: u64 = 8;
/// 默认出口设备号。
pub const DEVICE: u64 = 70;

/// 记录式内存出口运行时：建连、转发、释放全部留痕，可按设备注入故障。
pub struct RecordingRuntime {
    protocols: BTreeMap<u64, OutboundProtocol>,
    unavailable: BTreeSet<u64>,
    dial_fail: BTreeSet<u64>,
    /// 全局转发失败开关（测试中途可翻转，故用 `Cell`）。
    pub fail_forward: Cell<bool>,
    /// 建连记录：`(设备, 协议, 目的地址)`。
    pub opened: Vec<(u64, OutboundProtocol, SocketAddr)>,
    /// 转发记录：`(会话句柄, 载荷)`。
    pub forwarded: Vec<(u64, Vec<u8>)>,
    /// 释放记录：会话句柄。
    pub released: Vec<u64>,
    /// 仍存活的会话句柄。
    pub live: BTreeSet<u64>,
    next: u64,
}

impl RecordingRuntime {
    /// 一台设备、配置一个协议。
    #[must_use]
    pub fn with_device(device: u64, protocol: OutboundProtocol) -> Self {
        Self {
            protocols: BTreeMap::from([(device, protocol)]),
            ..Self::default()
        }
    }

    /// 标记该设备协议出口不可用。
    pub fn unavailable(mut self, device: u64) -> Self {
        self.unavailable.insert(device);
        self
    }

    /// 注入该设备建连失败。
    pub fn dial_fail(mut self, device: u64) -> Self {
        self.dial_fail.insert(device);
        self
    }
}

impl Default for RecordingRuntime {
    fn default() -> Self {
        Self {
            protocols: BTreeMap::new(),
            unavailable: BTreeSet::new(),
            dial_fail: BTreeSet::new(),
            fail_forward: Cell::new(false),
            opened: Vec::new(),
            forwarded: Vec::new(),
            released: Vec::new(),
            live: BTreeSet::new(),
            next: 0,
        }
    }
}

impl OutboundRuntime for RecordingRuntime {
    fn protocol_of(&self, device: DeviceId) -> Option<OutboundProtocol> {
        self.protocols.get(&device.0).copied()
    }

    fn is_available(&self, device: DeviceId, _protocol: OutboundProtocol) -> bool {
        !self.unavailable.contains(&device.0)
    }

    fn open(
        &mut self,
        device: DeviceId,
        protocol: OutboundProtocol,
        target: SocketAddr,
    ) -> Result<OutboundSession, RuntimeError> {
        if self.dial_fail.contains(&device.0) {
            return Err(RuntimeError::Dial);
        }
        if self.unavailable.contains(&device.0) {
            return Err(RuntimeError::Unavailable);
        }
        self.opened.push((device.0, protocol, target));
        self.next += 1;
        self.live.insert(self.next);
        Ok(OutboundSession(self.next))
    }

    fn forward(&mut self, session: OutboundSession, packet: &[u8]) -> Result<(), RuntimeError> {
        if !self.live.contains(&session.0) {
            return Err(RuntimeError::UnknownSession);
        }
        if self.fail_forward.get() {
            return Err(RuntimeError::Forward);
        }
        self.forwarded.push((session.0, packet.to_vec()));
        Ok(())
    }

    fn release(&mut self, session: OutboundSession) {
        self.live.remove(&session.0);
        self.released.push(session.0);
    }
}

/// 固定权威来源：按环境查预置租约，可翻转 `resolve` 失败与 `validate` 陈旧。
pub struct FixedAuthority {
    leases: BTreeMap<u64, Lease>,
    /// `false` ⇒ `resolve` 一律拒绝（模拟环境无绑定）。
    pub resolve_ok: Cell<bool>,
    /// `true` ⇒ `validate` 返回 [`AuthorityError::StaleLease`]。
    pub stale: Cell<bool>,
}

impl FixedAuthority {
    /// 空权威：任何环境都 `resolve` 失败。
    #[must_use]
    pub fn new() -> Self {
        Self {
            leases: BTreeMap::new(),
            resolve_ok: Cell::new(true),
            stale: Cell::new(false),
        }
    }

    /// 登记一个环境 →（设备，代次）的租约。
    #[must_use]
    pub fn with_env(mut self, environment: u64, device: u64, epoch: u64) -> Self {
        self.leases.insert(
            environment,
            Lease {
                instance: [0u8; 16],
                environment: EnvironmentId(environment),
                device: DeviceId(device),
                epoch,
            },
        );
        self
    }
}

impl Default for FixedAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl BindingAuthority for FixedAuthority {
    fn resolve(&self, environment: EnvironmentId) -> Result<Lease, AuthorityError> {
        if !self.resolve_ok.get() {
            return Err(AuthorityError::UnknownEnvironment(environment));
        }
        self.leases
            .get(&environment.0)
            .copied()
            .ok_or(AuthorityError::UnknownEnvironment(environment))
    }

    fn validate(&self, _lease: Lease) -> Result<(), AuthorityError> {
        if self.stale.get() {
            Err(AuthorityError::StaleLease)
        } else {
            Ok(())
        }
    }
}

/// 造一条归因。
#[must_use]
pub fn attribution(environment: u64, device: u64, epoch: u64) -> Attribution {
    Attribution {
        environment: EnvironmentId(environment),
        device: DeviceId(device),
        epoch,
    }
}

/// 回环上游地址。
#[must_use]
pub fn upstream(port: u16) -> SocketAddr {
    (std::net::Ipv4Addr::LOCALHOST, port).into()
}

/// 造一条 DNS 会话键：源地址回环 + 指定源端口，目的端固定取登记上游。
#[must_use]
pub fn key(source_port: u16) -> SessionKey {
    SessionKey::new(
        Transport::Udp,
        std::net::Ipv4Addr::LOCALHOST.into(),
        source_port,
        std::net::Ipv4Addr::LOCALHOST.into(),
        53,
    )
}

/// 造一条目的地址与登记上游不同的会话键（用于「无法改指向」用例）。
#[must_use]
pub fn key_to(source_port: u16, destination: SocketAddr) -> SessionKey {
    SessionKey::new(
        Transport::Udp,
        std::net::Ipv4Addr::LOCALHOST.into(),
        source_port,
        destination.ip(),
        destination.port(),
    )
}

/// 出接口路由表：上游（127.0.0.1）→ 接口 1 / 源地址 127.0.0.1。
#[must_use]
pub fn routes() -> RouteTable {
    let mut routes = RouteTable::new();
    routes
        .insert_host(
            "127.0.0.1".parse().unwrap(),
            1,
            "127.0.0.1".parse().unwrap(),
        )
        .expect("主机路由应可插入");
    routes
}

/// 装一套出口选择层（固定权威 + 记录式运行时 + 回环主机路由）。
#[must_use]
pub fn selector(
    authority: FixedAuthority,
    runtime: RecordingRuntime,
    capacity: usize,
) -> EgressSelector<FixedAuthority, RecordingRuntime> {
    EgressSelector::new(authority, runtime, routes(), capacity, TTL)
}

/// 按 `(环境, 上游)` 清单造绑定表。
#[must_use]
pub fn table(entries: &[(u64, SocketAddr)]) -> Table {
    let mut table = Table::default();
    for &(environment, upstream) in entries {
        table.bind(environment, upstream);
    }
    table
}
