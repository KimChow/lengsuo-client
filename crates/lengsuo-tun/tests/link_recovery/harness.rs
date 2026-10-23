//! 断线/休眠恢复用例的共享夹具：权威来源替身、多设备出口替身与投递辅助。
//!
//! 用例本体留在 `tests/link_recovery.rs`（用例名保持在测试目标根上），实现放在
//! 这里，以免单文件超过 400 行。

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use lengsuo_environment::{DeviceId as EnvDeviceId, EnvironmentId as EnvEnvironmentId, Router};
use lengsuo_tun::egress::{
    Attribution, AuthorityError, BindingAuthority, DeviceId, EgressDecision, EgressSelector,
    EnvironmentId, Lease, NodeOutboundRuntime, OutboundExchange, OutboundProtocol, OutboundRuntime,
    OutboundSession, RuntimeError,
};
use lengsuo_tun::session::{Clock, SessionKey};

use crate::support::{info_of, RealAuthority};

/// 权威来源替身：在真实 `Router` 之上补「设备离线」窗口。
///
/// 真实 `Router::set_online(false)` 会**移除**该设备名下的绑定，此后 `resolve`
/// 只能返回 `UnknownEnvironment`。本替身先按真实语义撤销绑定，再对「曾经绑定、
/// 现已离线」的环境返回更精确的 `DeviceOffline`——这正是选择层要区分的拒绝原因；
/// 设备恢复时按记忆表重新 `bind`，代次随之推进。
pub struct LinkAuthority {
    inner: RealAuthority,
    env_device: BTreeMap<u64, u64>,
    offline: BTreeSet<u64>,
}

impl LinkAuthority {
    fn new(inner: RealAuthority, bindings: &[(u64, u64)]) -> Self {
        Self {
            inner,
            env_device: bindings.iter().copied().collect(),
            offline: BTreeSet::new(),
        }
    }

    /// 上报设备断开：撤销真实绑定，并记下「离线」供 `resolve` 给出精确原因。
    pub fn device_down(&mut self, device: u64) {
        self.inner.set_online(EnvDeviceId(device), false);
        self.offline.insert(device);
    }

    /// 上报设备恢复：重新上线并逐环境重绑；返回该设备最后一个绑定的代次。
    pub fn device_up(&mut self, device: u64) -> u64 {
        self.inner.set_online(EnvDeviceId(device), true);
        self.offline.remove(&device);
        let mut epoch = 0;
        for (&environment, &bound) in &self.env_device {
            if bound == device {
                epoch = self
                    .inner
                    .rebind(EnvEnvironmentId(environment), EnvDeviceId(device));
            }
        }
        epoch
    }
}

impl BindingAuthority for LinkAuthority {
    fn resolve(&self, environment: EnvironmentId) -> Result<Lease, AuthorityError> {
        if let Some(&device) = self.env_device.get(&environment.0) {
            if self.offline.contains(&device) {
                return Err(AuthorityError::DeviceOffline(DeviceId(device)));
            }
        }
        self.inner.resolve(environment)
    }

    fn validate(&self, lease: Lease) -> Result<(), AuthorityError> {
        if self.offline.contains(&lease.device.0) {
            return Err(AuthorityError::DeviceOffline(lease.device));
        }
        self.inner.validate(lease)
    }
}

/// 多设备内存出口运行时：记录活会话、释放与投递，供两设备隔离用例使用。
pub struct LinkRuntime {
    protocols: BTreeMap<u64, OutboundProtocol>,
    live: BTreeMap<u64, u64>,
    pub released: Vec<u64>,
    pub forwarded: BTreeMap<u64, Vec<Vec<u8>>>,
    pub opens: usize,
    next: u64,
}

impl LinkRuntime {
    pub fn with_protocols(entries: &[(u64, OutboundProtocol)]) -> Self {
        Self {
            protocols: entries.iter().copied().collect(),
            live: BTreeMap::new(),
            released: Vec::new(),
            forwarded: BTreeMap::new(),
            opens: 0,
            next: 0,
        }
    }

    pub fn live_count(&self) -> usize {
        self.live.len()
    }
}

impl OutboundRuntime for LinkRuntime {
    fn protocol_of(&self, device: DeviceId) -> Option<OutboundProtocol> {
        self.protocols.get(&device.0).copied()
    }

    fn is_available(&self, device: DeviceId, _protocol: OutboundProtocol) -> bool {
        self.protocols.contains_key(&device.0)
    }

    fn open(
        &mut self,
        device: DeviceId,
        _protocol: OutboundProtocol,
        _target: SocketAddr,
    ) -> Result<OutboundSession, RuntimeError> {
        if !self.protocols.contains_key(&device.0) {
            return Err(RuntimeError::NoProtocol);
        }
        self.opens += 1;
        self.next += 1;
        self.live.insert(self.next, device.0);
        Ok(OutboundSession(self.next))
    }

    fn forward(&mut self, session: OutboundSession, packet: &[u8]) -> Result<(), RuntimeError> {
        if !self.live.contains_key(&session.0) {
            return Err(RuntimeError::UnknownSession);
        }
        self.forwarded
            .entry(session.0)
            .or_default()
            .push(packet.to_vec());
        Ok(())
    }

    fn release(&mut self, session: OutboundSession) {
        self.live.remove(&session.0);
        self.released.push(session.0);
    }
}

/// 建一套「真实 Router 适配 + 记忆表」的权威来源；按绑定顺序返回代次。
pub fn link_authority(bindings: &[(u64, u64)]) -> (LinkAuthority, Vec<u64>) {
    let mut router = Router::new().expect("路由实例应可创建");
    let mut epochs = Vec::with_capacity(bindings.len());
    for &(environment, device) in bindings {
        router.set_online(EnvDeviceId(device), true);
        let lease = router
            .bind(EnvEnvironmentId(environment), EnvDeviceId(device))
            .expect("绑定应成功");
        epochs.push(lease.epoch);
    }
    (
        LinkAuthority::new(RealAuthority::new(router), bindings),
        epochs,
    )
}

/// 用给定报文与归因选一次出口（不关心会话键的内容）。
pub fn select_packet<A, R>(
    selector: &mut EgressSelector<A, R>,
    packet: &[u8],
    attribution: Attribution,
    now: Clock,
) -> EgressDecision
where
    A: BindingAuthority,
    R: OutboundRuntime,
{
    let info = info_of(packet);
    let key = SessionKey::from_info(info);
    selector.select(&info, key, attribution, now)
}

/// 取回程字节，直到攒够 `expected` 字节或超时。
pub fn take_response(
    selector: &mut EgressSelector<LinkAuthority, NodeOutboundRuntime>,
    session: OutboundSession,
    expected: usize,
    budget: Duration,
) -> Vec<u8> {
    let deadline = Instant::now() + budget;
    let mut out = Vec::new();
    while Instant::now() < deadline {
        if let Some(bytes) = selector.runtime_mut().take_response(session) {
            out.extend_from_slice(&bytes);
            if out.len() >= expected {
                return out;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    out
}
