//! 共享夹具：真实权威来源适配、内存假出口运行时、报文与路由构造。

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::time::Duration;

use lengsuo_environment::{DeviceId as EnvDeviceId, EnvironmentId as EnvEnvironmentId, Router};
use lengsuo_tun::egress::{
    Attribution, AuthorityError, BindingAuthority, DeviceId, EgressSelector, EnvironmentId, Lease,
    OutboundProtocol, OutboundRuntime, OutboundSession, RuntimeError,
};
use lengsuo_tun::packet::PacketInfo;
use lengsuo_tun::session::{Clock, SessionKey};
use lengsuo_tun::tcp::connector::RouteTable;

/// 每个用例的总超时上限。
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// 会话表 TTL（毫秒）：测试用固定时钟推进。
pub const TTL: Clock = 60_000;
/// 环境 7 / 设备 70：绝大多数用例共用的默认布置。
pub const ENV: u64 = 7;
pub const DEVICE: u64 = 70;

/// 真实权威来源适配：把 `lengsuo_environment::Router` 接到 `BindingAuthority`。
///
/// 这一层证明 trait 形状与真实路由核心的 `resolve` / `validate` 语义对得上：
/// 两者都是「环境无绑定 ⇒ 拒绝」「设备离线 ⇒ 拒绝」「代次变化 ⇒ 租约失效」。
pub struct RealAuthority {
    router: Router,
}

impl RealAuthority {
    pub fn new(router: Router) -> Self {
        Self { router }
    }

    /// 上报设备在线状态（离线会撤销该设备名下的全部绑定）。
    pub fn set_online(&mut self, device: EnvDeviceId, online: bool) {
        self.router.set_online(device, online);
    }

    /// 把环境换绑到另一台设备（代次推进 ⇒ 旧租约失效）。
    pub fn rebind(&mut self, environment: EnvEnvironmentId, device: EnvDeviceId) -> u64 {
        self.router
            .bind(environment, device)
            .expect("换绑应成功")
            .epoch
    }
}

/// 真实路由核心的拒绝 → 出口层的拒绝。`env` 用于「环境无绑定」这一支。
fn map_router_error(error: lengsuo_environment::RouterError, env: EnvironmentId) -> AuthorityError {
    use lengsuo_environment::RouterError as E;
    match error {
        E::UnknownEnvironment(_) => AuthorityError::UnknownEnvironment(env),
        E::DeviceOffline(device) => AuthorityError::DeviceOffline(DeviceId(device.0)),
        E::StaleLease(_) => AuthorityError::StaleLease,
        _ => AuthorityError::Rejected,
    }
}

impl BindingAuthority for RealAuthority {
    fn resolve(&self, environment: EnvironmentId) -> Result<Lease, AuthorityError> {
        let lease = self
            .router
            .resolve(EnvEnvironmentId(environment.0))
            .map_err(|error| map_router_error(error, environment))?;
        Ok(Lease {
            instance: lease.instance,
            environment,
            device: DeviceId(lease.device.0),
            epoch: lease.epoch,
        })
    }

    fn validate(&self, lease: Lease) -> Result<(), AuthorityError> {
        self.router
            .validate(lengsuo_environment::Lease {
                instance: lease.instance,
                environment: EnvEnvironmentId(lease.environment.0),
                device: EnvDeviceId(lease.device.0),
                epoch: lease.epoch,
            })
            .map_err(|error| map_router_error(error, lease.environment))
    }
}

/// 内存假出口运行时：记录建立的会话与投递的字节，可按设备注入「协议缺失/不可用」。
#[derive(Default)]
pub struct FakeRuntime {
    /// 每台设备配置的协议 / 标记为不可用的设备。
    protocols: BTreeMap<u64, OutboundProtocol>,
    unavailable: BTreeSet<u64>,
    /// 已建立的会话（句柄 → 设备）/ 已释放的会话句柄（断言不泄漏）。
    live: BTreeMap<u64, u64>,
    pub released: Vec<u64>,
    /// 收到的载荷（按会话分组）/ 建连次数（断言「不重复建连」）。
    pub forwarded: BTreeMap<u64, Vec<Vec<u8>>>,
    pub opens: usize,
    /// 下一个会话句柄。
    next: u64,
}

impl FakeRuntime {
    pub fn with_protocol(device: u64, protocol: OutboundProtocol) -> Self {
        Self {
            protocols: BTreeMap::from([(device, protocol)]),
            ..Self::default()
        }
    }

    pub fn unavailable(mut self, device: u64) -> Self {
        self.unavailable.insert(device);
        self
    }

    /// 仍然存活的会话数（泄漏检查）。
    pub fn live_count(&self) -> usize {
        self.live.len()
    }
}

impl OutboundRuntime for FakeRuntime {
    fn protocol_of(&self, device: lengsuo_tun::egress::DeviceId) -> Option<OutboundProtocol> {
        self.protocols.get(&device.0).copied()
    }

    fn is_available(
        &self,
        device: lengsuo_tun::egress::DeviceId,
        _protocol: OutboundProtocol,
    ) -> bool {
        !self.unavailable.contains(&device.0)
    }

    fn open(
        &mut self,
        device: lengsuo_tun::egress::DeviceId,
        _protocol: OutboundProtocol,
        _target: SocketAddr,
    ) -> Result<OutboundSession, RuntimeError> {
        if !self.protocols.contains_key(&device.0) {
            return Err(RuntimeError::NoProtocol);
        }
        if self.unavailable.contains(&device.0) {
            return Err(RuntimeError::Unavailable);
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

/// 最小合法 IPv4/TCP 报文（回环地址 + 假端口，不访问网络）。
pub fn valid_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 20 + 20 + 3];
    packet[0] = 0x45;
    let total = packet.len() as u16;
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[127, 0, 0, 1]);
    packet[16..20].copy_from_slice(&[127, 0, 0, 9]);
    packet[20..22].copy_from_slice(&40_000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443u16.to_be_bytes());
    packet[32] = 5 << 4;
    let mut sum: u32 = packet[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|word| u32::from(u16::from_be_bytes(*word)))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet
}

/// 源端口不同的测试报文（制造「另一个会话键」）。
pub fn packet_with_source_port(port: u16) -> Vec<u8> {
    let mut packet = valid_packet();
    packet[20..22].copy_from_slice(&port.to_be_bytes());
    packet
}

/// 解析测试报文得到元数据（与生产解析器同一个 `packet::inspect`）。
pub fn info_of(packet: &[u8]) -> PacketInfo {
    lengsuo_tun::packet::inspect(packet).expect("测试报文必须可解析")
}

/// 造一条出接口路由表：回环目标 → 接口 7 / 源地址 127.0.0.1。
pub fn routes() -> RouteTable {
    let mut routes = RouteTable::new();
    let host = "127.0.0.9".parse().unwrap();
    let source = "127.0.0.1".parse().unwrap();
    routes
        .insert_host(host, 7, source)
        .expect("主机路由应可插入");
    routes
}

/// 造一个「已上线并绑定」的权威路由。
pub fn bound_router(environment: u64, device: u64) -> (Router, Lease) {
    let mut router = Router::new().expect("路由实例应可创建");
    let dev = EnvDeviceId(device);
    router.set_online(dev, true);
    let lease = router
        .bind(EnvEnvironmentId(environment), dev)
        .expect("绑定应成功");
    let mapped = Lease {
        instance: lease.instance,
        environment: EnvironmentId(environment),
        device: DeviceId(device),
        epoch: lease.epoch,
    };
    (router, mapped)
}

/// 造一条归因。
pub fn attribution(environment: u64, device: u64, epoch: u64) -> Attribution {
    Attribution {
        environment: EnvironmentId(environment),
        device: DeviceId(device),
        epoch,
    }
}

/// 装一套「权威路由 + 假运行时 + 选择层」。
pub fn selector(
    router: Router,
    runtime: FakeRuntime,
) -> EgressSelector<RealAuthority, FakeRuntime> {
    EgressSelector::new(RealAuthority::new(router), runtime, routes(), 16, TTL)
}

/// 用默认报文与当前代次的归因选一次出口。
pub fn select(
    selector: &mut EgressSelector<RealAuthority, FakeRuntime>,
    epoch: u64,
    now: Clock,
) -> lengsuo_tun::egress::EgressDecision {
    let info = info_of(&valid_packet());
    let key = SessionKey::from_info(info);
    selector.select(&info, key, attribution(ENV, DEVICE, epoch), now)
}

/// 「无归属」的哨兵归因：环境号取一个永不绑定的值。
pub const ATTRIBUTION_MISSING: Attribution = Attribution {
    environment: EnvironmentId(u64::MAX),
    device: DeviceId(u64::MAX),
    epoch: u64::MAX,
};
