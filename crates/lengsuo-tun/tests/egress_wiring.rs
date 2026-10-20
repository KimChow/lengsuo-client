//! 出口方向接线测试：包 → 归因 → 选协议出口 → 交给出口运行时。
//!
//! # 性质（重要，勿误读）
//!
//! 本用例**不碰真实网卡、不建真实 socket、不做协议互通**：出口运行时是内存假实现。
//! 因此本套件证明的是**接线层的决策语义**（归因 → 选出口 → 复用 → 释放 →
//! fail-closed），**不是**与任何外部实现的互通。
//!
//! # 依赖方向的实测证据
//!
//! `lengsuo-environment` **依赖** `lengsuo-tun`（它复用 `PacketInfo`），故
//! `lengsuo-tun` 反向依赖它会构成 **cargo 依赖环**、cargo 直接拒绝构建（本卡已用
//! 最小复现工程实测复现）。生产侧因此只定义两个 trait 由上层注入；测试侧
//! `lengsuo-environment` 是本 crate 的 **dev-dependency**，本文件因此用**真实的
//! `lengsuo_environment::Router`** 做权威来源，验证 trait 与真实路由核心一致。
//!
//! 全部用例带总超时，不使用主机绝对路径、不含真实凭据。

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use lengsuo_environment::{DeviceId as EnvDeviceId, EnvironmentId as EnvEnvironmentId, Router};
use lengsuo_tun::egress::{
    Attribution, AuthorityError, BindingAuthority, DenyReason, DeviceId, EgressDecision,
    EgressSelector, EnvironmentId, Lease, OutboundProtocol, OutboundRuntime, OutboundSession,
    RuntimeError,
};
use lengsuo_tun::ingress::{EgressSink, Ingress, SelectorSink};
use lengsuo_tun::packet::PacketInfo;
use lengsuo_tun::session::{Clock, SessionKey};
use lengsuo_tun::tcp::connector::RouteTable;

/// 每个用例的总超时上限。
const TIMEOUT: Duration = Duration::from_secs(10);
/// 会话表 TTL（毫秒）：测试用固定时钟推进。
const TTL: Clock = 60_000;
/// 环境 7 / 设备 70：绝大多数用例共用的默认布置。
const ENV: u64 = 7;
const DEVICE: u64 = 70;

/// 真实权威来源适配：把 `lengsuo_environment::Router` 接到 `BindingAuthority`。
///
/// 这一层证明 trait 形状与真实路由核心的 `resolve` / `validate` 语义对得上：
/// 两者都是「环境无绑定 ⇒ 拒绝」「设备离线 ⇒ 拒绝」「代次变化 ⇒ 租约失效」。
struct RealAuthority {
    router: Router,
}

impl RealAuthority {
    fn new(router: Router) -> Self {
        Self { router }
    }

    /// 上报设备在线状态（离线会撤销该设备名下的全部绑定）。
    fn set_online(&mut self, device: EnvDeviceId, online: bool) {
        self.router.set_online(device, online);
    }

    /// 把环境换绑到另一台设备（代次推进 ⇒ 旧租约失效）。
    fn rebind(&mut self, environment: EnvEnvironmentId, device: EnvDeviceId) -> u64 {
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
struct FakeRuntime {
    /// 每台设备配置的协议 / 标记为不可用的设备。
    protocols: BTreeMap<u64, OutboundProtocol>,
    unavailable: BTreeSet<u64>,
    /// 已建立的会话（句柄 → 设备）/ 已释放的会话句柄（断言不泄漏）。
    live: BTreeMap<u64, u64>,
    released: Vec<u64>,
    /// 收到的载荷（按会话分组）/ 建连次数（断言「不重复建连」）。
    forwarded: BTreeMap<u64, Vec<Vec<u8>>>,
    opens: usize,
    /// 下一个会话句柄。
    next: u64,
}

impl FakeRuntime {
    fn with_protocol(device: u64, protocol: OutboundProtocol) -> Self {
        Self {
            protocols: BTreeMap::from([(device, protocol)]),
            ..Self::default()
        }
    }

    fn unavailable(mut self, device: u64) -> Self {
        self.unavailable.insert(device);
        self
    }

    /// 仍然存活的会话数（泄漏检查）。
    fn live_count(&self) -> usize {
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
fn valid_packet() -> Vec<u8> {
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
fn packet_with_source_port(port: u16) -> Vec<u8> {
    let mut packet = valid_packet();
    packet[20..22].copy_from_slice(&port.to_be_bytes());
    packet
}

/// 解析测试报文得到元数据（与生产解析器同一个 `packet::inspect`）。
fn info_of(packet: &[u8]) -> PacketInfo {
    lengsuo_tun::packet::inspect(packet).expect("测试报文必须可解析")
}

/// 造一条出接口路由表：回环目标 → 接口 7 / 源地址 127.0.0.1。
fn routes() -> RouteTable {
    let mut routes = RouteTable::new();
    let host = "127.0.0.9".parse().unwrap();
    let source = "127.0.0.1".parse().unwrap();
    routes
        .insert_host(host, 7, source)
        .expect("主机路由应可插入");
    routes
}

/// 造一个「已上线并绑定」的权威路由。
fn bound_router(environment: u64, device: u64) -> (Router, Lease) {
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
fn attribution(environment: u64, device: u64, epoch: u64) -> Attribution {
    Attribution {
        environment: EnvironmentId(environment),
        device: DeviceId(device),
        epoch,
    }
}

/// 装一套「权威路由 + 假运行时 + 选择层」。
fn selector(router: Router, runtime: FakeRuntime) -> EgressSelector<RealAuthority, FakeRuntime> {
    EgressSelector::new(RealAuthority::new(router), runtime, routes(), 16, TTL)
}

/// 用默认报文与当前代次的归因选一次出口。
fn select(
    selector: &mut EgressSelector<RealAuthority, FakeRuntime>,
    epoch: u64,
    now: Clock,
) -> EgressDecision {
    let info = info_of(&valid_packet());
    let key = SessionKey::from_info(info);
    selector.select(&info, key, attribution(ENV, DEVICE, epoch), now)
}

/// 「无归属」的哨兵归因：环境号取一个永不绑定的值。
const ATTRIBUTION_MISSING: Attribution = Attribution {
    environment: EnvironmentId(u64::MAX),
    device: DeviceId(u64::MAX),
    epoch: u64::MAX,
};

/// 用例 1：正常路径——包归因到环境 A ⇒ 选中环境 A 的协议出口
///
/// 归因到环境 A ⇒ 选中环境 A 的出口：断言句柄（协议/设备/代次/出接口）与 reason。
#[tokio::test]
async fn attributed_packet_selects_that_environments_outbound() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let mut selector = selector(router, runtime);

        let decision = select(&mut selector, lease.epoch, 1_000);
        let handle = decision.handle().expect("应选中出口");
        assert_eq!(decision.deny_reason(), None);
        assert_eq!(handle.binding.environment.0, ENV, "命中的环境");
        assert_eq!(handle.binding.device.0, DEVICE, "命中的设备");
        assert_eq!(handle.binding.epoch, lease.epoch, "命中的代次");
        assert_eq!(handle.protocol, OutboundProtocol::Vless, "选中的协议出口");
        assert_eq!(handle.interface_index, 7, "出接口由路由表选定");
        assert_eq!(handle.source, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(selector.session_count(), 1, "应持有一条出口会话");
    })
    .await
    .expect("用例超时");
}

/// 用例 2：归因不到环境 ⇒ 拒绝（**不得**回落到默认直连）；断言无出口、无建连、无直连。
#[tokio::test]
async fn unattributed_packet_is_denied_not_sent_direct() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, _lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let selector = selector(router, runtime);

        let packet = valid_packet();
        let info = info_of(&packet);
        let key = SessionKey::from_info(info);

        // 归因缺席：走 ingress 的 sink 侧——分类器返回 Ok(None) 时根本不进出口层。
        let mut sink = SelectorSink::new(selector, || 1_000u64);
        assert!(sink.deliver(&packet, &info, ATTRIBUTION_MISSING).is_err());

        // 直接问选择层：即便硬塞一个不存在的环境，也必须拒绝而不是直连。
        let decision = sink
            .selector_mut()
            .select(&info, key, attribution(999, DEVICE, 1), 1_000);
        assert_eq!(decision.deny_reason(), Some(DenyReason::UnknownEnvironment));
        assert_eq!(decision.handle(), None, "拒绝不得给出出口句柄");
        assert_eq!(sink.selector().session_count(), 0, "拒绝不得留下会话");
        assert_eq!(sink.selector().runtime().live_count(), 0, "拒绝不得建连");
    })
    .await
    .expect("用例超时");
}

/// 用例 3：设备下线后其绑定立即失效 ⇒ 拒绝；不得改走别的出口。
#[tokio::test]
async fn offline_device_is_denied() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let mut selector = selector(router, runtime);

        // 先成功选一次，确认正常路径可用。
        assert!(select(&mut selector, lease.epoch, 1_000).handle().is_some());

        // 设备离线：权威路由撤销该设备名下的全部绑定。
        selector
            .authority_mut()
            .set_online(EnvDeviceId(DEVICE), false);

        // 新会话键（换源端口）⇒ 必须因设备离线被拒。
        let other = packet_with_source_port(40_001);
        let other_info = info_of(&other);
        let decision = selector.select(
            &other_info,
            SessionKey::from_info(other_info),
            attribution(ENV, DEVICE, lease.epoch),
            2_000,
        );
        assert_eq!(decision.deny_reason(), Some(DenyReason::UnknownEnvironment));
        assert_eq!(decision.handle(), None);
    })
    .await
    .expect("用例超时");
}

/// 用例 4：协议出口不可用 ⇒ 拒绝（**不静默降级**）；断言没有改用任何其它协议。
#[tokio::test]
async fn unavailable_protocol_is_denied_without_fallback() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        // 设备 70 配的是 vless，但此刻不可用（设备 71 配的是 trojan 且可用）。
        let runtime =
            FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless).unavailable(DEVICE);
        let mut selector = selector(router, runtime);

        let decision = select(&mut selector, lease.epoch, 1_000);
        assert_eq!(
            decision.deny_reason(),
            Some(DenyReason::ProtocolUnavailable)
        );
        assert_eq!(decision.handle(), None, "不得给出任何出口句柄");
        assert_eq!(selector.session_count(), 0, "不得留下会话");
        assert_eq!(selector.runtime().opens, 0, "不得建连，更不得改用别的协议");
    })
    .await
    .expect("用例超时");
}

/// 设备**未配置任何协议** ⇒ 同样拒绝（不回落到直连，也不换协议）。
#[tokio::test]
async fn device_without_protocol_is_denied() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::default(); // 没有任何设备配置协议
        let mut selector = selector(router, runtime);

        let decision = select(&mut selector, lease.epoch, 1_000);
        assert_eq!(
            decision.deny_reason(),
            Some(DenyReason::ProtocolUnavailable)
        );
        assert_eq!(selector.runtime().opens, 0);
    })
    .await
    .expect("用例超时");
}

/// 用例 5：换绑（代次推进）后旧租约失效 ⇒ 复用路径必须拒绝，不得继续用旧出口。
#[tokio::test]
async fn stale_lease_is_denied_and_not_reused() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let mut selector = selector(router, runtime);

        let info = info_of(&valid_packet());
        let key = SessionKey::from_info(info);

        // 第一次选中并建连。
        assert!(select(&mut selector, lease.epoch, 1_000).handle().is_some());
        assert_eq!(selector.runtime().opens, 1);

        // 换绑：同一环境改绑到另一台在线设备 ⇒ 代次推进，旧租约失效。
        selector.authority_mut().set_online(EnvDeviceId(71), true);
        let new_epoch = selector
            .authority_mut()
            .rebind(EnvEnvironmentId(ENV), EnvDeviceId(71));
        assert!(new_epoch > lease.epoch, "换绑必须推进代次，旧租约因此失效");

        // 同一会话键再选：旧租约已失效 ⇒ 拒绝，**不得**复用旧出口。
        let decision = selector.select(&info, key, attribution(ENV, DEVICE, lease.epoch), 2_000);
        assert_eq!(decision.deny_reason(), Some(DenyReason::StaleLease));
        assert_eq!(decision.handle(), None, "不得复用失效租约对应的旧出口");
        assert_eq!(selector.runtime().opens, 1, "拒绝时不得新建连接");
    })
    .await
    .expect("用例超时");
}

/// 归因的代次落后于权威绑定 ⇒ 拒绝（换绑前的旧归因不得继续用）。
#[tokio::test]
async fn stale_attribution_is_denied() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let mut selector = selector(router, runtime);

        // 换绑推进代次。
        selector.authority_mut().set_online(EnvDeviceId(71), true);
        selector
            .authority_mut()
            .rebind(EnvEnvironmentId(ENV), EnvDeviceId(71));

        let decision = select(&mut selector, lease.epoch, 1_000);
        assert_eq!(decision.deny_reason(), Some(DenyReason::StaleAttribution));
        assert_eq!(selector.runtime().opens, 0, "拒绝不得建连");
    })
    .await
    .expect("用例超时");
}

/// 用例 6：同一会话键重复选路 ⇒ 复用同一出口句柄（**不重复建连**）。
#[tokio::test]
async fn repeated_selection_reuses_same_outbound() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let mut selector = selector(router, runtime);

        let info = info_of(&valid_packet());
        let key = SessionKey::from_info(info);
        let attribution = attribution(ENV, DEVICE, lease.epoch);

        let first = selector.select(&info, key, attribution, 1_000);
        let second = selector.select(&info, key, attribution, 1_001);
        let third = selector.select(&info, key, attribution, 1_002);

        let first_handle = first.handle().expect("首次应选中");
        assert_eq!(second.handle(), Some(first_handle), "必须复用同一出口句柄");
        assert_eq!(third.handle(), Some(first_handle));
        assert_eq!(selector.runtime().opens, 1, "不得重复建连");
        assert_eq!(selector.session_count(), 1, "会话表只应有一条条目");
    })
    .await
    .expect("用例超时");
}

/// 用例 7：关闭会话 ⇒ 出口被释放、运行时无残留会话（**不泄漏**）。
#[tokio::test]
async fn closing_session_releases_outbound() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let mut selector = selector(router, runtime);

        let info = info_of(&valid_packet());
        let key = SessionKey::from_info(info);
        let handle = select(&mut selector, lease.epoch, 1_000)
            .handle()
            .expect("应选中出口");
        assert_eq!(selector.runtime().live_count(), 1, "建连后有一条活会话");

        let closed = selector.close(key).expect("关闭应返回句柄");
        assert_eq!(closed, handle, "释放的应是那条出口");
        assert_eq!(selector.session_count(), 0, "会话表应已清空");
        assert_eq!(
            selector.runtime().live_count(),
            0,
            "出口必须被释放，不得泄漏"
        );
        assert_eq!(selector.runtime().released, vec![handle.session.0]);
    })
    .await
    .expect("用例超时");
}

/// 会话过期（TTL 到点）⇒ `gc` 释放出口，不泄漏。
#[tokio::test]
async fn expired_sessions_are_released_on_gc() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let mut selector = selector(router, runtime);

        assert!(select(&mut selector, lease.epoch, 1_000).handle().is_some());
        assert_eq!(selector.runtime().live_count(), 1);

        // 时钟推进过 TTL ⇒ 条目过期，gc 必须释放其出口。
        let reclaimed = selector.gc(1_000 + TTL + 1);
        assert_eq!(reclaimed, 1, "应回收一条过期会话");
        assert_eq!(selector.session_count(), 0);
        assert_eq!(
            selector.runtime().live_count(),
            0,
            "过期会话的出口必须被释放"
        );
    })
    .await
    .expect("用例超时");
}

/// 用例 8：路由表没覆盖目的地址 ⇒ 拒绝；**不走默认路由、不回落直连**。
#[tokio::test]
async fn missing_route_is_denied() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        // 空路由表：任何目的地址都查不到出接口。
        let mut selector = EgressSelector::new(
            RealAuthority::new(router),
            runtime,
            RouteTable::new(),
            16,
            TTL,
        );

        let decision = select(&mut selector, lease.epoch, 1_000);
        assert_eq!(decision.deny_reason(), Some(DenyReason::NoRoute));
        assert_eq!(decision.handle(), None);
        assert_eq!(selector.runtime().opens, 0, "无出接口不得建连");
    })
    .await
    .expect("用例超时");
}

/// 用例 9：接进既有 Ingress<D, C, E> 的 sink 侧（**不重写** ingress）
///
/// 内存假设备：队列里逐个吐出报文，空了返回超时。
struct FakeSource {
    queue: VecDeque<Vec<u8>>,
}

impl FakeSource {
    fn with(packets: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            queue: packets.into_iter().collect(),
        }
    }
}

impl lengsuo_tun::ingress::PacketSource for FakeSource {
    type Error = String;

    fn receive(
        &mut self,
        _timeout: Duration,
    ) -> Result<lengsuo_tun::ingress::Receipt, Self::Error> {
        let receipt = self.queue.pop_front();
        Ok(receipt.map_or(
            lengsuo_tun::ingress::Receipt::Timeout,
            lengsuo_tun::ingress::Receipt::Packet,
        ))
    }
}

/// 分类器：按固定脚本给出归因或「无归属」。
struct ScriptedClassifier {
    script: VecDeque<Option<Attribution>>,
}

impl lengsuo_tun::ingress::Classifier for ScriptedClassifier {
    type Attribution = Attribution;
    type Error = String;

    fn classify(&mut self, _info: &PacketInfo) -> Result<Option<Self::Attribution>, Self::Error> {
        Ok(self.script.pop_front().unwrap_or(None))
    }
}

/// 出口选择层作为 `Ingress` 的 sink：**设备 → 分类 → 选出口**整链跑通，统计口径分列。
#[tokio::test]
async fn selector_sink_plugs_into_existing_ingress_pipeline() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let selector = selector(router, runtime);
        let attribution = attribution(ENV, DEVICE, lease.epoch);

        let mut ingress = Ingress::new(
            FakeSource::with([valid_packet(), valid_packet()]),
            ScriptedClassifier {
                script: VecDeque::from([Some(attribution), None]),
            },
            SelectorSink::new(selector, || 1_000u64),
        );

        // 第一步：分类命中 → 选出出口 → 投递成功。
        let step = ingress.step(Duration::from_millis(1));
        assert_eq!(step, lengsuo_tun::ingress::Step::Delivered);

        // 第二步：分类无归属 ⇒ 出口层根本不会被调用。
        let step = ingress.step(Duration::from_millis(1));
        assert!(matches!(step, lengsuo_tun::ingress::Step::Denied { .. }));

        let stats = ingress.stats();
        assert_eq!(stats.received, 2);
        assert_eq!(stats.delivered, 1, "只有归因命中的那一包被投递");
        assert_eq!(stats.denied_no_attribution, 1, "无归属必须计入拒绝");
        assert_eq!(stats.egress_errors, 0, "无归属不是出口错误");

        // 出口层确实建立并使用了一条会话，且载荷已投递。
        let sink = ingress.sink();
        assert_eq!(sink.selector().session_count(), 1);
        assert_eq!(sink.selector().runtime().opens, 1);
        let forwarded = &sink.selector().runtime().forwarded;
        assert_eq!(forwarded.len(), 1, "应有一条会话收到过载荷");
        assert_eq!(forwarded.values().next().map(Vec::len), Some(1));
    })
    .await
    .expect("用例超时");
}

/// 出口层拒绝（协议不可用）⇒ 计入 ingress 的 `egress_errors`，与「未归属」分列。
#[tokio::test]
async fn selector_denial_is_counted_as_egress_error_not_unattributed() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        // 协议不可用 ⇒ 出口层拒绝。
        let runtime =
            FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless).unavailable(DEVICE);
        let selector = selector(router, runtime);
        let attribution = attribution(ENV, DEVICE, lease.epoch);

        let mut ingress = Ingress::new(
            FakeSource::with([valid_packet()]),
            ScriptedClassifier {
                script: VecDeque::from([Some(attribution)]),
            },
            SelectorSink::new(selector, || 1_000u64),
        );

        let step = ingress.step(Duration::from_millis(1));
        assert!(
            matches!(step, lengsuo_tun::ingress::Step::EgressFailed { .. }),
            "出口层拒绝应表现为出口失败：{step:?}"
        );

        let stats = ingress.stats();
        assert_eq!(stats.received, 1);
        assert_eq!(stats.delivered, 0, "拒绝不得投递");
        assert_eq!(stats.egress_errors, 1, "拒绝计入出口错误");
        assert_eq!(
            stats.denied_no_attribution, 0,
            "有归因但出口拒绝，不算未归属"
        );
    })
    .await
    .expect("用例超时");
}
