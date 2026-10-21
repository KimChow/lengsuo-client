//! 进程入口与演示接线。
//!
//! 本模块负责两件事：
//! 1. 把**命令行 → 配置 → 设备 → 运行时**这条链跑起来（[`run_entry`]）。
//! 2. 提供一组**静态**的归因器与权威来源（[`StaticClassifier`] / [`StaticAuthority`]），
//!    让入口在没有真实节点接进来时也能跑通一条完整链路。
//!
//! # 演示接线的性质
//!
//! [`StaticClassifier`] / [`StaticAuthority`] 是**固定值**：所有报文都归因到同一个
//! 环境、同一个设备、同一个代次。这**不是**生产策略——生产上归因由
//! `lengsuo-environment` 的路由核心给出，权威租约由节点侧给出。本入口把它们做成
//! 静态值，只是为了让「进程能跑起来」这件事有确定的语义；调用方若要接真实来源，
//! 应自行实现 [`lengsuo_tun::ingress::Classifier`] 与
//! [`lengsuo_tun::egress::BindingAuthority`]，再走 [`Runtime::new`] 组装。
//!
//! # 与参考实现的对照
//!
//! Xray 的 `proxy/tun/handler.go` 由 Xray 核心在 `core.RequireFeatures` 里注入
//! `policy.Manager` 与 `routing.Dispatcher`，本入口没有核心可挂，故用静态替身。

use lengsuo_tun::egress::{
    Attribution, AuthorityError, BindingAuthority, DeviceId, EgressSelector, EnvironmentId,
    Lease, OutboundProtocol, OutboundRuntime, OutboundSession, RuntimeError,
};
use lengsuo_tun::ingress::Classifier;
use lengsuo_tun::packet::PacketInfo;
use lengsuo_tun::session::Clock;
use lengsuo_tun::tcp::listener::{self, TcpListener};
use lengsuo_tun::tcp::state::Config as ConnConfig;

use super::config::{self, RuntimeConfig};
use super::device::{self, DeviceError};
use super::runtime::{Limits, OutboundExchange, Runtime, RuntimeStats, StopReason};

/// 入口层的失败原因。全部显式：出错即非零退出，不静默成功。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntryError {
    /// 命令行或配置非法。
    #[error("配置非法：{0}")]
    Config(#[from] config::ConfigError),
    /// 设备层失败。
    #[error("设备失败：{0}")]
    Device(#[from] DeviceError),
    /// 事件循环以设备错误终止。
    #[error("运行时终止：设备失败：{detail}")]
    DeviceFailed { detail: String },
}

/// 固定归因器：所有报文都归因到同一组（环境、设备、代次）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticClassifier {
    /// 环境号。
    pub environment: u64,
    /// 设备号。
    pub device: u64,
    /// 代次。
    pub epoch: u64,
}

impl Classifier for StaticClassifier {
    type Attribution = Attribution;
    type Error = String;

    /// 恒定返回一个归属。**永不**返回 `Ok(None)`：本演示接线不做「无归属」判定，
    /// 无归属的语义由调用方自己的分类器实现。
    fn classify(&mut self, _info: &PacketInfo) -> Result<Option<Attribution>, Self::Error> {
        Ok(Some(Attribution {
            environment: EnvironmentId(self.environment),
            device: DeviceId(self.device),
            epoch: self.epoch,
        }))
    }
}

/// 固定权威来源：一个环境、一台设备、一个代次。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticAuthority {
    /// 环境号。
    pub environment: u64,
    /// 设备号。
    pub device: u64,
    /// 代次。
    pub epoch: u64,
}

impl BindingAuthority for StaticAuthority {
    /// 只认自己那一个环境；其它环境一律拒绝（**不回落**）。
    fn resolve(&self, environment: EnvironmentId) -> Result<Lease, AuthorityError> {
        if environment.0 != self.environment {
            return Err(AuthorityError::UnknownEnvironment(environment));
        }
        Ok(Lease {
            instance: [0u8; 16],
            environment,
            device: DeviceId(self.device),
            epoch: self.epoch,
        })
    }

    /// 校验租约仍代表当前权威状态。
    fn validate(&self, lease: Lease) -> Result<(), AuthorityError> {
        if lease.environment.0 != self.environment
            || lease.device.0 != self.device
            || lease.epoch != self.epoch
        {
            return Err(AuthorityError::StaleLease);
        }
        Ok(())
    }
}

/// 演示用的出口运行时：不做真实拨号，但**如实记账**。
///
/// 它是 `OutboundRuntime` + `OutboundExchange` 的最小实现：每个设备一个协议，
/// 建连即发一个句柄，转发即记账。本进程没有节点侧的协议栈，所以这里**不假装**
/// 有真实链路——真实实现见 `lengsuo-node`。
#[derive(Debug, Default)]
pub struct DemoOutbound {
    /// 每台设备配置的协议。
    protocols: std::collections::BTreeMap<u64, OutboundProtocol>,
    /// 已建立的会话（句柄 → 设备）。
    live: std::collections::BTreeMap<u64, u64>,
    /// 已转发的载荷（按会话分组）。
    pub forwarded: std::collections::BTreeMap<u64, Vec<Vec<u8>>>,
    /// 建连次数。
    pub opens: usize,
    /// 下一个会话句柄。
    next: u64,
}

impl DemoOutbound {
    /// 建立一个演示出口运行时：给定设备与它的协议。
    pub fn new(device: u64, protocol: OutboundProtocol) -> Self {
        Self {
            protocols: std::collections::BTreeMap::from([(device, protocol)]),
            ..Self::default()
        }
    }
}

impl OutboundRuntime for DemoOutbound {
    fn protocol_of(&self, device: DeviceId) -> Option<OutboundProtocol> {
        self.protocols.get(&device.0).copied()
    }

    fn is_available(&self, device: DeviceId, protocol: OutboundProtocol) -> bool {
        self.protocols.get(&device.0) == Some(&protocol)
    }

    fn open(
        &mut self,
        device: DeviceId,
        protocol: OutboundProtocol,
        _target: std::net::SocketAddr,
    ) -> Result<OutboundSession, RuntimeError> {
        if self.protocols.get(&device.0) != Some(&protocol) {
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
    }
}

impl OutboundExchange for DemoOutbound {
    /// 演示出口没有回程数据源：恒为 `None`。
    fn take_response(&mut self, _session: OutboundSession) -> Option<Vec<u8>> {
        None
    }
}

/// 一次入口运行的产物：统计 + 停止原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryOutcome {
    /// 统计快照。
    pub stats: RuntimeStats,
    /// 停止原因。
    pub stopped: StopReason,
}

/// 静态接线：把配置里的环境/设备/代次接成一套自洽的归因器与权威来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticWiring {
    /// 归因器。
    pub classifier: StaticClassifier,
    /// 权威来源。
    pub authority: StaticAuthority,
    /// 演示出口运行时所配置的协议。
    pub protocol: OutboundProtocol,
}

impl StaticWiring {
    /// 按配置组装静态接线。
    #[must_use]
    pub fn from_config(config: &RuntimeConfig) -> Self {
        Self {
            classifier: StaticClassifier {
                environment: config.environment,
                device: config.device_id,
                epoch: config.epoch,
            },
            authority: StaticAuthority {
                environment: config.environment,
                device: config.device_id,
                epoch: config.epoch,
            },
            protocol: OutboundProtocol::Vless,
        }
    }
}

/// 按配置组装一个可运行的运行时。
///
/// 设备由调用方注入（生产传 [`PlatformDevice`]，测试传内存替身）；出口运行时同理。
fn build_runtime<D, R>(
    config: &RuntimeConfig,
    device: D,
    outbound: R,
) -> Result<Runtime<D, StaticClassifier, StaticAuthority, R>, EntryError>
where
    D: lengsuo_tun::ingress::PacketSource<Error = DeviceError> + super::device::TunDevice,
    R: lengsuo_tun::egress::OutboundRuntime + OutboundExchange,
{
    let wiring = StaticWiring::from_config(config);
    let routes = config.route_table()?;
    let selector = EgressSelector::new(
        wiring.authority,
        outbound,
        routes,
        config.session_capacity,
        config.session_ttl_ms,
    );
    let listener = TcpListener::new(listener::Config {
        connection: ConnConfig {
            receive_window: 4096,
            reorder_slots: 4,
            iss_seed: 0,
        },
        session_capacity: config.session_capacity,
        session_ttl: config.session_ttl_ms,
        interface_mtu: config.mtu,
        iss_seed_start: 1000,
    });
    Ok(Runtime::new(device, wiring.classifier, selector, listener))
}

/// 跑一次完整的入口：解析配置 → 开设备 → 建运行时 → 跑事件循环。
///
/// 设备打开失败时返回 [`EntryError`]（**不返回空设备、不静默成功**）。
pub fn run_entry(
    args: Vec<String>,
    now: Clock,
) -> Result<EntryOutcome, EntryError> {
    let raw = config::parse_args(args)?;
    let config = raw.into_config()?;
    run_with_config(&config, now)
}

/// 按已校验的配置跑一次完整的入口。
pub fn run_with_config(
    config: &RuntimeConfig,
    now: Clock,
) -> Result<EntryOutcome, EntryError> {
    let device = device::open_device(config)?;
    let outbound = DemoOutbound::new(config.device_id, OutboundProtocol::Vless);
    let mut runtime = build_runtime(config, device, outbound)?;
    let outcome = runtime.run(
        config.read_timeout(),
        Limits {
            max_packets: config.max_packets,
            max_steps: config.max_steps,
        },
        now,
    );
    Ok(EntryOutcome {
        stats: outcome.stats,
        stopped: outcome.stopped,
    })
}

/// 进程主逻辑：返回**退出码**。
///
/// 0 表示正常收尾（含达到预算停机）；非 0 表示配置/设备/运行时失败。
pub fn main_with_args(args: Vec<String>) -> i32 {
    let now = Clock::from(monotonic_millis());
    match run_entry(args, now) {
        Ok(outcome) => {
            eprintln!(
                "lengsuo-tun-runtime: 收 {} 包，写回 {} 包，拒绝 {} 包，停止原因 {:?}",
                outcome.stats.received,
                outcome.stats.written,
                outcome.stats.denied,
                outcome.stopped
            );
            0
        }
        Err(error) => {
            eprintln!("lengsuo-tun-runtime: {error}");
            1
        }
    }
}

/// 单调时钟毫秒刻度（进程启动以来的毫秒数）。
///
/// 用 `Instant` 而不是系统时钟：单调时钟不受 NTP 调整影响，超时判定不会跳变。
fn monotonic_millis() -> u64 {
    use std::time::Instant;
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}
