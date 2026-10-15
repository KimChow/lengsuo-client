//! 五元组、方向与时间戳：把 `lengsuo-tun` 的公开报文元数据归一化为会话键。
//!
//! 会话键与方向无关：始终按「发起方 -> 应答方」排序。入站报文先反转再查表，
//! 因此同一条双向流的两个方向落在同一个键上，不存在需要两侧分别登记的歧义。
//! 键里不含环境身份：环境归属只能由可信入口显式登记（见 `session`/`classify`），
//! 本模块不会从地址或端口猜测归属。

use crate::router::{DeviceId, EnvironmentId};
use lengsuo_tun::packet::{PacketInfo, Transport};
use std::net::IpAddr;
use std::time::Duration;

/// UDP DNS 的约定端口。只判定端口语义，不解析 DNS 报文结构，也不校验其合法性。
pub const DNS_PORT: u16 = 53;

/// 相对本机（平台 TUN 侧）的报文方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// 本机应用发出，走向出口设备。
    Egress,
    /// 从出口设备回给本机应用的应答。
    Ingress,
}

/// 单调毫秒时钟，由调用方（出口运行时）提供。
///
/// 纯内存判定不依赖真实等待：测试与生产都以显式时间戳驱动 TTL，
/// 时间只会前进，本模块不做任何系统调用。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// 叠加时长；`u64` 毫秒溢出或超过 `u128` 可表示范围时返回 `None`，
    /// 调用方必须 fail-closed。
    pub fn checked_add(self, delta: Duration) -> Option<Self> {
        let delta = u64::try_from(delta.as_millis()).ok()?;
        self.0.checked_add(delta).map(Timestamp)
    }

    /// 回退时长；结果为负时返回 `None`。
    pub fn checked_sub(self, delta: Duration) -> Option<Self> {
        let delta = u64::try_from(delta.as_millis()).ok()?;
        self.0.checked_sub(delta).map(Timestamp)
    }
}

/// 本模块认可的传输协议，与 `lengsuo_tun::packet::Transport` 一一对应。
/// 本地定义是为了让键可派生 `Ord`/`Hash`（供 BTreeMap 使用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlowProtocol {
    Tcp,
    Udp,
}

impl From<Transport> for FlowProtocol {
    fn from(value: Transport) -> Self {
        match value {
            Transport::Tcp => Self::Tcp,
            Transport::Udp => Self::Udp,
        }
    }
}

/// 归一化五元组：会话表的键，方向无关。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    pub protocol: FlowProtocol,
    pub source: IpAddr,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
}

impl FlowKey {
    /// 由报文元数据构造归一化键：出站原样、入站反转。
    pub fn from_packet(info: &PacketInfo, direction: Direction) -> Self {
        let key = Self {
            protocol: info.protocol.into(),
            source: info.source,
            source_port: info.source_port,
            destination: info.destination,
            destination_port: info.destination_port,
        };
        match direction {
            Direction::Egress => key,
            Direction::Ingress => key.reversed(),
        }
    }

    /// 交换两端，得到反向键。
    pub fn reversed(self) -> Self {
        Self {
            protocol: self.protocol,
            source: self.destination,
            source_port: self.destination_port,
            destination: self.source,
            destination_port: self.source_port,
        }
    }

    /// UDP 且端口 53 落在应答侧即视为 DNS 会话（归一化键上发起侧是源端口）。
    pub fn dns(&self) -> bool {
        self.protocol == FlowProtocol::Udp && self.destination_port == DNS_PORT
    }
}

/// 分类出的流量语义。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficKind {
    TcpStream,
    UdpFlow,
    DnsQuery,
    DnsResponse,
}

/// 按归一化键与报文方向判定语义；只看端口，不只看载荷。
pub fn traffic_kind(key: &FlowKey, direction: Direction) -> TrafficKind {
    if key.dns() {
        return match direction {
            Direction::Egress => TrafficKind::DnsQuery,
            Direction::Ingress => TrafficKind::DnsResponse,
        };
    }
    match key.protocol {
        FlowProtocol::Tcp => TrafficKind::TcpStream,
        FlowProtocol::Udp => TrafficKind::UdpFlow,
    }
}

/// 归属 + 出口 + 代次的最小凭据，结构上与 [`crate::Lease`] 同构，
/// 但由「已认证入口登记过的会话」加上权威路由当场解析得到。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribution {
    pub environment: EnvironmentId,
    pub device: DeviceId,
    pub epoch: u64,
}
