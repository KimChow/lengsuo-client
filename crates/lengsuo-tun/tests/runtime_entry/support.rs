//! 测试夹具：内存设备替身、内存出口运行时、报文构造器。
//!
//! # 性质（重要，勿误读）
//!
//! 本目录下的用例**不接真实 TUN 设备、不建真实 socket、不与任何外部实现互通**：
//! 设备是内存替身，出口运行时是内存替身。因此它证明的是**入口的接线语义**
//! （配置校验 → 读循环 → 校验 → 归因 → 路由/出口决策 → 写回），**不是**
//! 「TUN 已实机可用」的证据。
//!
//! # 被测代码就是生产代码
//!
//! 测试用 `#[path]` 直接把 `src/bin/lengsuo-tun-runtime.rs` 包含进来，因此**跑的就是
//! bin crate root 那份源码**，不存在「测试替身另写一份逻辑」的问题。

#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use lengsuo_tun::egress::{
    Attribution, AuthorityError, BindingAuthority, DeviceId, EnvironmentId, Lease,
    OutboundProtocol, OutboundRuntime, OutboundSession, RuntimeError,
};
use lengsuo_tun::ingress::{Classifier, PacketSource, Receipt};
use lengsuo_tun::packet::PacketInfo;
use lengsuo_tun::session::Clock;
use lengsuo_tun::tcp::segment::{self, Flags};

use crate::runtime_entry::{DeviceError, OutboundExchange, TunDevice};

/// 测试用的固定时钟刻度（毫秒）。
pub const NOW: Clock = 1_000;
/// 本端地址（模拟 TUN 侧）。
pub const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// 对端地址（模拟 TUN 另一侧）。
pub const REMOTE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// 本端端口。
pub const LOCAL_PORT: u16 = 8080;
/// 对端端口。
pub const REMOTE_PORT: u16 = 40_000;

/// 内存设备替身：队列里逐个吐出报文，空了返回超时；写回包进 `written`。
#[derive(Default)]
pub struct FakeDevice {
    /// 待收报文队列。
    pub queue: VecDeque<Vec<u8>>,
    /// 已写回的报文。
    pub written: Vec<Vec<u8>>,
    /// 收包时的错误（注入一次后清空）。
    pub fail_next: Option<String>,
}

impl FakeDevice {
    /// 用一批报文建立设备替身。
    pub fn with(packets: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            queue: packets.into_iter().collect(),
            ..Self::default()
        }
    }
}

impl PacketSource for FakeDevice {
    type Error = DeviceError;

    fn receive(&mut self, _timeout: Duration) -> Result<Receipt, Self::Error> {
        if self.fail_next.take().is_some() {
            return Err(DeviceError::Syscall {
                op: "内存设备",
                code: -1,
            });
        }
        Ok(self
            .queue
            .pop_front()
            .map_or(Receipt::Timeout, Receipt::Packet))
    }
}

impl TunDevice for FakeDevice {
    fn send(&mut self, packet: &[u8]) -> Result<(), DeviceError> {
        self.written.push(packet.to_vec());
        Ok(())
    }
}

/// 内存权威来源：一个环境、一台设备、一条有效租约。
#[derive(Clone, Copy)]
pub struct FakeAuthority {
    /// 环境号。
    pub environment: u64,
    /// 设备号。
    pub device: u64,
    /// 代次。
    pub epoch: u64,
}

impl BindingAuthority for FakeAuthority {
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

    fn validate(&self, lease: Lease) -> Result<(), AuthorityError> {
        if lease.environment.0 != self.environment || lease.device.0 != self.device {
            return Err(AuthorityError::StaleLease);
        }
        Ok(())
    }
}

/// 内存出口运行时：记录会话、投递的载荷与回程字节。
#[derive(Default)]
pub struct FakeOutbound {
    /// 每台设备配置的协议。
    pub protocols: BTreeMap<u64, OutboundProtocol>,
    /// 已建立的会话（句柄 → 设备）。
    pub live: BTreeMap<u64, u64>,
    /// 每个会话已就绪的回程字节。
    pub responses: BTreeMap<u64, VecDeque<Vec<u8>>>,
    /// 收到的载荷（按会话分组）。
    pub forwarded: BTreeMap<u64, Vec<Vec<u8>>>,
    /// 建连次数。
    pub opens: usize,
    /// 下一个会话句柄。
    pub next: u64,
}

impl FakeOutbound {
    /// 建立一个出口运行时：给定设备与它的协议。
    pub fn with_protocol(device: u64, protocol: OutboundProtocol) -> Self {
        Self {
            protocols: BTreeMap::from([(device, protocol)]),
            ..Self::default()
        }
    }

    /// 给某个会话预置回程字节。
    pub fn push_response(&mut self, session: u64, bytes: Vec<u8>) {
        self.responses.entry(session).or_default().push_back(bytes);
    }
}

impl OutboundRuntime for FakeOutbound {
    fn protocol_of(&self, device: DeviceId) -> Option<OutboundProtocol> {
        self.protocols.get(&device.0).copied()
    }

    fn is_available(&self, device: DeviceId, protocol: OutboundProtocol) -> bool {
        self.protocols.contains_key(&device.0) && self.protocols.get(&device.0) == Some(&protocol)
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
    }
}

impl OutboundExchange for FakeOutbound {
    fn take_response(&mut self, session: OutboundSession) -> Option<Vec<u8>> {
        self.responses.get_mut(&session.0)?.pop_front()
    }
}

/// 恒定归因器。
pub struct FixedClassifier {
    /// 恒定返回的归属；`None` 表示「无归属」。
    pub attribution: Option<Attribution>,
}

impl Classifier for FixedClassifier {
    type Attribution = Attribution;
    type Error = String;

    fn classify(&mut self, _info: &PacketInfo) -> Result<Option<Attribution>, String> {
        Ok(self.attribution)
    }
}

/// 构造一条 IPv4+TCP 报文（对端 → 本端），带正确的 IP 与 TCP 校验和。
///
/// 伪首部的源/目的与 IP 头一致（对端 → 本端），这样报文能通过
/// `checksum::verify`——本入口的 ① 步会先校验，校验不过的一律丢弃。
pub fn tcp_packet(seq: u32, ack: u32, flags: Flags, payload: &[u8]) -> Vec<u8> {
    let pseudo = pseudo_v4((20 + payload.len()) as u16);
    let segment = segment::build(
        REMOTE_PORT,
        LOCAL_PORT,
        seq,
        ack,
        flags,
        4096,
        &[],
        payload,
        &pseudo,
    )
    .expect("段应可构造");
    let total = 20 + segment.len();
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&REMOTE.octets());
    packet[16..20].copy_from_slice(&LOCAL.octets());
    packet[10..12].copy_from_slice(&0u16.to_be_bytes());
    let header_sum = !ones_complement_sum(&[&packet[..20]]);
    packet[10..12].copy_from_slice(&header_sum.to_be_bytes());
    packet[20..].copy_from_slice(&segment);
    packet
}

/// RFC 1071 一补码和（测试侧自算；库内的等价函数是 crate 私有）。
fn ones_complement_sum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for part in parts {
        let mut index = 0;
        while index + 1 < part.len() {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([part[index], part[index + 1]])));
            index += 2;
        }
        if let Some(odd) = part.get(index) {
            sum = sum.wrapping_add(u32::from(*odd) << 8);
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    (sum & 0xffff) as u16
}

/// IPv4 伪首部（12 字节）：源 = 对端，目的 = 本端。
fn pseudo_v4(len: u16) -> [u8; 12] {
    let mut p = [0u8; 12];
    p[0..4].copy_from_slice(&REMOTE.octets());
    p[4..8].copy_from_slice(&LOCAL.octets());
    p[9] = 6;
    p[10..12].copy_from_slice(&len.to_be_bytes());
    p
}

/// 默认的权威布置。
pub fn authority() -> FakeAuthority {
    FakeAuthority {
        environment: 7,
        device: 70,
        epoch: 3,
    }
}

/// 构造一份合法的配置（`10.0.0.0/24` → 接口 7，源地址 `10.0.0.1`）。
pub fn route_rule() -> crate::runtime_entry::RouteRule {
    crate::runtime_entry::RouteRule {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        interface_index: 7,
        source: IpAddr::V4(LOCAL),
    }
}

/// 构造一份合法的配置。
pub fn config() -> crate::runtime_entry::RuntimeConfig {
    crate::runtime_entry::RawConfig {
        device_name: Some("lstest0".to_string()),
        mtu: Some(1500),
        routes: vec![route_rule()],
        ..crate::runtime_entry::RawConfig::default()
    }
    .into_config()
    .expect("配置应合法")
}
