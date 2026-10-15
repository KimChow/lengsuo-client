//! 分类测试用的最小 IP 报文构造器：只造 `lengsuo-tun` 解析器能接受的合法头部。
//! 纯内存，不创建套接字、不碰任何真实设备。

#![allow(dead_code)]

use lengsuo_tun::packet::{inspect, PacketInfo};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

pub const fn v6(groups: [u16; 8]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(
        groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6], groups[7],
    ))
}

/// IPv4 头部一补码和：校验和字段先置零再求和，写入其反码。
fn ipv4_checksum(header: &mut [u8]) {
    header[10..12].copy_from_slice(&0u16.to_be_bytes());
    let mut sum: u32 = 0;
    for word in header.chunks(2) {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn tcp_segment(source_port: u16, destination_port: u16) -> Vec<u8> {
    let mut segment = vec![0; 20];
    segment[0..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[12] = 0x50; // data offset = 5
    segment[13] = 0x10; // ACK
    segment[14..16].copy_from_slice(&64_000u16.to_be_bytes());
    segment
}

fn udp_segment(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut segment = vec![0; 8];
    segment[0..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    let len = u16::try_from(8 + payload.len()).expect("UDP 载荷过长");
    segment[4..6].copy_from_slice(&len.to_be_bytes());
    segment.extend_from_slice(payload);
    segment
}

fn ipv4(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, l4: &[u8]) -> Vec<u8> {
    // 偏移 10..12 是校验和占位，必须排在源/目地址之前，否则整张头部错位。
    let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, protocol, 0, 0];
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&destination.octets());
    debug_assert_eq!(packet.len(), 20);
    let total = u16::try_from(packet.len() + l4.len()).expect("IPv4 报文过长");
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    ipv4_checksum(&mut packet);
    packet.extend_from_slice(l4);
    packet
}

fn ipv6(source: Ipv6Addr, destination: Ipv6Addr, protocol: u8, l4: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x60, 0, 0, 0, 0, 0, protocol, 64];
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&destination.octets());
    let len = u16::try_from(l4.len()).expect("IPv6 载荷过长");
    packet[4..6].copy_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(l4);
    packet
}

fn addr_bytes(addr: IpAddr) -> ([u8; 4], Option<[u8; 16]>) {
    match addr {
        IpAddr::V4(v4) => (v4.octets(), None),
        IpAddr::V6(v6) => ([0; 4], Some(v6.octets())),
    }
}

/// 造一个合法 TCP 报文（零载荷）。
pub fn tcp_packet(
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    let segment = tcp_segment(source_port, destination_port);
    let (v4src, v6src) = addr_bytes(source);
    let (v4dst, v6dst) = addr_bytes(destination);
    match (v6src, v6dst) {
        (Some(src), Some(dst)) => ipv6(
            Ipv6Addr::from(src),
            Ipv6Addr::from(dst),
            PROTO_TCP,
            &segment,
        ),
        (None, None) => ipv4(
            Ipv4Addr::from(v4src),
            Ipv4Addr::from(v4dst),
            PROTO_TCP,
            &segment,
        ),
        _ => panic!("IPv4 与 IPv6 不能混在同一个报文里"),
    }
}

/// 造一个合法 UDP 报文。
pub fn udp_packet(
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let segment = udp_segment(source_port, destination_port, payload);
    let (v4src, v6src) = addr_bytes(source);
    let (v4dst, v6dst) = addr_bytes(destination);
    match (v6src, v6dst) {
        (Some(src), Some(dst)) => ipv6(
            Ipv6Addr::from(src),
            Ipv6Addr::from(dst),
            PROTO_UDP,
            &segment,
        ),
        (None, None) => ipv4(
            Ipv4Addr::from(v4src),
            Ipv4Addr::from(v4dst),
            PROTO_UDP,
            &segment,
        ),
        _ => panic!("IPv4 与 IPv6 不能混在同一个报文里"),
    }
}

/// 解析成 tun 元数据；失败直接 panic（测试前置条件不成立）。
pub fn info(packet: &[u8]) -> PacketInfo {
    inspect(packet).expect("测试构造的报文应当可解析")
}

// ------- 分类与 DNS 用例共用的夹具 -------

use lengsuo_environment::{
    classify::Classifier, DeviceId, EnvironmentId, Router, Timestamp, DNS_PORT,
};
use std::time::Duration;
use tokio::time::timeout;

pub const CLIENT: IpAddr = v4(198, 51, 100, 7);
pub const SERVER: IpAddr = v4(203, 0, 113, 20);
pub const DNS_SERVER: IpAddr = v4(203, 0, 113, 53);
pub const V6_CLIENT: IpAddr = v6([0xfd00, 0, 0, 0, 0, 0, 0, 7]);
pub const V6_SERVER: IpAddr = v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
pub const V6_DNS: IpAddr = v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 53]);

pub const ENV_A: EnvironmentId = EnvironmentId(1);
pub const ENV_B: EnvironmentId = EnvironmentId(2);
pub const DEV_A: DeviceId = DeviceId(10);
pub const DEV_B: DeviceId = DeviceId(20);
pub const DEV_C: DeviceId = DeviceId(30);

pub const T0: Timestamp = Timestamp(1_000);
pub const IDLE: Duration = Duration::from_secs(10);
pub const HARD: Duration = Duration::from_secs(30);
/// 宽松保护：只防死锁或意外等待，不参与任何判定。
pub const SLACK: Duration = Duration::from_secs(5);

/// 在超时保护内运行一段纯内存逻辑，超时即判失败。
pub async fn guard<F: std::future::Future<Output = ()>>(body: F) {
    timeout(SLACK, body).await.expect("用例应在超时前完成");
}

/// 三台出口设备全部显式上线的权威路由。
pub fn online_router() -> Router {
    let mut router = Router::new().expect("路由实例应可创建");
    router.set_online(DEV_A, true);
    router.set_online(DEV_B, true);
    router.set_online(DEV_C, true);
    router
}

pub fn classifier() -> Classifier {
    Classifier::new(8, IDLE, HARD).expect("容量与 TTL 合法")
}

/// 出站 TCP 流的两个方向（同一五元组）。
pub fn tcp_pair(source: IpAddr, destination: IpAddr, sport: u16, dport: u16) -> (Vec<u8>, Vec<u8>) {
    (
        tcp_packet(source, destination, sport, dport),
        tcp_packet(destination, source, dport, sport),
    )
}

/// 发起查询与对应响应（同一会话键的两个方向）。
pub fn dns_pair(
    client: IpAddr,
    resolver: IpAddr,
    sport: u16,
    payload: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    (
        udp_packet(client, resolver, sport, DNS_PORT, payload),
        udp_packet(resolver, client, DNS_PORT, sport, payload),
    )
}
