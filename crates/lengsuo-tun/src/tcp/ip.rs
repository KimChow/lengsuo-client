//! IP 头部定位与回包构造：把 [`SendSegment`] 编成一个完整的 IP 报文。
//!
//! 与 `packet.rs`（只读解析）互补：这里是**写**侧，负责「定位入站报文的 TCP 段首」
//! 与「组装出站 IP 头 + TCP 段」。IP 头部一律本模块自建（IPv4 IHL=5、IPv6 固定 40），
//! 校验和复用 [`crate::checksum::ones_complement_sum`]，TCP 段交给
//! [`super::segment::build`]——本模块不重写第二份 TCP 校验和实现。
//!
//! fail-closed：任何长度换算溢出、地址族不匹配或段长非法都返回
//! [`super::listener::Error::ReplyLength`]，绝不 panic、不越界写。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::checksum;

use super::listener::Error;
use super::segment;
use super::state::SendSegment;

/// IPv4 头部固定长度（本栈不发选项）。
const IPV4_HEADER: usize = 20;
/// IPv6 固定头部长度。
const IPV6_HEADER: usize = 40;
/// TCP 协议号。
const PROTOCOL_TCP: u8 = 6;
/// 出站 IPv4 头部：本栈恒用 IHL=5。
const IPV4_IHL: u8 = 0x45;
/// 出站 IPv4 的标志位：DF（不分片）。
const IPV4_FLAG_DF: u16 = 0x4000;
/// 出站报文跳数/存活时间。
const HOP_LIMIT: u8 = 64;
/// IPv4 IHL 字段的低位掩码，单位为 4 字节。
const IHL_MASK: u8 = 0x0f;
/// IHL 字段的单位字节数。
const IHL_UNIT: usize = 4;
/// 地址族不匹配或长度非法时使用的冗余标记。
const NO_PAYLOAD: usize = 0;

/// 由入站报文算出 TCP 段起始偏移：IPv4 为 IHL×4，IPv6 为固定 40。
///
/// `payload_offset` 只用于**校验**段首不晚于声称的载荷位置（防御性检查，正常情形下
/// 段首 + TCP 头部长度 == payload_offset）。返回值来自报文自身的版本与 IHL 字段，
/// 已由 `packet::inspect` 核对过取值范围。
pub(super) fn tcp_segment_start(ip_packet: &[u8], payload_offset: usize) -> Option<usize> {
    let first = *ip_packet.first()?;
    let start = match first >> 4 {
        4 => usize::from(first & IHL_MASK) * IHL_UNIT,
        6 => IPV6_HEADER,
        _ => return None,
    };
    if start == 0 || start > payload_offset || payload_offset > ip_packet.len() {
        return None;
    }
    Some(start)
}

/// 构造单个回包：IP 头部 + 用 [`segment::build`] 生成的 TCP 段。
///
/// 地址方向相对入站报文对调：源 = 本端，目的 = 对端；端口同样对调。两个地址必须同族。
pub(super) fn reply(
    local: std::net::IpAddr,
    peer: std::net::IpAddr,
    local_port: u16,
    peer_port: u16,
    s: &SendSegment,
) -> Result<Vec<u8>, Error> {
    match (local, peer) {
        (IpAddr::V4(local), IpAddr::V4(peer)) => build_ipv4(local, peer, local_port, peer_port, s),
        (IpAddr::V6(local), IpAddr::V6(peer)) => build_ipv6(local, peer, local_port, peer_port, s),
        // 地址族不一致的键只作哈希用，不构成真实会话；回包时按拒绝处理。
        _ => Err(Error::ReplyLength(NO_PAYLOAD)),
    }
}

/// 组装 IPv4 回包：20 字节固定头部（无选项）+ TCP 段。
fn build_ipv4(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    s: &SendSegment,
) -> Result<Vec<u8>, Error> {
    // 伪首部的长度字段必须是**段长**（不含 IP 头部），因此先算段长再构造段。
    let seg_len = segment::MIN_HEADER
        .checked_add(s.payload.len())
        .and_then(|n| u16::try_from(n).ok())
        .ok_or(Error::ReplyLength(s.payload.len()))?;
    let pseudo = pseudo_v4(source, destination, seg_len);
    let tcp = segment::build(
        source_port,
        destination_port,
        s.seq,
        s.ack,
        s.flags,
        s.window,
        &[],
        &s.payload,
        &pseudo,
    )
    .map_err(|_| Error::ReplyLength(s.payload.len()))?;
    let total = IPV4_HEADER
        .checked_add(tcp.len())
        .ok_or(Error::ReplyLength(tcp.len()))?;
    let total_u16 = u16::try_from(total).map_err(|_| Error::ReplyLength(total))?;
    let mut packet = vec![0u8; total];
    packet[0] = IPV4_IHL;
    packet[1] = 0; // DSCP/ECN
    packet[2..4].copy_from_slice(&total_u16.to_be_bytes());
    packet[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    packet[6..8].copy_from_slice(&IPV4_FLAG_DF.to_be_bytes());
    packet[8] = HOP_LIMIT;
    packet[9] = PROTOCOL_TCP;
    packet[10..12].copy_from_slice(&0u16.to_be_bytes()); // 头部校验和稍后回填
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let header_sum = !checksum::ones_complement_sum(&[&packet[..IPV4_HEADER]]);
    packet[10..12].copy_from_slice(&header_sum.to_be_bytes());
    packet[IPV4_HEADER..].copy_from_slice(&tcp);
    Ok(packet)
}

/// 组装 IPv6 回包：40 字节固定头部 + TCP 段。
fn build_ipv6(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    s: &SendSegment,
) -> Result<Vec<u8>, Error> {
    let seg_len = segment::MIN_HEADER
        .checked_add(s.payload.len())
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(Error::ReplyLength(s.payload.len()))?;
    let pseudo = pseudo_v6(source, destination, seg_len);
    let tcp = segment::build(
        source_port,
        destination_port,
        s.seq,
        s.ack,
        s.flags,
        s.window,
        &[],
        &s.payload,
        &pseudo,
    )
    .map_err(|_| Error::ReplyLength(s.payload.len()))?;
    let payload_len = u16::try_from(tcp.len()).map_err(|_| Error::ReplyLength(tcp.len()))?;
    let mut packet = vec![0u8; IPV6_HEADER + tcp.len()];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    packet[6] = PROTOCOL_TCP;
    packet[7] = HOP_LIMIT;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[IPV6_HEADER..].copy_from_slice(&tcp);
    Ok(packet)
}

/// IPv4 TCP 伪首部（12 字节）：源/目的地址、零字节、协议号、16 位段长。
fn pseudo_v4(source: Ipv4Addr, destination: Ipv4Addr, len: u16) -> [u8; 12] {
    let mut p = [0u8; 12];
    p[0..4].copy_from_slice(&source.octets());
    p[4..8].copy_from_slice(&destination.octets());
    p[9] = PROTOCOL_TCP;
    p[10..12].copy_from_slice(&len.to_be_bytes());
    p
}

/// IPv6 TCP 伪首部（40 字节）。
fn pseudo_v6(source: Ipv6Addr, destination: Ipv6Addr, len: u32) -> [u8; 40] {
    let mut p = [0u8; 40];
    p[0..16].copy_from_slice(&source.octets());
    p[16..32].copy_from_slice(&destination.octets());
    p[32..36].copy_from_slice(&len.to_be_bytes());
    p[39] = PROTOCOL_TCP;
    p
}

#[cfg(test)]
mod tests {
    use super::super::segment::Flags;
    use super::*;

    fn send(flags: Flags, payload: &[u8]) -> SendSegment {
        SendSegment {
            seq: 1,
            ack: 2,
            flags,
            window: 4096,
            payload: payload.to_vec(),
        }
    }

    /// 组装的 IPv4 回包必须能被 `packet::inspect` 与 `checksum::verify` 双双接受。
    #[test]
    fn ipv4_reply_round_trips_through_verify() {
        let packet = reply(
            Ipv4Addr::new(10, 0, 0, 1).into(),
            Ipv4Addr::new(10, 0, 0, 2).into(),
            8080,
            40000,
            &send(Flags::SYN | Flags::ACK, &[]),
        )
        .unwrap();
        let info = checksum::verify(&packet).unwrap();
        assert_eq!((info.source_port, info.destination_port), (8080, 40000));
        assert_eq!(info.payload_offset, IPV4_HEADER + segment::MIN_HEADER);
        // 段首定位与 inspect 的载荷偏移一致（段首 + 20 == 载荷偏移）。
        assert_eq!(tcp_segment_start(&packet, info.payload_offset), Some(20));
    }

    /// 载荷非空时伪首部长度字段必须跟着段长走，否则 verify 会拒。
    #[test]
    fn ipv4_reply_with_payload_verifies() {
        let packet = reply(
            Ipv4Addr::new(10, 0, 0, 1).into(),
            Ipv4Addr::new(10, 0, 0, 2).into(),
            1,
            2,
            &send(Flags::ACK | Flags::PSH, b"payload"),
        )
        .unwrap();
        let info = checksum::verify(&packet).unwrap();
        // 载荷偏移 = IP 头 20 + TCP 头 20，与载荷长度无关；总长再含 7 字节载荷。
        assert_eq!(info.payload_offset, IPV4_HEADER + segment::MIN_HEADER);
        assert_eq!(packet.len(), IPV4_HEADER + segment::MIN_HEADER + 7);
    }

    /// IPv6 回包同样必须通过校验和验证。
    #[test]
    fn ipv6_reply_verifies() {
        let packet = reply(
            Ipv6Addr::LOCALHOST.into(),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).into(),
            443,
            5000,
            &send(Flags::ACK, b"hi"),
        )
        .unwrap();
        let info = checksum::verify(&packet).unwrap();
        assert_eq!((info.source_port, info.destination_port), (443, 5000));
        assert_eq!(tcp_segment_start(&packet, info.payload_offset), Some(40));
    }

    /// 地址族不匹配与非法段首定位都必须拒绝，不 panic。
    #[test]
    fn mismatched_family_and_bad_offsets_are_rejected() {
        let (v4, v6) = (Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into());
        assert!(reply(v4, v6, 1, 2, &send(Flags::ACK, &[])).is_err());
        assert!(reply(v6, v4, 1, 2, &send(Flags::ACK, &[])).is_err());
        // 段首晚于声明的载荷偏移、或偏移越过报文长度，一律 None。
        let packet = reply(v4, v4, 1, 2, &send(Flags::ACK, &[])).unwrap();
        assert_eq!(tcp_segment_start(&packet, 19), None);
        assert_eq!(tcp_segment_start(&packet, usize::MAX), None);
        assert_eq!(tcp_segment_start(&[], 20), None);
    }
}
