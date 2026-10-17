//! IP 层对接：把设备喂进来的裸 IP 报文拆成「五元组 + TCP 段」。
//!
//! 复用兄弟模块 [`crate::packet`] 做 IP 头部解析（它只读头部元数据，
//! 不改写字节），本模块负责定位 L4 载荷、校验 TCP 校验和，并在校验失败时
//! **fail-closed**：一律拒收，不返回"看起来能用"的段。
//!
//! # 校验和的覆盖范围
//!
//! TCP 校验和覆盖「伪首部 + TCP 段」。伪首部里的源/目的地址与协议号来自
//! IP 首部，而 IP 首部自带的头部校验和**不覆盖 TCP 段**，所以 TCP 校验和
//! 与 IP 头部是否正确是两件事：本模块只验前者。IP 头部完整性由
//! `checksum::verify_ipv4_header` 单独提供，接到真实设备上时应一并调用
//! （见 [`Inbound::verify_ip_header_checksum`]）。
//!
//! # 分片
//!
//! IPv4 分片（MF 置位或偏移非零）里只有首片带 TCP 头部，其余片没有端口。
//! 本阶段**不做 IP 重组**，遇到分片直接丢弃并计数（`DropReason::IpFragment`）。
//! IPv6 的逐跳扩展头同样不解析，非首个扩展头时按无法定位 L4 丢弃。

use crate::checksum::{self, TcpPorts};
use crate::packet::{self, PacketInfo};
use crate::tcp::segment::{Error as SegmentError, TcpSegment};

/// 一段入站数据最多检查的字节数。超过这个长度的输入视为非 IP 报文，
/// 与 [`packet::MAX_PACKET_LEN`] 保持一致。
pub const MAX_IP_PACKET_LEN: usize = packet::MAX_PACKET_LEN;

/// fail-closed 的丢弃原因。每个都对应一个可观测计数。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// IP 头部本身非法（版本/长度/截断）。附带底层错误文本。
    MalformedIp(&'static str),
    /// 非 TCP 承载协议（UDP / ICMP / …）。第一阶段只服务 TCP。
    NotTcp(u8),
    /// IPv4 分片或 IPv6 扩展头链，本阶段不重组。
    IpFragment,
    /// L4 载荷长度不足以放下最小 TCP 头部，或保留位/头部长度不自洽。
    MalformedTcp,
    /// TCP 校验和不匹配（含伪首部不一致）。
    Checksum,
}

/// 一条已定位到 TCP 段的入站报文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    /// IP 层元数据（含五元组与地址字节串）。
    pub info: PacketInfo,
    /// TCP 段的**借用视图**：指向入站缓冲，不拥有字节。
    pub segment: TcpSegment<'static>,
    /// L4 载荷在原始缓冲中的起始偏移。构造响应时需要复制这段字节。
    pub payload_offset: usize,
    /// L4 载荷长度（含 TCP 头部）。
    pub payload_len: usize,
}

impl Inbound {
    /// 从原始 IP 报文解析。任何不一致都返回 `None` 并给出原因，绝不 panic。
    ///
    /// 返回的 `Inbound` 借用 `packet`，因此生命周期与输入绑定；
    /// 需要跨越 borrow 边界时先 [`TcpSegment::to_owned`]。
    pub fn parse(packet: &[u8]) -> Result<Self, DropReason> {
        if packet.len() > MAX_IP_PACKET_LEN {
            return Err(DropReason::MalformedIp("oversized"));
        }
        let info = packet::inspect(packet).map_err(|e| DropReason::MalformedIp(e.code()))?;

        // 分片一律不处理：非首片没有 TCP 头部，首片也没有完整段。
        if info.fragment {
            return Err(DropReason::IpFragment);
        }

        if info.protocol != 6 {
            return Err(DropReason::NotTcp(info.protocol));
        }

        // `packet::inspect` 已保证 l4_offset 落在头部之后且头部合法。
        let l4_offset = match info.l4_offset {
            Some(o) if (o as usize) <= packet.len() => o as usize,
            _ => return Err(DropReason::MalformedIp("missing-l4-offset")),
        };
        let payload = &packet[l4_offset..];

        let segment = TcpSegment::parse(payload).ok_or(if payload.len() < 20 {
            DropReason::MalformedTcp
        } else {
            DropReason::MalformedTcp
        })?;

        // 校验和必须覆盖伪首部 + 整段。伪首部长度用实际载荷长度，
        // 与发送端 `checksum::tcp_checksum` 对称。
        let ports = TcpPorts {
            source: info.source_port.unwrap_or(segment.header.source),
            destination: info.destination_port.unwrap_or(segment.header.destination),
        };
        if !checksum::verify_tcp(&info, &ports, payload) {
            return Err(DropReason::Checksum);
        }

        Ok(Inbound {
            info,
            // 安全性：见下方「为何能用 transmute 延长生命周期」。
            segment: unsafe { extend_lifetime(segment) },
            payload_offset: l4_offset,
            payload_len: payload.len(),
        })
    }

    /// 校验 IPv4 头部校验和；IPv6 无头部校验和，恒为 `true`。
    /// 接到真实设备时应在 [`Inbound::parse`] 之前调用。
    pub fn verify_ip_header_checksum(&self, packet: &[u8]) -> bool {
        checksum::verify_ipv4_header(packet)
    }

    /// 段载荷（TCP 头部之后的应用字节）。借用**原始报文**而非内部视图，
    /// 这样即使 `Inbound` 已通过 transmute 延长生命周期，载荷读取仍然
    /// 由调用方传入的缓冲的真实生命周期约束。
    pub fn payload<'a>(&self, packet: &'a [u8]) -> Option<&'a [u8]> {
        let start = self.payload_offset + self.segment.header.data_offset as usize;
        let end = self.payload_offset + self.payload_len;
        if start > end || end > packet.len() {
            return None;
        }
        Some(&packet[start..end])
    }

    /// 该流的本端方向：入站段的源地址/端口是远端，目的地址/端口是本端。
    pub fn endpoint(&self) -> Option<crate::tcp::listener::Endpoint<'_>> {
        use crate::tcp::listener::Endpoint;
        let (sa, da) = match &self.info.source {
            packet::IpAddr::V4(s) => match &self.info.destination {
                packet::IpAddr::V4(d) => (
                    std::net::IpAddr::V4(*s),
                    std::net::IpAddr::V4(*d),
                ),
                _ => return None,
            },
            packet::IpAddr::V6(s) => match &self.info.destination {
                packet::IpAddr::V6(d) => (std::net::IpAddr::V6(*s), std::net::IpAddr::V6(*d)),
            },
        };
        Some(Endpoint {
            remote: (sa, self.info.source_port?),
            local: (da, self.info.destination_port?),
        })
    }

    /// 反向五元组（本端 → 远端），用于把响应写回同一条流。
    pub fn flow(&self) -> Option<checksum::Flow<'_>> {
        let ep = self.endpoint()?;
        Some(checksum::Flow {
            source: ep.local,
            destination: ep.remote,
        })
    }

    /// 丢弃原因的稳定文本，供计数与诊断。`MalformedIp` 内嵌原因码，
    /// 其余分支给出本模块的说明。
    pub fn reason_text(reason: DropReason) -> &'static str {
        match reason {
            DropReason::MalformedIp(c) => c,
            DropReason::NotTcp(_) => "not-tcp",
            DropReason::IpFragment => "ip-fragment",
            DropReason::MalformedTcp => "malformed-tcp",
            DropReason::Checksum => "checksum",
        }
    }
}

/// 把 `TcpSegment<'a>` 视图转成 `TcpSegment<'static>`。
///
/// # Safety
///
/// 视图本身**从不被解引用**：`TcpSegment` 的 `flags`/`options`/`payload()`
/// 在 `parse` 阶段已把用到的字节复制进 `flags` 与定宽数组，剩下唯一的
/// 借用是 `raw: &'a [u8]`。`raw` 只在调用方仍持有同一缓冲时被使用，
/// 而 `Inbound::payload` 刻意要求重新传入原始缓冲，因此读取的生命周期
/// 由该实参约束，而非这里伪造的 `'static`。
///
/// 若将来给 `TcpSegment` 增加任何按 `raw` 解引用的方法，必须同时删除
/// 本函数。
unsafe fn extend_lifetime<'a>(segment: TcpSegment<'a>) -> TcpSegment<'static> {
    std::mem::transmute::<TcpSegment<'a>, TcpSegment<'static>>(segment)
}

/// 出站：把构造好的 TCP 段包进一个最小 IP 报文。
///
/// 生成的是**完整可投递的裸 IP 报文**（含 IP 头部与 TCP 校验和），
/// 与 TAP/TUN 语义一致：写向 TUN 字符设备的就是裸 IP 报文，
/// 不补以太网首部。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

/// 封装一个 IPv4 报文。`ip_id` 由调用方提供以保证可重现。
pub fn encapsulate_ipv4(
    flow: &checksum::Flow<'_>,
    ip_id: u16,
    ttl: u8,
    tcp: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    if tcp.len() > u16::MAX as usize - 40 {
        return Err(Error::TooLong);
    }
    if tcp.is_empty() {
        return Err(Error::EmptySegment);
    }
    let (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) = (flow.source.0, flow.destination.0)
    else {
        return Err(Error::AddressFamily);
    };
    let total = 20 + tcp.len();
    out.reserve(total);
    let start = out.len();

    out.extend_from_slice(&[0x45, 0x00]);
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&ip_id.to_be_bytes());
    // 不分片：DF 置位、偏移为 0。
    out.extend_from_slice(&0x4000u16.to_be_bytes());
    out.push(ttl);
    out.push(6); // IPPROTO_TCP
    out.extend_from_slice(&[0, 0]); // 校验和占位
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());

    // 头部校验和。
    let cks = checksum::ipv4_header_checksum(&out[start..start + 20]);
    out[start + 10..start + 12].copy_from_slice(&cks.to_be_bytes());

    // TCP 校验和：段内偏移 16..18 清零后按伪首部计算。
    let seg_start = out.len();
    out.extend_from_slice(tcp);
    let ports = TcpPorts {
        source: flow.source.1,
        destination: flow.destination.1,
    };
    let info = PacketInfo {
        version: 4,
        source: packet::IpAddr::V4(src),
        destination: packet::IpAddr::V4(dst),
        protocol: 6,
        payload_len: (out.len() - seg_start) as u16,
        source_port: Some(ports.source),
        destination_port: Some(ports.destination),
        fragment: false,
        l4_offset: Some(seg_start as u32),
    };
    let body = &mut out[seg_start..];
    body[16] = 0;
    body[17] = 0;
    let value = checksum::tcp_checksum(&info, &ports, body);
    body[16..18].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

/// 封装一个 IPv6 报文。`payload_len` 即 TCP 段长度（IPv6 不含头部）。
pub fn encapsulate_ipv6(
    flow: &checksum::Flow<'_>,
    hop_limit: u8,
    tcp: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    if tcp.len() > u16::MAX as usize {
        return Err(Error::TooLong);
    }
    if tcp.is_empty() {
        return Err(Error::EmptySegment);
    }
    let (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) = (flow.source.0, flow.destination.0)
    else {
        return Err(Error::AddressFamily);
    };
    out.reserve(40 + tcp.len());
    let start = out.len();

    // 版本 6、Traffic Class 0、Flow Label 0。
    out.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    out.push(6); // Next Header = TCP
    out.push(hop_limit);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());

    let seg_start = out.len();
    out.extend_from_slice(tcp);
    let ports = TcpPorts {
        source: flow.source.1,
        destination: flow.destination.1,
    };
    let info = PacketInfo {
        version: 6,
        source: packet::IpAddr::V6(src),
        destination: packet::IpAddr::V6(dst),
        protocol: 6,
        payload_len: (out.len() - seg_start) as u16,
        source_port: Some(ports.source),
        destination_port: Some(ports.destination),
        fragment: false,
        l4_offset: Some(seg_start as u32),
    };
    let body = &mut out[seg_start..];
    body[16] = 0;
    body[17] = 0;
    let value = checksum::tcp_checksum(&info, &ports, body);
    body[16..18].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

/// 封装失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    TooLong,
    EmptySegment,
    AddressFamily,
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::TooLong => "too-long",
            Error::EmptySegment => "empty-segment",
            Error::AddressFamily => "address-family",
        }
    }
}

/// 把 [`crate::tcp::segment::Error`] 映射为丢弃原因，供调用方统一计数。
impl From<SegmentError> for DropReason {
    fn from(value: SegmentError) -> Self {
        match value {
            SegmentError::TooShort => DropReason::MalformedTcp,
            SegmentError::HeaderLength => DropReason::MalformedTcp,
            SegmentError::Checksum => DropReason::Checksum,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::segment::Flag;

    fn v4_flow() -> checksum::Flow<'static> {
        checksum::Flow {
            source: ("10.0.0.1".parse().unwrap(), 12345),
            destination: ("10.0.0.2".parse().unwrap(), 443),
        }
    }

    fn build_segment(f: &checksum::Flow<'_>, flags: &[Flag], seq: u32, ack: u32) -> Vec<u8> {
        let s = TcpSegment::build(f, flags, seq, ack, 65535, 0, &[]);
        let owned = s.to_owned();
        owned.segment().to_vec()
    }

    #[test]
    fn parse_round_trips_ipv4() {
        let f = v4_flow();
        let seg = build_segment(&f, &[Flag::Syn], 1000, 0);
        let mut pkt = Vec::new();
        encapsulate_ipv4(&f, 7, 64, &seg, &mut pkt).unwrap();

        let inb = Inbound::parse(&pkt).expect("合法 v4 报文应解析成功");
        assert_eq!(inb.info.version, 4);
        assert!(!inb.info.fragment);
        assert_eq!(inb.info.protocol, 6);
        assert!(inb.segment.header.flags.iter().any(|x| *x == Flag::Syn));
        assert_eq!(inb.segment.header.sequence, 1000);
        assert_eq!(inb.segment.flags(), inb.segment.header.flags_slice());
        assert!(inb.verify_ip_header_checksum(&pkt));
        let ep = inb.endpoint().unwrap();
        assert_eq!(ep.remote.1, f.source.1);
        assert_eq!(ep.local.1, f.destination.1);
        assert_eq!(inb.payload(&pkt), Some(&[][..]));
    }

    #[test]
    fn bad_tcp_checksum_is_rejected() {
        let f = v4_flow();
        let seg = build_segment(&f, &[Flag::Syn], 1000, 0);
        let mut pkt = Vec::new();
        encapsulate_ipv4(&f, 7, 64, &seg, &mut pkt).unwrap();
        let l4 = Inbound::parse(&pkt).unwrap().payload_offset;
        pkt[l4 + 16] ^= 0xff;
        assert_eq!(Inbound::parse(&pkt), Err(DropReason::Checksum));
    }

    #[test]
    fn udp_is_not_accepted() {
        let f = v4_flow();
        let seg = build_segment(&f, &[Flag::Syn], 1000, 0);
        let mut pkt = Vec::new();
        encapsulate_ipv4(&f, 7, 64, &seg, &mut pkt).unwrap();
        // 改协议号为 UDP 并重算头部校验和。
        pkt[9] = 17;
        pkt[10] = 0;
        pkt[11] = 0;
        let cks = checksum::ipv4_header_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&cks.to_be_bytes());
        match Inbound::parse(&pkt) {
            Err(DropReason::NotTcp(17)) => {}
            other => panic!("expected NotTcp(17), got {other:?}"),
        }
    }

    #[test]
    fn fragment_is_dropped() {
        let f = v4_flow();
        let seg = build_segment(&f, &[Flag::Syn], 1000, 0);
        let mut pkt = Vec::new();
        encapsulate_ipv4(&f, 7, 64, &seg, &mut pkt).unwrap();
        pkt[6] = 0x20; // MF 置位
        pkt[10] = 0;
        pkt[11] = 0;
        let cks = checksum::ipv4_header_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&cks.to_be_bytes());
        assert_eq!(Inbound::parse(&pkt), Err(DropReason::IpFragment));
    }

    #[test]
    fn truncated_ip_is_rejected() {
        let f = v4_flow();
        let seg = build_segment(&f, &[Flag::Syn], 1000, 0);
        let mut pkt = Vec::new();
        encapsulate_ipv4(&f, 7, 64, &seg, &mut pkt).unwrap();
        pkt.truncate(30); // 头部说 60 总长，实际 30
        assert!(matches!(
            Inbound::parse(&pkt),
            Err(DropReason::MalformedIp("truncated"))
        ));
    }

    #[test]
    fn non_ip_is_rejected() {
        assert_eq!(
            Inbound::parse(&[0xff, 0xff, 0, 1, 2, 3]),
            Err(DropReason::MalformedIp("unsupported-version"))
        );
    }

    #[test]
    fn short_tcp_payload_is_rejected() {
        let f = v4_flow();
        let mut pkt = Vec::new();
        // 手工造一个 10 字节的 TCP 载荷。
        let fake = [0u8; 10];
        let seg_start = {
            let (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) =
                (f.source.0, f.destination.0)
            else {
                unreachable!()
            };
            pkt.extend_from_slice(&[0x45, 0x00]);
            pkt.extend_from_slice(&((20 + fake.len()) as u16).to_be_bytes());
            pkt.extend_from_slice(&[0, 0]);
            pkt.extend_from_slice(&0x4000u16.to_be_bytes());
            pkt.extend_from_slice(&[64, 6, 0, 0]);
            pkt.extend_from_slice(&src.octets());
            pkt.extend_from_slice(&dst.octets());
            let cks = checksum::ipv4_header_checksum(&pkt[..20]);
            pkt[10..12].copy_from_slice(&cks.to_be_bytes());
            pkt.len()
        };
        pkt.extend_from_slice(&fake);
        let _ = seg_start;
        assert_eq!(Inbound::parse(&pkt), Err(DropReason::MalformedTcp));
    }

    #[test]
    fn ipv6_round_trip_and_checksum() {
        let f = checksum::Flow {
            source: ("fe80::1".parse().unwrap(), 12345),
            destination: ("fe80::2".parse().unwrap(), 443),
        };
        let seg = build_segment(&f, &[Flag::Syn, Flag::Ack], 5, 9);
        let mut pkt = Vec::new();
        encapsulate_ipv6(&f, 64, &seg, &mut pkt).unwrap();
        let inb = Inbound::parse(&pkt).expect("v6 应解析成功");
        assert_eq!(inb.info.version, 6);
        assert_eq!(inb.segment.header.sequence, 5);
        assert!(inb.verify_ip_header_checksum(&pkt));
    }

    #[test]
    fn ipv6_bad_checksum_is_rejected() {
        let f = checksum::Flow {
            source: ("fe80::1".parse().unwrap(), 12345),
            destination: ("fe80::2".parse().unwrap(), 443),
        };
        let seg = build_segment(&f, &[Flag::Syn], 5, 0);
        let mut pkt = Vec::new();
        encapsulate_ipv6(&f, 64, &seg, &mut pkt).unwrap();
        let l4 = 40;
        pkt[l4 + 17] ^= 0x01;
        assert_eq!(Inbound::parse(&pkt), Err(DropReason::Checksum));
    }

    #[test]
    fn v4_v6_pseudo_headers_are_not_interchangeable() {
        // 同端口的段在 v4 / v6 下校验和不同：跨家族误用应当被拒收。
        let v4f = v4_flow();
        let seg = build_segment(&v4f, &[Flag::Syn], 1000, 0);
        let mut v6 = Vec::new();
        let f6 = checksum::Flow {
            source: ("::1".parse().unwrap(), 12345),
            destination: ("::2".parse().unwrap(), 443),
        };
        encapsulate_ipv6(&f6, 64, &seg, &mut v6).unwrap();
        assert_eq!(Inbound::parse(&v6), Err(DropReason::Checksum));
    }

    #[test]
    fn encapsulate_rejects_empty_and_mismatched_family() {
        let f = v4_flow();
        let mut out = Vec::new();
        assert_eq!(
            encapsulate_ipv4(&f, 1, 64, &[], &mut out),
            Err(Error::EmptySegment)
        );
        let f6 = checksum::Flow {
            source: ("::1".parse().unwrap(), 1),
            destination: ("::2".parse().unwrap(), 2),
        };
        assert_eq!(
            encapsulate_ipv4(&f6, 1, 64, &[0; 20], &mut out),
            Err(Error::AddressFamily)
        );
        let mut out = Vec::new();
        assert_eq!(
            encapsulate_ipv6(&f, 64, &[0; 20], &mut out),
            Err(Error::AddressFamily)
        );
    }

    #[test]
    fn ip_header_checksum_is_checked_only_when_asked() {
        let f = v4_flow();
        let seg = build_segment(&f, &[Flag::Syn], 1000, 0);
        let mut pkt = Vec::new();
        encapsulate_ipv4(&f, 7, 64, &seg, &mut pkt).unwrap();
        // 破坏 IP 头部校验和字段：TCP 校验和仍有效，parse 应放行，
        // 但 verify_ip_header_checksum 必须报告失败。
        pkt[10] = pkt[10] ^ 0x01;
        let inb = Inbound::parse(&pkt).expect("TCP 校验和独立于 IP 头部校验和");
        assert!(!inb.verify_ip_header_checksum(&pkt));
    }

    #[test]
    fn drop_reason_text_is_stable() {
        assert_eq!(Inbound::reason_text(DropReason::Checksum), "checksum");
        assert_eq!(Inbound::reason_text(DropReason::IpFragment), "ip-fragment");
        assert_eq!(
            Inbound::reason_text(DropReason::MalformedIp("truncated")),
            "truncated"
        );
    }
}
