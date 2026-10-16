//! 路径 MTU 判定与 PMTUD 错误报文测试：边界值、字节级字段与校验和断言。
//! 全部纯内存，不建设备、不发包；每个用例都在 timeout 与 blocking 线程的双重约束下
//! 运行。报文由测试侧独立构造，校验和用测试侧独立算法核对，不复用被测实现，
//! 因此这些断言只证明生成器与 RFC 描述一致，不代表真实链路或协议栈互通。

use lengsuo_tun::mtu::{
    carried_prefix, decide, decide_from, error_packet, Decision, Direction, Error, IpVersion,
    MAX_MTU_V4_FIELD, MIN_PATH_MTU_V4, MIN_PATH_MTU_V6,
};
use lengsuo_tun::packet::Error as PacketError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const SOURCE_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const DEST_V4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const NEXTHOP_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 254);
const SOURCE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const DEST_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
const NEXTHOP_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xfffe);

/// 测试侧独立的一补码和：逐字累加后立刻折叠进位，与被测的批量折叠写法不同。
fn ones_sum(bytes: &[u8]) -> u16 {
    let mut acc: u32 = 0;
    for pair in bytes.chunks(2) {
        let word = if pair.len() == 2 {
            u32::from(u16::from_be_bytes([pair[0], pair[1]]))
        } else {
            u32::from(pair[0]) << 8
        };
        acc = acc.wrapping_add(word);
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// 接收端核对：把含校验和字段的整段计入，结果必须为全 1。
fn verify(bytes: &[u8]) -> bool {
    ones_sum(bytes) == 0xffff
}

fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// 构造 IPv4 头部（DF、偏移 0），并重算头部校验和。
fn ipv4(ihl: usize, protocol: u8, source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
    let mut packet = vec![0u8; ihl * 4];
    packet[0] = 0x40 | ihl as u8;
    packet[1] = 0b1011_0000; // DSCP 22 / ECN 0，用于核对 TOS 复制
    let total_len = packet.len() as u16;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[4..6].copy_from_slice(&0x1122u16.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    for byte in packet.iter_mut().skip(20) {
        *byte = 0x01; // NOP 选项占位；选项整体计入头部校验和即可
    }
    refill_v4(&mut packet);
    packet
}

fn refill_v4(packet: &mut [u8]) {
    let header = usize::from(packet[0] & 0x0f) * 4;
    packet[10] = 0;
    packet[11] = 0;
    let checksum = !ones_sum(&packet[..header]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

/// 在已构造的 IPv4 头部后追加传输段，修正总长度与校验和。
fn append_v4(packet: &mut Vec<u8>, segment: &[u8]) {
    let header = usize::from(packet[0] & 0x0f) * 4;
    packet.truncate(header);
    let total = header + segment.len();
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet.extend_from_slice(segment);
    refill_v4(packet);
}

fn tcp(source_port: u16, destination_port: u16, body: usize) -> Vec<u8> {
    let mut segment = vec![0u8; 20 + body];
    segment[0..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[8..12].copy_from_slice(&0x0a1b_2c3du32.to_be_bytes()); // 序号：截取断言用
    segment[12] = 5 << 4;
    segment[13] = 0x18;
    segment[14..16].copy_from_slice(&0x2000u16.to_be_bytes()); // 窗口
    segment
}

fn udp(source_port: u16, destination_port: u16, body: usize) -> Vec<u8> {
    let mut segment = vec![0u8; 8 + body];
    segment[0..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[4..6].copy_from_slice(&((8 + body) as u16).to_be_bytes());
    segment
}

fn ipv6(next_header: u8, segment: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(segment.len() as u16).to_be_bytes());
    packet[6] = next_header;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&SOURCE_V6.octets());
    packet[24..40].copy_from_slice(&DEST_V6.octets());
    packet.extend_from_slice(segment);
    packet
}

fn v4_tcp(body: usize) -> Vec<u8> {
    let mut packet = ipv4(5, 6, SOURCE_V4, DEST_V4);
    append_v4(&mut packet, &tcp(5000, 443, body));
    packet
}

fn v6_tcp(body: usize) -> Vec<u8> {
    ipv6(6, &tcp(5000, 443, body))
}

// --------------------------------------------------------------- 判定边界

#[test]
fn ipv4_boundary_is_inclusive() {
    {
        // 恰等于 MTU 可发，超一字节过大。
        assert_eq!(
            decide(IpVersion::V4, 1500, 1500, Direction::Egress),
            Ok(Decision::Send)
        );
        assert_eq!(
            decide(IpVersion::V4, 1500, 1501, Direction::Egress),
            Ok(Decision::TooBig {
                mtu: 1500,
                packet_len: 1501,
                direction: Direction::Egress
            })
        );
        assert_eq!(
            decide(IpVersion::V4, 1500, 1, Direction::Ingress),
            Ok(Decision::Send)
        );
    }
}

#[test]
fn direction_decides_only_reportability() {
    {
        let too_big = decide(IpVersion::V6, 1400, 1401, Direction::Egress).expect("判定");
        assert!(too_big.may_report());
        assert_eq!(too_big.too_big(), Some((1400, 1401)));
        assert!(!too_big.is_send());
        let inbound = decide(IpVersion::V6, 1400, 1401, Direction::Ingress).expect("判定");
        assert_eq!(inbound.too_big(), Some((1400, 1401)), "长度结论与方向无关");
        assert!(!inbound.may_report(), "入站过大不得回报 PMTUD 错误");
        let send = decide(IpVersion::V4, 1500, 100, Direction::Egress).expect("判定");
        assert!(send.is_send() && !send.may_report() && send.too_big().is_none());
    }
}

#[test]
fn mtu_below_family_floor_is_rejected() {
    {
        assert_eq!(MIN_PATH_MTU_V4, 576);
        assert_eq!(MIN_PATH_MTU_V6, 1280);
        assert_eq!(IpVersion::V4.floor(), MIN_PATH_MTU_V4);
        assert_eq!(IpVersion::V6.floor(), MIN_PATH_MTU_V6);
        for mtu in [0u16, 575] {
            assert_eq!(
                decide(IpVersion::V4, mtu, 1500, Direction::Egress),
                Err(Error::MtuOutOfRange {
                    family: IpVersion::V4,
                    value: mtu
                }),
                "IPv4 MTU {mtu} 低于 RFC 1191 下限必须拒绝，不夹紧"
            );
        }
        for mtu in [0u16, 68, 1279] {
            assert_eq!(
                decide(IpVersion::V6, mtu, 2000, Direction::Egress),
                Err(Error::MtuOutOfRange {
                    family: IpVersion::V6,
                    value: mtu
                }),
                "IPv6 MTU {mtu} 低于 RFC 1981 下限必须拒绝"
            );
        }
        assert!(decide(IpVersion::V4, MIN_PATH_MTU_V4, 1, Direction::Egress).is_ok());
        assert!(decide(IpVersion::V6, MIN_PATH_MTU_V6, 1, Direction::Egress).is_ok());
    }
}

#[test]
fn packet_length_bounds_are_rejected() {
    {
        assert_eq!(
            decide(IpVersion::V4, 1500, 0, Direction::Egress),
            Err(Error::PacketLength(0))
        );
        assert_eq!(
            decide(IpVersion::V6, 1500, 65_536, Direction::Egress),
            Err(Error::PacketLength(65_536))
        );
        assert_eq!(
            decide(
                IpVersion::V4,
                u16::MAX,
                usize::from(u16::MAX),
                Direction::Egress
            ),
            Ok(Decision::Send)
        );
    }
}

#[test]
fn decide_from_reads_version_and_buffer_length() {
    {
        // v4_tcp(536) → 20B IP 头 + 20B TCP 头 + 536B 载荷 = 576B（IPv4 下限，
        // decide_from 的接口 MTU 校验与 decide 相同：低于下限显式失败）。
        let packet = v4_tcp(536);
        assert_eq!(packet.len(), 576);
        assert_eq!(
            decide_from(&packet, 576, Direction::Egress),
            Ok(Decision::Send),
            "恰等于 MTU 可发"
        );
        assert_eq!(
            decide_from(&packet, 575, Direction::Egress),
            Err(Error::MtuOutOfRange {
                family: IpVersion::V4,
                value: 575
            }),
            "接口 MTU 低于下限显式失败（与 decide 同策略）"
        );
        // v4_tcp(560) → 20+20+560 = 600B，超出 576 一个单元。
        assert_eq!(
            decide_from(&v4_tcp(560), 576, Direction::Egress),
            Ok(Decision::TooBig {
                mtu: 576,
                packet_len: 600,
                direction: Direction::Egress
            })
        );
        let v6 = v6_tcp(1220);
        assert_eq!(v6.len(), 1280);
        assert_eq!(
            decide_from(&v6, 1280, Direction::Ingress),
            Ok(Decision::Send),
            "入站只读长度，方向不影响判定"
        );
        // 版本 nibble 不是 4/6 一律拒绝，不按 IPv4 处理。
        let mut garbage = vec![0u8; 40];
        garbage[0] = 0x50;
        assert_eq!(
            decide_from(&garbage, 1500, Direction::Egress),
            Err(Error::Packet(PacketError::UnsupportedVersion))
        );
        assert_eq!(
            decide_from(&[], 1500, Direction::Egress),
            Err(Error::Packet(PacketError::Incomplete))
        );
    }
}

// ------------------------------------------------------------ IPv4 错误报文

#[test]
fn ipv4_error_packet_bytes_and_checksums() {
    {
        let original = v4_tcp(100);
        let packet = error_packet(&original, 1400, IpAddr::V4(NEXTHOP_V4)).expect("生成 IPv4 错误");
        // 20 字节外层头 + 8 字节 ICMP + (20 IP 头 + 8 TCP 头)。
        assert_eq!(packet.len(), 56);
        assert_eq!(
            u16::from_be_bytes([packet[2], packet[3]]) as usize,
            packet.len()
        );
        assert_eq!(packet[0], 0x45, "外层固定版本 4、IHL=5");
        assert_eq!(packet[1], original[1], "TOS 复制原报文");
        assert_eq!(&packet[4..8], &[0, 0, 0, 0], "标识、DF 与片偏移全部为零");
        assert_eq!(packet[8], 255);
        assert_eq!(packet[9], 1, "协议号 = ICMP");
        assert_eq!(&packet[12..16], &NEXTHOP_V4.octets(), "源为本链路地址");
        assert_eq!(&packet[16..20], &SOURCE_V4.octets(), "目的取自原报文源地址");
        assert!(verify(&packet[..20]), "外层 IPv4 头部校验和必须自洽");

        let icmp = 20;
        assert_eq!(packet[icmp], 3, "Destination Unreachable");
        assert_eq!(packet[icmp + 1], 4, "code 4 = 需要分片但设置了 DF");
        assert_ne!(be16(&packet[icmp + 2..icmp + 4]), 0, "校验和字段确被写入");
        assert_eq!(
            &packet[icmp + 4..icmp + 6],
            &[0, 0],
            "RFC 792 未用字段保持零"
        );
        assert_eq!(be16(&packet[icmp + 6..icmp + 8]), 1400, "Next-Hop MTU");
        assert!(verify(&packet[icmp..]), "ICMP 校验和覆盖整个消息");
        assert_eq!(
            &packet[icmp + 8..],
            &original[..28],
            "携带原 IP 头与前 8 字节（源地址在 12..16，序号在 TCP 头内）"
        );
        // 源地址与 TCP 序号起点都必须落在携带范围里（语义复核）。
        assert_eq!(&original[12..16], &SOURCE_V4.octets(), "原报文源地址");
        assert!(28 <= original.len(), "TCP 序号字段应在携带范围内");
    }
}

#[test]
fn ipv4_error_carries_options_and_transport_prefix() {
    {
        for ihl in [5usize, 6, 8, 15] {
            let mut original = ipv4(ihl, 6, SOURCE_V4, DEST_V4);
            append_v4(&mut original, &tcp(5000, 443, 10));
            let carried = ihl * 4 + 8;
            assert_eq!(
                carried_prefix(&original).expect("截取"),
                &original[..carried]
            );
            let packet = error_packet(&original, 576, IpAddr::V4(NEXTHOP_V4)).expect("生成");
            assert_eq!(packet.len(), 28 + carried);
            assert_eq!(be16(&packet[2..4]) as usize, packet.len());
            assert_eq!(&packet[28..], &original[..carried], "IP 选项必须随头部携带");
            assert!(verify(&packet[..20]) && verify(&packet[20..]));
            assert_eq!(be16(&packet[26..28]), 576);
        }
        // UDP 同样只截前 8 字节，不管载荷多长。
        let mut original = ipv4(5, 17, SOURCE_V4, DEST_V4);
        append_v4(&mut original, &udp(5000, 443, 900));
        assert_eq!(carried_prefix(&original).expect("截取").len(), 28);
        let packet = error_packet(&original, 1280, IpAddr::V4(NEXTHOP_V4)).expect("生成");
        assert_eq!(&packet[28..], &original[..28]);
        assert_eq!(
            be16(&packet[26..28]),
            1280,
            "MTU 落在 ICMP 头部的 16 位字段"
        );
        assert_eq!(&packet[20..22], &[3, 4], "type 3 / code 4");
        assert_eq!(&packet[24..26], &[0, 0], "RFC 792 未用字段保持零");
    }
}

#[test]
fn ipv4_next_hop_mtu_field_limits() {
    {
        let original = v4_tcp(100);
        // 低于下限直接拒绝，不夹紧到 576。
        assert_eq!(
            error_packet(&original, MIN_PATH_MTU_V4 - 1, IpAddr::V4(NEXTHOP_V4)),
            Err(Error::MtuOutOfRange {
                family: IpVersion::V4,
                value: 575
            })
        );
        // RFC 1191：Next-Hop MTU 字段最高位必须为 0，故 15 位上限可用。
        assert_eq!(
            error_packet(&original, MAX_MTU_V4_FIELD, IpAddr::V4(NEXTHOP_V4))
                .expect("32767 可用")
                .len(),
            56
        );
        for mtu in [32768u16, 60000, u16::MAX] {
            assert_eq!(
                error_packet(&original, mtu, IpAddr::V4(NEXTHOP_V4)),
                Err(Error::MtuOutOfRange {
                    family: IpVersion::V4,
                    value: mtu
                }),
                "MTU {mtu} 超出 15 位字段"
            );
        }
    }
}

// ------------------------------------------------------------ IPv6 错误报文

#[test]
fn ipv6_error_packet_bytes_and_checksums() {
    {
        let original = v6_tcp(400);
        let packet = error_packet(&original, 1280, IpAddr::V6(NEXTHOP_V6)).expect("生成 IPv6 错误");
        // 外层 40 + (ICMPv6 固定 8 + 前缀 48) = 96，载荷长度 56。
        assert_eq!(packet.len(), 96);
        assert_eq!(packet[0] & 0xf0, 0x60, "版本 nibble 之后补零");
        assert_eq!(be16(&packet[4..6]), 56, "载荷长度 = ICMPv6 消息长度");
        assert_eq!(packet[6], 58, "下一头 = ICMPv6");
        assert_eq!(packet[7], 255, "跳数上限");
        assert_eq!(&packet[8..24], &NEXTHOP_V6.octets());
        assert_eq!(&packet[24..40], &SOURCE_V6.octets(), "目的取自原报文源地址");

        let icmp = 40;
        assert_eq!(packet[icmp], 2, "Packet Too Big");
        assert_eq!(packet[icmp + 1], 0, "code 必须为 0");
        assert_eq!(be32(&packet[icmp + 4..icmp + 8]), 1280, "32 位 MTU 字段");
        assert_eq!(
            &packet[icmp + 8..],
            &original[..48],
            "携带 40 字节 IPv6 头加 8 字节 TCP 头"
        );

        // ICMPv6 校验和 = 伪首部 + 消息，测试侧独立复算并要求非零。
        let checksum = be16(&packet[icmp + 2..icmp + 4]);
        assert_ne!(checksum, 0, "IPv6 校验和不得为零");
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&NEXTHOP_V6.octets());
        bytes.extend_from_slice(&SOURCE_V6.octets());
        bytes.extend_from_slice(&((packet.len() - 40) as u32).to_be_bytes());
        bytes.extend_from_slice(&[0u8, 0, 0, 58]);
        bytes.extend_from_slice(&packet[icmp..]);
        assert_eq!(ones_sum(&bytes), 0xffff, "ICMPv6 伪首部校验和必须自洽");
    }
}

#[test]
fn ipv6_mtu_field_accepts_full_u16_range() {
    {
        let original = v6_tcp(0);
        // IPv6 的 MTU 字段是 32 位，u16 输入不需要 15 位裁剪；上下限都接受。
        for mtu in [MIN_PATH_MTU_V6, 1400, u16::MAX] {
            let packet = error_packet(&original, mtu, IpAddr::V6(NEXTHOP_V6)).expect("生成");
            assert_eq!(be32(&packet[44..48]), u32::from(mtu));
            assert_eq!(packet.len(), 96);
        }
        assert_eq!(
            error_packet(&original, MIN_PATH_MTU_V6 - 1, IpAddr::V6(NEXTHOP_V6)),
            Err(Error::MtuOutOfRange {
                family: IpVersion::V6,
                value: 1279
            })
        );
        assert_eq!(
            error_packet(&original, 1280, IpAddr::V4(SOURCE_V4)),
            Err(Error::SourceFamily),
            "错误源地址必须与原报文同族"
        );
    }
}

// ---------------------------------------------------------------- 拒绝路径

#[test]
fn non_tcp_udp_and_nested_errors_are_refused() {
    {
        // 对 ICMP/ICMPv6 错误报文再回错误会造成环路放大（RFC 1122），一律拒绝。
        let icmp_v6 = ipv6(58, &tcp(5000, 443, 8));
        assert_eq!(
            error_packet(&icmp_v6, 1280, IpAddr::V6(NEXTHOP_V6)),
            Err(Error::NotReportable)
        );
        assert_eq!(carried_prefix(&icmp_v6), Err(Error::NotReportable));
        let v4_icmp = ipv4(5, 1, SOURCE_V4, DEST_V4);
        assert_eq!(
            error_packet(&v4_icmp, 1400, IpAddr::V4(NEXTHOP_V4)),
            Err(Error::NotReportable)
        );
        assert_eq!(carried_prefix(&v4_icmp), Err(Error::NotReportable));
        // IGMP 与 GRE/ESP 等本 crate 不解析的协议同样拒绝。
        for protocol in [2u8, 47, 50, 132] {
            let packet = ipv4(5, protocol, SOURCE_V4, DEST_V4);
            assert_eq!(
                carried_prefix(&packet),
                Err(Error::NotReportable),
                "协议 {protocol}"
            );
        }
        // IPv6 扩展头与分片：不遍历、不重组，也不回报。
        for next_header in [0u8, 43, 44, 60] {
            let packet = ipv6(next_header, &tcp(1, 2, 8));
            assert_eq!(
                carried_prefix(&packet),
                Err(Error::NotReportable),
                "下一头 {next_header}"
            );
        }
    }
}

#[test]
fn truncated_and_malformed_originals_are_refused() {
    {
        // 头部之后不足 8 字节上层头部：无法按 RFC 截取。
        let mut short = ipv4(5, 6, SOURCE_V4, DEST_V4);
        append_v4(&mut short, &[0; 4]);
        assert_eq!(short.len(), 24);
        assert_eq!(carried_prefix(&short), Err(Error::IncompleteOriginal));
        assert_eq!(
            error_packet(&short, 1400, IpAddr::V4(NEXTHOP_V4)),
            Err(Error::IncompleteOriginal)
        );
        // 只有头部、没有传输段。
        assert_eq!(
            carried_prefix(&ipv4(5, 6, SOURCE_V4, DEST_V4)),
            Err(Error::IncompleteOriginal)
        );
        let mut v6_short = ipv6(6, &tcp(1, 2, 0)[..4]);
        assert_eq!(carried_prefix(&v6_short), Err(Error::IncompleteOriginal));
        v6_short.truncate(40);
        assert_eq!(carried_prefix(&v6_short), Err(Error::IncompleteOriginal));

        // 分片、长度字段不一致、坏校验和仍按 `packet` 的原始种类拒绝，绝不生成错误报文。
        let mut fragmented = v4_tcp(100);
        fragmented[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // MF
        refill_v4(&mut fragmented);
        assert_eq!(
            error_packet(&fragmented, 1400, IpAddr::V4(NEXTHOP_V4)),
            Err(Error::Packet(PacketError::Fragmented))
        );
        let mut bad_length = v4_tcp(100);
        bad_length[2] = 0;
        bad_length[3] = 1;
        assert_eq!(
            error_packet(&bad_length, 1400, IpAddr::V4(NEXTHOP_V4)),
            Err(Error::Packet(PacketError::TotalLength))
        );
        let mut bad_checksum = v4_tcp(100);
        bad_checksum[10] ^= 0xff;
        assert_eq!(
            error_packet(&bad_checksum, 1400, IpAddr::V4(NEXTHOP_V4)),
            Err(Error::Packet(PacketError::Checksum))
        );
        let mut wrong_ihl = v4_tcp(100);
        wrong_ihl[0] = 0x44; // IHL=4 非法
        assert_eq!(
            error_packet(&wrong_ihl, 1400, IpAddr::V4(NEXTHOP_V4)),
            Err(Error::Packet(PacketError::HeaderLength))
        );
    }
}

#[test]
fn unusable_destinations_are_refused() {
    {
        // 错误报文目的 = 原报文源：未指定与组播一律拒绝，不伪造目标。
        for source in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(224, 0, 0, 1)] {
            let mut original = v4_tcp(10);
            original[12..16].copy_from_slice(&source.octets());
            refill_v4(&mut original);
            assert_eq!(
                error_packet(&original, 1400, IpAddr::V4(NEXTHOP_V4)),
                Err(Error::UnreachableTarget),
                "源地址 {source} 不可作为错误报文目的"
            );
        }
        for source in [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
        ] {
            let mut original = v6_tcp(10);
            original[8..24].copy_from_slice(&source.octets());
            assert_eq!(
                error_packet(&original, 1280, IpAddr::V6(NEXTHOP_V6)),
                Err(Error::UnreachableTarget),
                "源地址 {source} 不可作为错误报文目的"
            );
        }
        // 地址族错配先于头部解析拒绝。
        assert_eq!(
            error_packet(&v4_tcp(10), 1400, IpAddr::V6(SOURCE_V6)),
            Err(Error::SourceFamily)
        );
    }
}

/// 所有拒绝种类都有可读信息；对抗性入参不触发 panic。
#[test]
fn error_messages_are_present_and_paths_never_panic() {
    {
        for error in [
            Error::MtuOutOfRange {
                family: IpVersion::V4,
                value: 1,
            },
            Error::MtuOutOfRange {
                family: IpVersion::V6,
                value: 1,
            },
            Error::PacketLength(0),
            Error::Packet(PacketError::Incomplete),
            Error::NotReportable,
            Error::IncompleteOriginal,
            Error::UnreachableTarget,
            Error::SourceFamily,
        ] {
            assert!(!error.to_string().is_empty());
            let reference: &dyn std::error::Error = &error;
            assert!(!reference.to_string().is_empty());
        }
        let mut buffer = [0u8; 200];
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = index as u8;
        }
        for version in [0u8, 4, 5, 6, 15] {
            for length in [0usize, 1, 9, 20, 21, 40, 41, 120, 200] {
                let mut candidate = buffer[..length].to_vec();
                if let Some(first) = candidate.first_mut() {
                    *first = version << 4;
                }
                let _ = carried_prefix(&candidate);
                let _ = decide_from(&candidate, 1500, Direction::Egress);
                let _ = decide_from(&candidate, 1400, Direction::Ingress);
                let _ = error_packet(&candidate, 1400, IpAddr::V4(NEXTHOP_V4));
                let _ = error_packet(&candidate, 1280, IpAddr::V6(NEXTHOP_V6));
            }
        }
    }
}
