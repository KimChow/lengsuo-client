//! 非法输入拒绝路径：非 TCP/UDP、截断、不可用目的地与报错信息（自原 mtu.rs 原样搬移）。

use crate::fixtures::*;

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
