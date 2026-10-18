//! IPv4 PMTUD 错误报文字节级断言（自原 mtu.rs 原样搬移）。

use crate::fixtures::*;

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
