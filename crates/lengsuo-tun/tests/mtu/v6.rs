//! IPv6 PMTUD 错误报文与 MTU 字段（自原 mtu.rs 原样搬移）。

use crate::fixtures::*;

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

