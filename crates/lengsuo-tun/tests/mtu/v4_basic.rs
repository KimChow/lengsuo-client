//! IPv4 路径 MTU 判定边界与方向性（自原 mtu.rs 原样搬移）。

use crate::fixtures::*;

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
