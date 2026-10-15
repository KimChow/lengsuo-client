//! IP 报文元数据边界与错误路径测试，不代表平台 TUN 驱动验收。
mod support;
use lengsuo_tun::packet::{inspect, Error};
use std::net::{IpAddr, Ipv6Addr};
use support::*;

#[test]
fn legal_ipv4_tcp_without_options() {
    let mut packet = ipv4(5, 6);
    append(&mut packet, &tcp(5000, 443, 5, 3));
    let info = inspect(&packet).expect("legal IPv4 TCP");
    assert_eq!((info.source, info.destination), v4_pairs());
    assert_tcp(info, 40);
    assert_eq!(&packet[info.payload_offset..], &[0, 0, 0]);
    // 校验和字段确实被写入而非恰好为零。
    assert_ne!((packet[10], packet[11]), (0, 0));
}

#[test]
fn legal_ipv4_tcp_with_options() {
    for ihl in [6usize, 8, 15] {
        let mut packet = ipv4(ihl, 6);
        append(&mut packet, &tcp(5000, 443, 5, 4));
        let info = inspect(&packet).expect("options must not break parsing");
        assert_tcp(info, ihl * 4 + 20);
    }
    // data offset 上界 15 字（60 字节 TCP 头部），其后零载荷。
    let mut packet = ipv4(5, 6);
    append(&mut packet, &tcp(5000, 443, 15, 40));
    assert_eq!(packet.len(), 80);
    assert_tcp(inspect(&packet).expect("60-byte TCP header"), 80);
}

#[test]
fn legal_ipv4_udp_including_empty_payload() {
    let mut packet = ipv4(5, 17);
    append(&mut packet, &udp(5000, 443, 5));
    let info = inspect(&packet).expect("legal IPv4 UDP");
    assert_udp(info, 28);
    assert_eq!(&packet[info.payload_offset..], &[0; 5]);

    let mut packet = ipv4(5, 17);
    append(&mut packet, &udp(5000, 443, 0));
    assert_udp(inspect(&packet).expect("empty UDP payload"), 28);
}

#[test]
fn legal_ipv6_tcp_and_udp() {
    let packet = ipv6(6, &tcp(5000, 443, 5, 4));
    let info = inspect(&packet).expect("legal IPv6 TCP");
    assert_eq!(
        info.source,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    );
    assert_eq!(
        info.destination,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
    );
    assert_tcp(info, 60);

    let packet = ipv6(17, &udp(5000, 443, 2));
    assert_udp(inspect(&packet).expect("legal IPv6 UDP"), 48);
    let packet = ipv6(17, &udp(5000, 443, 0));
    assert_udp(inspect(&packet).expect("empty IPv6 UDP payload"), 48);
}

#[test]
fn every_truncation_fails_closed() {
    let mut udp_packet = ipv4(5, 17);
    append(&mut udp_packet, &udp(5000, 443, 5));
    let bases = [
        v4_variant(5, 6),
        v4_variant(8, 6),
        udp_packet,
        ipv6(6, &tcp(5000, 443, 5, 4)),
        ipv6(17, &udp(5000, 443, 2)),
    ];
    for base in bases {
        for len in 0..base.len() {
            let result = inspect(&base[..len]);
            assert!(result.is_err(), "{len} of {} bytes parsed OK", base.len());
            let error = result.unwrap_err();
            assert!(
                matches!(
                    error,
                    Error::Incomplete
                        | Error::TotalLength
                        | Error::HeaderLength
                        | Error::Checksum
                        | Error::TcpHeader
                        | Error::UdpLength
                ),
                "unexpected {error:?} at {len} of {} bytes",
                base.len()
            );
        }
        assert!(inspect(&base).is_ok(), "full base must parse: {base:?}");
    }
}

/// 供截断测试使用的带段合法报文。
fn v4_variant(ihl: usize, protocol: u8) -> Vec<u8> {
    let mut packet = ipv4(ihl, protocol);
    if protocol == 6 {
        append(&mut packet, &tcp(5000, 443, 5, 3));
    }
    packet
}

#[test]
fn unsupported_version_and_empty_input() {
    assert_eq!(inspect(&[]), Err(Error::Incomplete));
    for version in [0u8, 1, 2, 3, 5, 7, 8, 9, 0xf] {
        let mut packet = v4_variant(5, 6);
        packet[0] = (packet[0] & 0x0f) | (version << 4);
        assert_eq!(
            inspect(&packet),
            Err(Error::UnsupportedVersion),
            "v{version}"
        );
    }
    // 首字节为 IPv4 但版本 nibble 正确时不检查通信类，因此 tos 非零仍应通过。
    let mut packet = v4_variant(5, 6);
    packet[1] = 0xff;
    refill(&mut packet);
    assert!(inspect(&packet).is_ok());
}

#[test]
fn bad_ipv4_header_length() {
    for ihl in 0..5usize {
        let mut packet = v4_variant(5, 6);
        packet[0] = 0x40 | ihl as u8;
        refill(&mut packet);
        assert_eq!(inspect(&packet), Err(Error::HeaderLength), "ihl {ihl}");
    }
    // IHL=15（60 字节）而输入只有 43 字节。
    let mut packet = v4_variant(5, 6);
    packet[0] = 0x4f;
    refill(&mut packet);
    assert_eq!(inspect(&packet), Err(Error::HeaderLength));
    // IHL 超过 15 无法编码；4 位字段最大即 15，已被上一条覆盖。
    let packet = ipv4(5, 6);
    assert_eq!(inspect(&packet), Err(Error::Incomplete), "header-only TCP");
}

#[test]
fn bad_ipv4_total_length() {
    let base = v4_variant(5, 6);
    let total = u16::from_be_bytes([base[2], base[3]]);
    let mut longer = base.clone();
    longer.push(0);
    longer[2] = total.to_be_bytes()[0];
    longer[3] = total.to_be_bytes()[1];
    refill(&mut longer);
    assert_eq!(
        inspect(&longer),
        Err(Error::TotalLength),
        "trailing garbage"
    );

    let mut shorter = base.clone();
    shorter.truncate(shorter.len() - 1);
    assert_eq!(inspect(&shorter), Err(Error::TotalLength), "short input");

    let mut inflated = base.clone();
    let value = total + 1;
    inflated[2] = value.to_be_bytes()[0];
    inflated[3] = value.to_be_bytes()[1];
    refill(&mut inflated);
    assert_eq!(inspect(&inflated), Err(Error::TotalLength));

    let mut zero = base.clone();
    zero[2] = 0;
    zero[3] = 0;
    refill(&mut zero);
    assert_eq!(inspect(&zero), Err(Error::TotalLength));
}

#[test]
fn bad_ipv4_checksum() {
    let base = v4_variant(5, 6);
    let mut tampered = base.clone();
    tampered[12] ^= 0xff; // 改源地址却不修正校验和
    assert_eq!(inspect(&tampered), Err(Error::Checksum));

    let mut zeroed = base.clone();
    zeroed[10] = 0;
    zeroed[11] = 0;
    assert_eq!(inspect(&zeroed), Err(Error::Checksum));

    let mut flipped = base.clone();
    flipped[11] ^= 0x01;
    assert_eq!(inspect(&flipped), Err(Error::Checksum));
    assert_eq!(base[8], 64);
}

#[test]
fn ipv4_fragments_are_rejected() {
    // MF 置位且偏移为零。
    let packet = fragment(0x20, 0);
    assert_eq!(inspect(&packet), Err(Error::Fragmented));
    // 非零分片偏移（首片，MF=1 已由偏移覆盖）。
    let packet = fragment(0x00, 1);
    assert_eq!(inspect(&packet), Err(Error::Fragmented));
    // 末片：MF=0 但偏移非零，仍拒绝。
    let packet = fragment(0x40, 2);
    assert_eq!(inspect(&packet), Err(Error::Fragmented));
    // 偏移字段低 13 位全部置位。
    let packet = fragment(0x3f, 0xff);
    assert_eq!(inspect(&packet), Err(Error::Fragmented));
}

fn fragment(flags_high: u8, offset_low: u8) -> Vec<u8> {
    let mut packet = v4_variant(5, 6);
    packet[6] = flags_high;
    packet[7] = offset_low;
    refill(&mut packet);
    packet
}

#[test]
fn ipv6_extension_headers_and_fragments_are_rejected() {
    // 0=逐跳选项、43=路由、44=分片、50=ESP、51=认证、60=目的、1=ICMPv6、58=下一头为 ICMPv6。
    for next_header in [0u8, 43, 44, 50, 51, 58, 60, 1, 41, 143, 255] {
        let packet = ipv6(next_header, &tcp(5000, 443, 5, 4));
        assert_eq!(
            inspect(&packet),
            Err(Error::UnsupportedProtocol),
            "next header {next_header}"
        );
    }
}

#[test]
fn unsupported_ipv4_protocol_is_rejected() {
    for protocol in [1u8, 41, 43, 44, 47, 50, 58, 132] {
        let mut packet = ipv4(5, protocol);
        append(&mut packet, &tcp(5000, 443, 5, 4));
        assert_eq!(
            inspect(&packet),
            Err(Error::UnsupportedProtocol),
            "protocol {protocol}"
        );
    }
}

#[test]
fn bad_tcp_data_offset() {
    for words in 0..5u8 {
        let mut packet = v4_variant(5, 6);
        packet[32] = words << 4;
        refill(&mut packet);
        assert_eq!(inspect(&packet), Err(Error::TcpHeader), "words {words}");
    }
    // 16 字（60 字节）超过 IP 载荷实际长度 23 字节。
    let mut packet = v4_variant(5, 6);
    packet[32] = 0xf0;
    refill(&mut packet);
    assert_eq!(inspect(&packet), Err(Error::TcpHeader));
    // 声明 60 字节头部但段长仅 40 字节。
    let mut packet = ipv4(5, 6);
    let mut segment = tcp(5000, 443, 15, 0);
    segment.resize(40, 0);
    append(&mut packet, &segment);
    assert_eq!(inspect(&packet), Err(Error::TcpHeader));
    // TCP 段短于 20 字节。
    let mut packet = ipv4(5, 6);
    let short = tcp(5000, 443, 5, 0);
    append(&mut packet, &short[..19]);
    assert_eq!(inspect(&packet), Err(Error::Incomplete));
}

#[test]
fn bad_udp_length() {
    let mut packet = ipv4(5, 17);
    let mut segment = udp(5000, 443, 5);
    segment[4..6].copy_from_slice(&8u16.to_be_bytes()); // 声明短于实际
    append(&mut packet, &segment);
    assert_eq!(inspect(&packet), Err(Error::UdpLength));

    let mut packet = ipv4(5, 17);
    let mut segment = udp(5000, 443, 5);
    segment[4..6].copy_from_slice(&14u16.to_be_bytes()); // 声明长于实际
    append(&mut packet, &segment);
    assert_eq!(inspect(&packet), Err(Error::UdpLength));

    let mut packet = ipv4(5, 17);
    let mut segment = udp(5000, 443, 0);
    segment[4..6].copy_from_slice(&7u16.to_be_bytes()); // 小于最小 UDP 头部
    append(&mut packet, &segment);
    assert_eq!(inspect(&packet), Err(Error::UdpLength));

    // IPv6 上同样要求精确一致。
    let mut packet = ipv6(17, &udp(5000, 443, 5));
    packet[5] = packet[5].wrapping_sub(1);
    assert_eq!(inspect(&packet), Err(Error::TotalLength));
    let mut packet = ipv6(17, &udp(5000, 443, 5));
    let segment_len = udp(5000, 443, 5).len();
    packet[4..6].copy_from_slice(&(segment_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0u8]);
    assert_eq!(inspect(&packet), Err(Error::TotalLength));
    let packet = ipv6(6, &[]);
    assert_eq!(inspect(&packet), Err(Error::Incomplete));
    let mut short = vec![0u8; 39];
    short[0] = 0x60;
    assert_eq!(inspect(&short), Err(Error::Incomplete));
}

#[test]
fn errors_have_messages_and_never_panic_on_garbage() {
    let mut buffer = vec![0u8; 120];
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = index as u8;
    }
    buffer[0] = 0x45;
    let _ = inspect(&buffer);
    buffer[0] = 0x60;
    let _ = inspect(&buffer);
    for version in [4u8, 6] {
        for index in 0..60 {
            let mut candidate = buffer.clone();
            candidate[0] = version << 4;
            candidate[index] = candidate[index].wrapping_add(0x80);
            let _ = inspect(&candidate);
        }
    }
    for error in [
        Error::Incomplete,
        Error::UnsupportedVersion,
        Error::HeaderLength,
        Error::TotalLength,
        Error::Fragmented,
        Error::Checksum,
        Error::UnsupportedProtocol,
        Error::TcpHeader,
        Error::UdpLength,
    ] {
        assert!(!error.to_string().is_empty());
        let reference: &dyn std::error::Error = &error;
        assert!(!reference.to_string().is_empty());
    }
}
