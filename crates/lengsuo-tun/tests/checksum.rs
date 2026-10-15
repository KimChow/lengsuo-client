//! 传输层校验和验证测试。测试侧用独立算法生成校验和，不复用被测实现；
//! 这些用例只证明验证器与独立算法及固定向量一致，不代表真实网卡或协议栈互通。
mod support;

use lengsuo_tun::checksum::{verify, Error};
use lengsuo_tun::packet::{self, Transport};
use support::*;

/// 一补码和，测试侧独立写法：逐字累加后立即折叠进位，与被测算法的 u64 累加不同。
fn independent_sum(parts: &[&[u8]]) -> u16 {
    let mut bytes: Vec<u8> = Vec::new();
    for part in parts {
        bytes.extend_from_slice(part);
    }
    if bytes.len() % 2 == 1 {
        bytes.push(0);
    }
    let mut acc: u32 = 0;
    for pair in bytes.chunks(2) {
        let word = (u32::from(pair[0]) << 8) | u32::from(pair[1]);
        acc = acc.wrapping_add(word);
        acc = (acc & 0xffff) + (acc >> 16);
    }
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// IPv4 伪首部：源/目的地址、零字节、协议、16 位传输段长度。
fn ipv4_pseudo(packet: &[u8], segment_len: usize) -> Vec<u8> {
    let mut pseudo = vec![0u8; 12];
    pseudo[0..8].copy_from_slice(&packet[12..20]);
    pseudo[9] = packet[9];
    pseudo[10..12].copy_from_slice(&(segment_len as u16).to_be_bytes());
    pseudo
}

/// IPv6 伪首部：源/目的地址、32 位传输段长度、下一头。
fn ipv6_pseudo(packet: &[u8], segment_len: usize) -> Vec<u8> {
    let mut pseudo = vec![0u8; 40];
    pseudo[0..32].copy_from_slice(&packet[8..40]);
    pseudo[32..36].copy_from_slice(&(segment_len as u32).to_be_bytes());
    pseudo[39] = packet[6];
    pseudo
}

/// 在已构造报文上写入正确的传输层校验和（测试侧独立计算）。
fn stamp(packet: &mut [u8]) {
    let header = match packet[0] >> 4 {
        4 => usize::from(packet[0] & 0x0f) * 4,
        _ => 40,
    };
    let protocol = if packet[0] >> 4 == 4 {
        packet[9]
    } else {
        packet[6]
    };
    let segment = packet.len() - header;
    let field = match protocol {
        6 => header + 16,
        _ => header + 6,
    };
    packet[field] = 0;
    packet[field + 1] = 0;
    let pseudo = match packet[0] >> 4 {
        4 => ipv4_pseudo(packet, segment),
        _ => ipv6_pseudo(packet, segment),
    };
    let value = !independent_sum(&[&pseudo, &packet[header..]]);
    packet[field..field + 2].copy_from_slice(&value.to_be_bytes());
    if packet[0] >> 4 == 4 {
        refill(packet);
    }
}

/// 带校验和的 IPv4 报文（TCP 偏移 5 字）。
fn v4_tcp(offset_words: u8, body: usize, ihl: usize) -> Vec<u8> {
    let mut packet = ipv4(ihl, 6);
    append(&mut packet, &tcp(5000, 443, offset_words, body));
    stamp(&mut packet);
    packet
}

fn v4_udp(body: usize, ihl: usize) -> Vec<u8> {
    let mut packet = ipv4(ihl, 17);
    append(&mut packet, &udp(5000, 443, body));
    stamp(&mut packet);
    packet
}

fn v6_tcp(body: usize) -> Vec<u8> {
    let mut packet = ipv6(6, &tcp(5000, 443, 5, body));
    stamp(&mut packet);
    packet
}

fn v6_udp(body: usize) -> Vec<u8> {
    let mut packet = ipv6(17, &udp(5000, 443, body));
    stamp(&mut packet);
    packet
}

#[test]
fn correct_ipv4_tcp_with_even_and_odd_payload() {
    for (body, ihl) in [(0usize, 5usize), (3, 5), (4, 6), (7, 8), (12, 15)] {
        let packet = v4_tcp(5, body, ihl);
        let info =
            verify(&packet).unwrap_or_else(|error| panic!("ihl {ihl} body {body}: {error:?}"));
        let parsed = packet::inspect(&packet).expect("header still parses");
        assert_eq!(info, parsed);
        assert_eq!((info.source, info.destination), v4_pairs());
        assert_tcp(info, ihl * 4 + 20);
        assert_eq!(&packet[info.payload_offset..], &vec![0u8; body]);
    }
}

#[test]
fn correct_ipv4_udp_with_even_and_odd_payload() {
    for body in [0usize, 1, 2, 5, 16] {
        let packet = v4_udp(body, 5);
        let info = verify(&packet).unwrap_or_else(|error| panic!("body {body}: {error:?}"));
        assert_eq!((info.source, info.destination), v4_pairs());
        assert_udp(info, 28);
        assert_eq!(&packet[info.payload_offset..], &vec![0u8; body]);
    }
}

#[test]
fn correct_ipv6_tcp_and_udp_with_even_and_odd_payload() {
    for body in [0usize, 1, 5, 8] {
        let packet = v6_tcp(body);
        let info = verify(&packet).expect("IPv6 TCP must pass");
        assert_eq!(info.protocol, Transport::Tcp);
        assert_tcp(info, 60);

        let packet = v6_udp(body);
        let info = verify(&packet).expect("IPv6 UDP must pass");
        assert_udp(info, 48);
    }
}

#[test]
fn ipv4_udp_zero_checksum_is_permitted() {
    let mut packet = v4_udp(5, 5);
    assert_ne!((packet[26], packet[27]), (0, 0), "stamped first");
    packet[26] = 0;
    packet[27] = 0;
    let info = verify(&packet).expect("IPv4 UDP 未提供校验和必须放行");
    assert_eq!(info.protocol, Transport::Udp);
}

#[test]
fn ipv6_udp_zero_checksum_is_rejected() {
    let mut packet = v6_udp(5);
    assert_ne!((packet[46], packet[47]), (0, 0), "stamped first");
    packet[46] = 0;
    packet[47] = 0;
    assert_eq!(verify(&packet), Err(Error::TransportChecksum));
}

#[test]
fn corrupted_tcp_checksum_cleared_to_zero_is_rejected() {
    for (packet, field) in [(v4_tcp(5, 3, 5), 36usize), (v6_tcp(3), 56usize)] {
        assert_ne!((packet[field], packet[field + 1]), (0, 0), "stamped first");
        let mut zeroed = packet.clone();
        zeroed[field] = 0;
        zeroed[field + 1] = 0;
        assert!(packet::inspect(&zeroed).is_ok(), "header must still parse");
        assert_eq!(verify(&zeroed), Err(Error::TransportChecksum));
    }
}

#[test]
fn tampered_fields_are_rejected_without_touching_header_checksum() {
    let base = v4_tcp(5, 3, 5);
    // 改源 IP 会先被 IPv4 头部校验和挡下，因此同时回填头部校验和，逼出传输层检查。
    let mut source = base.clone();
    source[12] ^= 0x01;
    refill(&mut source);
    assert!(packet::inspect(&source).is_ok());
    assert_eq!(verify(&source), Err(Error::TransportChecksum));

    let mut port = base.clone();
    port[20] ^= 0x02; // 源端口
    assert_eq!(verify(&port), Err(Error::TransportChecksum));

    let mut payload = base.clone();
    let last = payload.len() - 1;
    payload[last] ^= 0x40;
    assert_eq!(verify(&payload), Err(Error::TransportChecksum));

    // IPv6 固定头部没有校验和，地址改动只能靠伪首部兜住：字节 8 与 39 分别是
    // 源与目的地址的边界字节。
    let v6 = v6_udp(5);
    let mut destination = v6.clone();
    destination[39] ^= 0x01;
    assert!(packet::inspect(&destination).is_ok(), "header still parses");
    assert_eq!(verify(&destination), Err(Error::TransportChecksum));
    let mut source = v6.clone();
    source[8] ^= 0x10;
    assert!(packet::inspect(&source).is_ok(), "header still parses");
    assert_eq!(verify(&source), Err(Error::TransportChecksum));
}

/// IPv6 固定头部中不在伪首部内的字段（通信类、流标签、跳数限制）既无 IPv6 头部
/// 校验和、也不属于传输段，本模块检测不到；其余字节的单比特翻转都必须被拒。
#[test]
fn uncovered_ipv6_fields_are_documented_and_other_flips_are_rejected() {
    // 明确记录范围外：改动这些字节仍会通过传输层校验。
    for index in [1usize, 2, 3, 7] {
        let mut candidate = v6_udp(5);
        candidate[index] ^= 0x55;
        assert!(
            verify(&candidate).is_ok(),
            "IPv6 byte {index} 本就不在校验和覆盖内"
        );
    }
    for base in [v4_tcp(5, 3, 5), v4_udp(5, 6), v6_tcp(4), v6_udp(3)] {
        assert!(verify(&base).is_ok(), "base must pass: {base:?}");
        let ipv6 = base[0] >> 4 == 6;
        for index in 0..base.len() {
            let mut candidate = base.clone();
            candidate[index] ^= 0x80;
            let result = verify(&candidate);
            if ipv6 && matches!(index, 1..=3 | 7) {
                continue;
            }
            match result {
                Ok(_) => panic!("byte {index} flip still verified"),
                Err(error) => assert!(
                    matches!(error, Error::TransportChecksum | Error::Packet(_)),
                    "byte {index}: {error:?}"
                ),
            }
        }
    }
}

#[test]
fn every_truncation_fails_closed_without_panic() {
    for base in [v4_tcp(5, 3, 5), v4_udp(5, 5), v6_tcp(1), v6_udp(5)] {
        for len in 0..base.len() {
            let result = verify(&base[..len]);
            assert!(result.is_err(), "{len} of {} bytes accepted", base.len());
        }
        assert!(verify(&base).is_ok(), "full base must verify: {base:?}");
    }
    // 空输入与纯噪声不 panic。
    assert!(matches!(
        verify(&[]),
        Err(Error::Packet(packet::Error::Incomplete))
    ));
    let noise: Vec<u8> = (0..64u8).collect();
    for prefix in 1..noise.len() {
        let _ = verify(&noise[..prefix]);
    }
}

#[test]
fn header_problems_keep_packet_error_kinds() {
    let mut fragmented = v4_tcp(5, 3, 5);
    fragmented[6] = 0x20; // MF
    refill(&mut fragmented);
    assert_eq!(
        verify(&fragmented),
        Err(Error::Packet(packet::Error::Fragmented))
    );

    let mut bad_version = v4_tcp(5, 3, 5);
    bad_version[0] = 0x90 | (bad_version[0] & 0x0f);
    refill(&mut bad_version);
    assert_eq!(
        verify(&bad_version),
        Err(Error::Packet(packet::Error::UnsupportedVersion))
    );

    let mut extension = v6_tcp(3);
    extension[6] = 43;
    assert_eq!(
        verify(&extension),
        Err(Error::Packet(packet::Error::UnsupportedProtocol))
    );

    let mut stale_header = v4_udp(5, 5);
    stale_header[8] ^= 0xff; // TTL 改动却不回填头部校验和
    assert_eq!(
        verify(&stale_header),
        Err(Error::Packet(packet::Error::Checksum))
    );

    let mut trailing = v4_tcp(5, 3, 5);
    trailing.push(0);
    assert_eq!(
        verify(&trailing),
        Err(Error::Packet(packet::Error::TotalLength))
    );
}

#[test]
fn errors_are_displayable_and_convertible() {
    let inner = packet::Error::TcpHeader;
    let wrapped = Error::from(inner);
    assert_eq!(wrapped, Error::Packet(inner));
    assert!(!wrapped.to_string().is_empty());
    assert!(!Error::TransportChecksum.to_string().is_empty());
    let reference: &dyn std::error::Error = &Error::TransportChecksum;
    assert_eq!(reference.to_string(), Error::TransportChecksum.to_string());
}

#[test]
fn mathematically_valid_zero_tcp_checksum_is_not_a_bypass() {
    for mut packet in [v4_tcp(5, 2, 5), v6_tcp(2)] {
        let start = if packet[0] >> 4 == 4 { 20 } else { 40 };
        packet[start + 16..start + 18].fill(0);
        let pseudo = if start == 20 {
            ipv4_pseudo(&packet, packet.len() - start)
        } else {
            ipv6_pseudo(&packet, packet.len() - start)
        };
        let correction = (!independent_sum(&[&pseudo, &packet[start..]])).to_be_bytes();
        let end = packet.len();
        packet[end - 2..].copy_from_slice(&correction);
        stamp(&mut packet);
        assert_eq!(&packet[start + 16..start + 18], &[0, 0]);
        assert!(verify(&packet).is_ok());
    }
}
