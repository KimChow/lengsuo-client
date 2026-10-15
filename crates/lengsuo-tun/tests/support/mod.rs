//! 测试报文构造器；不是生产解析器或生成 fixture。
use lengsuo_tun::packet::{PacketInfo, Transport};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// 头部长度：受输入长度截断，供构造器在追加段前后定位校验和字段。
pub fn header_len(packet: &[u8]) -> usize {
    let declared = (usize::from(packet[0] & 0x0f) * 4).max(IPV4_MIN_HEADER);
    let bound = (packet.len() / 2) * 2;
    declared.min(bound).max(IPV4_MIN_HEADER)
}

pub const IPV4_MIN_HEADER: usize = 20;

/// 重算校验和，只覆盖 IPv4 头部字节（不含传输段）。
pub fn refill(packet: &mut [u8]) {
    let header = header_len(packet);
    fill_checksum(&mut packet[..header]);
}

/// 计算并写入给定头部偏移 10..12 的一补码和。
pub fn fill_checksum(header: &mut [u8]) {
    header[10] = 0;
    header[11] = 0;
    let mut sum: u32 = 0;
    for word in header.as_chunks::<2>().0 {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([word[0], word[1]])));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let value = (!(sum & 0xffff)) as u16;
    header[10] = value.to_be_bytes()[0];
    header[11] = value.to_be_bytes()[1];
}

/// 只含 IPv4 头部（无传输段）的报文；总长度等于头部长度，DF 且偏移 0。
pub fn ipv4(ihl: usize, protocol: u8) -> Vec<u8> {
    let mut packet = vec![0u8; ihl * 4];
    packet[0] = 0x40 | ihl as u8;
    packet[2] = (packet.len() >> 8) as u8;
    packet[3] = packet.len() as u8;
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());
    packet[16..20].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 7).octets());
    for byte in packet
        .iter_mut()
        .skip(20)
        .take((ihl * 4).saturating_sub(21))
    {
        *byte = 0x01; // NOP 选项，末字节留 EOL
    }
    refill(&mut packet);
    packet
}

/// 在已构造的 IPv4 头部后追加传输段并修正总长度与校验和。
pub fn append(packet: &mut Vec<u8>, segment: &[u8]) {
    packet.truncate(header_len(packet));
    let total = packet.len() + segment.len();
    packet[2] = (total >> 8) as u8;
    packet[3] = total as u8;
    packet.extend_from_slice(segment);
    refill(packet);
}

pub fn tcp(source_port: u16, destination_port: u16, offset_words: u8, body: usize) -> Vec<u8> {
    let mut segment = vec![0u8; 20 + body];
    segment[0..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[12] = offset_words << 4;
    segment[13] = 0x18; // PSH+ACK，本解析器不读取标志位
    segment
}

pub fn udp(source_port: u16, destination_port: u16, body: usize) -> Vec<u8> {
    let mut segment = vec![0u8; 8 + body];
    segment[0..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[4..6].copy_from_slice(&((8 + body) as u16).to_be_bytes());
    segment
}

pub fn ipv6(next_header: u8, segment: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(segment.len() as u16).to_be_bytes());
    packet[6] = next_header;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    packet[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
    packet.extend_from_slice(segment);
    packet
}

pub fn assert_tcp(info: PacketInfo, payload_offset: usize) {
    assert_eq!(info.protocol, Transport::Tcp);
    assert_eq!(info.source_port, 5000);
    assert_eq!(info.destination_port, 443);
    assert_eq!(info.payload_offset, payload_offset);
}

pub fn assert_udp(info: PacketInfo, payload_offset: usize) {
    assert_eq!(info.protocol, Transport::Udp);
    assert_eq!(info.source_port, 5000);
    assert_eq!(info.destination_port, 443);
    assert_eq!(info.payload_offset, payload_offset);
}

pub fn v4_pairs() -> (IpAddr, IpAddr) {
    (
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
    )
}
