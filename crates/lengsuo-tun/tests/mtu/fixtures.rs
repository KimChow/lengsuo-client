//! MTU 测试共享报文构造与校验辅助（自原 mtu.rs 原样搬移；校验和用测试侧独立算法）。

//! 全部纯内存，不建设备、不发包；每个用例都在 timeout 与 blocking 线程的双重约束下
//! 运行。报文由测试侧独立构造，校验和用测试侧独立算法核对，不复用被测实现，
//! 因此这些断言只证明生成器与 RFC 描述一致，不代表真实链路或协议栈互通。

pub use lengsuo_tun::mtu::{
    carried_prefix, decide, decide_from, error_packet, Decision, Direction, Error, IpVersion,
    MAX_MTU_V4_FIELD, MIN_PATH_MTU_V4, MIN_PATH_MTU_V6,
};
pub use lengsuo_tun::packet::Error as PacketError;
pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const SOURCE_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
pub const DEST_V4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
pub const NEXTHOP_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 254);
pub const SOURCE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
pub const DEST_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
pub const NEXTHOP_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xfffe);

/// 测试侧独立的一补码和：逐字累加后立刻折叠进位，与被测的批量折叠写法不同。
pub fn ones_sum(bytes: &[u8]) -> u16 {
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
pub fn verify(bytes: &[u8]) -> bool {
    ones_sum(bytes) == 0xffff
}

pub fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

pub fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// 构造 IPv4 头部（DF、偏移 0），并重算头部校验和。
pub fn ipv4(ihl: usize, protocol: u8, source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
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

pub fn refill_v4(packet: &mut [u8]) {
    let header = usize::from(packet[0] & 0x0f) * 4;
    packet[10] = 0;
    packet[11] = 0;
    let checksum = !ones_sum(&packet[..header]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

/// 在已构造的 IPv4 头部后追加传输段，修正总长度与校验和。
pub fn append_v4(packet: &mut Vec<u8>, segment: &[u8]) {
    let header = usize::from(packet[0] & 0x0f) * 4;
    packet.truncate(header);
    let total = header + segment.len();
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet.extend_from_slice(segment);
    refill_v4(packet);
}

pub fn tcp(source_port: u16, destination_port: u16, body: usize) -> Vec<u8> {
    let mut segment = vec![0u8; 20 + body];
    segment[0..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[8..12].copy_from_slice(&0x0a1b_2c3du32.to_be_bytes()); // 序号：截取断言用
    segment[12] = 5 << 4;
    segment[13] = 0x18;
    segment[14..16].copy_from_slice(&0x2000u16.to_be_bytes()); // 窗口
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
    packet[8..24].copy_from_slice(&SOURCE_V6.octets());
    packet[24..40].copy_from_slice(&DEST_V6.octets());
    packet.extend_from_slice(segment);
    packet
}

pub fn v4_tcp(body: usize) -> Vec<u8> {
    let mut packet = ipv4(5, 6, SOURCE_V4, DEST_V4);
    append_v4(&mut packet, &tcp(5000, 443, body));
    packet
}

pub fn v6_tcp(body: usize) -> Vec<u8> {
    ipv6(6, &tcp(5000, 443, body))
}

// --------------------------------------------------------------- 判定边界
