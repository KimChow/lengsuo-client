//! 测试专用报文构造器；全部为假数据，不代表任何真实凭据或对端。
//!
//! 这些 helper 不是生产解析器，也不充当对端互通 fixture。
//! 本模块被多个测试目标共享，各目标只用得到其中一部分。
#![allow(dead_code)]

/// 运输报文固定头部长度。
pub const TRANSPORT_HEADER: usize = 16;

/// 只含 little endian 类型字段的头部字节。
pub fn type_bytes(kind: u32) -> Vec<u8> {
    kind.to_le_bytes().to_vec()
}

/// 构造指定类型的握手类报文：类型字段 + 填充字节，总长 `len`。
/// 若 `len < 4`，只输出类型字段的前 `len` 字节（用于截断测试）。
pub fn handshake_packet(kind: u32, len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; len];
    let header = type_bytes(kind);
    let copy = len.min(header.len());
    packet[..copy].copy_from_slice(&header[..copy]);
    for (offset, byte) in packet.iter_mut().enumerate().skip(4) {
        *byte = filler(offset);
    }
    packet
}

/// 填充字节：随下标变化，便于发现偏移错位。
pub fn filler(offset: usize) -> u8 {
    (offset % 251) as u8
}

/// 构造运输报文：类型(4) + 接收者(4) + 计数器(8) + 密文 `cipher_len` 字节。
pub fn transport_packet(receiver: u32, counter: u64, cipher_len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; TRANSPORT_HEADER + cipher_len];
    packet[..4].copy_from_slice(&4u32.to_le_bytes());
    packet[4..8].copy_from_slice(&receiver.to_le_bytes());
    packet[8..16].copy_from_slice(&counter.to_le_bytes());
    for (offset, byte) in packet.iter_mut().enumerate().skip(TRANSPORT_HEADER) {
        *byte = filler(offset);
    }
    packet
}

/// 把类型字段替换为任意 4 字节，用于保留位与未知类型测试。
pub fn with_raw_type(mut packet: Vec<u8>, raw: [u8; 4]) -> Vec<u8> {
    if packet.len() >= 4 {
        packet[..4].copy_from_slice(&raw);
    }
    packet
}
