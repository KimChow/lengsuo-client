//! TCP 段的解析与构造：fail-closed 的纯内存原语。
//!
//! 解析入口 [`parse_segment`] 只做两件事：按 [`packet::PacketInfo`] 已核对的元数据
//! 定位段头，并复核 TCP 校验和（[`checksum::tcp_checksum`]，复用会话表无关的
//! 线上 IP 伪首部）。任何长度、首部跨度、校验和不符一律返回 [`SegmentError`]，
//! 调用方丢弃并计数——本模块不 panic，也不加"仅调试"旁路。
//!
//! 构造侧 [`TcpSegment`] 以显式字段表达一个待发送段：`seq`/`ack` 保持 `u32`
//! 域上的**裸值**，回绕由调用方用有界模运算处理（见 `listener.rs`），因此这里
//! 只负责把字段落成合法字节并算出正确校验和。选项（MSS、窗口缩放等）本阶段
//! 不解析内容，只保证头部长度合法并可安全跳过。

use crate::checksum;
use crate::packet::{PacketError, PacketInfo, Transport};

/// TCP 固定首部长度：源/目的端口 4 + 序号 4 + 确认号 4 + 首部长度/标志 4 +
/// 窗口 2 + 校验和 2 + 紧急指针 2。
pub const TCP_MIN_HEADER_LEN: usize = 20;

/// 单个 TCP 段允许的最大首部长度（首部长度字段 4 位，上限 15 字长）。
pub const TCP_MAX_HEADER_LEN: usize = 60;

/// 本阶段可表示的全部 TCP 标志位（数据偏移之后的 12 位控制位中，NS/AE 保留）。
pub const FLAG_FIN: u16 = 0x01;
pub const FLAG_SYN: u16 = 0x02;
pub const FLAG_RST: u16 = 0x04;
pub const FLAG_PSH: u16 = 0x08;
pub const FLAG_ACK: u16 = 0x10;
pub const FLAG_URG: u16 = 0x20;
pub const FLAG_ECE: u16 = 0x40;
pub const FLAG_CWR: u16 = 0x80;

/// 已知标志位的合集。`parse_segment` 拒绝任何落在已知位之外的控制位，
/// 避免把不可解释的标志当成合法段交给状态机。
const KNOWN_FLAGS: u16 = FLAG_FIN
    | FLAG_SYN
    | FLAG_RST
    | FLAG_PSH
    | FLAG_ACK
    | FLAG_URG
    | FLAG_ECE
    | FLAG_CWR;

/// 段级拒绝原因。全部是可观测的分类：调用方按变体计数即可定位丢包成因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentError {
    /// 传输层不是 TCP（[`packet::inspect`] 已核对线上首部，此处只可能因
    /// 调用方传错 `PacketInfo` 而命中）。
    NotTcp,
    /// 段头超出数据包末尾：`(l4_offset + header_len) > packet.len()`。
    Truncated,
    /// 首部长度字段非法：小于 20 字节，或不是 4 的整数倍，或超过 60 字节。
    BadHeaderLength,
    /// 校验和不匹配，或 [`packet::inspect`] 本身失败（[`PacketError`] 映射到此）。
    /// 两者都是"线上字节不可信"，状态机据此丢弃并计数。
    BadChecksum,
    /// 构造侧：载荷超出单个段的表达上限（校验和 16 位补码求和域）。
    PayloadTooLong,
}

/// 一个 TCP 段的解析视图。载荷以 [`PacketInfo::payload_len`] 表达，
/// 字节本身留在原包内，由调用方按 `offsets` 取用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    /// 标志位合集，仅含 [`KNOWN_FLAGS`] 中的位。
    pub flags: u16,
    /// 通告窗口（未缩放）。
    pub window: u16,
    /// 段头字节数，范围 `[20, 60]` 且为 4 的倍数；选项内容被跳过。
    pub header_len: usize,
    /// 载荷字节数。
    pub payload_len: usize,
    /// 载荷首字节在 `packet` 中的偏移。
    pub payload_offset: usize,
    pub urgent: u16,
}

impl TcpSegment {
    pub fn has(&self, flag: u16) -> bool {
        self.flags & flag != 0
    }

    /// SYN 与 FIN 各占一个序号，与载荷长度无关。
    pub fn occupies_seq_space(&self) -> bool {
        self.has(FLAG_SYN) || self.has(FLAG_FIN)
    }

    /// 载荷尾端之后的下一个序号（裸 `u128` 算术，不进 `2^32` 域），
    /// 与 [`TcpSegment::occupies_seq_space`] 的语义配合，供调用方做窗口/去重判断。
    pub fn next_seq_raw(&self) -> u128 {
        u128::from(self.sequence) + u128::from(self.payload_len as u32)
    }
}

/// 解析并校验一个 TCP 段。
///
/// `info` 必须来自同一段 `packet` 的 [`packet::inspect`]：本函数复核
/// `info.transport == Tcp` 与 TCP 校验和，其余字段直接采信。任何不合法输入
/// 返回错误，绝不返回部分解析结果。
pub fn parse_segment(packet: &[u8], info: PacketInfo) -> Result<TcpSegment, SegmentError> {
    if info.protocol != Transport::Tcp {
        return Err(SegmentError::NotTcp);
    }
    let base = usize::from(info.l4_offset);
    if base.checked_add(TCP_MIN_HEADER_LEN).is_none_or(|end| end > packet.len()) {
        return Err(SegmentError::Truncated);
    }
    let header = packet
        .get(base..base + TCP_MIN_HEADER_LEN)
        .ok_or(SegmentError::Truncated)?;

    let data_offset = usize::from(header[12] >> 4);
    if data_offset < 5 || data_offset > 15 {
        return Err(SegmentError::BadHeaderLength);
    }
    let header_len = data_offset * 4;
    let end = base
        .checked_add(header_len)
        .filter(|end| *end <= packet.len())
        .ok_or(SegmentError::Truncated)?;

    let source_port = u16::from_be_bytes([header[0], header[1]]);
    let destination_port = u16::from_be_bytes([header[2], header[3]]);
    let sequence = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let acknowledgment = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    let flags = u16::from_be_bytes([header[12], header[13]]) & 0x01ff;
    if flags & !KNOWN_FLAGS != 0 {
        // 含保留/未知控制位：不可解释，按不可信输入处理。
        return Err(SegmentError::BadHeaderLength);
    }
    let window = u16::from_be_bytes([header[14], header[15]]);
    let checksum_field = u16::from_be_bytes([header[16], header[17]]);
    let urgent = u16::from_be_bytes([header[18], header[19]]);

    // TCP 校验和覆盖 IP 伪首部 + 完整段头（含选项）+ 载荷。
    let ip_start = base - ip_header_len(info);
    let expected = checksum::tcp_checksum(
        &packet[ip_start..],
        &packet[base..],
    )
    .map_err(|_| SegmentError::BadChecksum)?;
    if expected != checksum_field {
        return Err(SegmentError::BadChecksum);
    }

    Ok(TcpSegment {
        source_port,
        destination_port,
        sequence,
        acknowledgment,
        flags,
        window,
        header_len,
        payload_len: end - (base + header_len) + info.payload_len - info.payload_len,
        payload_offset: base + header_len,
        urgent,
    })
}

/// IPv4 / IPv6 定长首部字节数：`l4_offset` 由 [`packet::inspect`] 算出，
/// 反推 IP 首部起点即可复用线上伪首部所需的原始字节。
fn ip_header_len(info: PacketInfo) -> usize {
    if info.ipv6 {
        40
    } else {
        20
    }
}

/// 可复用的段构造器：把 [`crate::packet::TcpSegmentBuilder`] 的产出补齐校验和，
/// 并把字段回填成 [`TcpSegment`] 供上层记账（序号推进、重传快照等）。
pub struct SegmentFactory {
    builder: crate::packet::TcpSegmentBuilder,
}

impl SegmentFactory {
    pub fn new(ip: [u8; 4], tcp: [u8; 20]) -> Self {
        Self {
            builder: crate::packet::TcpSegmentBuilder::new(ip, tcp),
        }
    }

    pub fn with_header_len(mut self, header_len: usize) -> Self {
        self.builder.set_header_len(header_len);
        self
    }

    /// 头部选项区（MSS 等）写入：`options` 必须为 4 的倍数且总首部落在合法区间，
    /// 否则 `builder` 在自身写路径内拒绝。此处不额外复制，直接复用底层缓冲。
    pub fn write_options(
        &mut self,
        offset_in_header: usize,
        options: &[u8],
    ) -> Result<&mut [u8], PacketError> {
        self.builder
            .write_segment_slice(offset_in_header, options)
            .map_err(|err| err.into_build_error())
    }

    /// 写入载荷并算出校验和，返回构造后的完整数据包与其段视图。
    /// 载荷与选项合计受 [`crate::packet::MAX_L4_PAYLOAD`] 约束。
    pub fn build(&mut self, payload: &[u8]) -> Result<BuiltSegment, SegmentError> {
        let written = self
            .builder
            .write_l4_payload(payload)
            .map_err(|err| err.into_build_error())?;
        if written > crate::packet::MAX_L4_PAYLOAD {
            return Err(SegmentError::PayloadTooLong);
        }
        let checksum_field =
            checksum::tcp_checksum(self.builder.ip_header_bytes(), self.builder.tcp_header_bytes())
                .map_err(|_| SegmentError::PayloadTooLong)?;
        self.builder.set_checksum(checksum_field);
        let packet = self.builder.finish().map_err(|_| SegmentError::PayloadTooLong)?;
        let header_len = self.builder.header_len();
        Ok(BuiltSegment {
            packet,
            segment: TcpSegment {
                source_port: self.builder.source_port(),
                destination_port: self.builder.destination_port(),
                sequence: self.builder.sequence(),
                acknowledgment: self.builder.acknowledgment(),
                flags: self.builder.flags() & 0x01ff,
                window: self.builder.window(),
                header_len,
                payload_len: payload.len(),
                payload_offset: 20 + header_len,
                urgent: 0,
            },
        })
    }

    /// 只改标志/序号/确认号/窗口后重发同一载荷（重传路径）。校验和每次重算。
    pub fn patch_control(
        &mut self,
        sequence: u32,
        acknowledgment: u32,
        flags: u16,
        window: u16,
    ) {
        self.builder.set_sequence(sequence);
        self.builder.set_acknowledgment(acknowledgment);
        self.builder.set_flags(flags);
        self.builder.set_window(window);
    }

    pub fn sequence(&self) -> u32 {
        self.builder.sequence()
    }

    pub fn acknowledgment(&self) -> u32 {
        self.builder.acknowledgment()
    }

    pub fn set_acknowledgment(&mut self, value: u32) {
        self.builder.set_acknowledgment(value);
    }

    pub fn set_window(&mut self, value: u16) {
        self.builder.set_window(value);
    }

    pub fn set_flags(&mut self, value: u16) {
        self.builder.set_flags(value);
    }

    pub fn set_payload_slice(&mut self, payload: &[u8]) -> Result<(), PacketError> {
        self.builder
            .write_l4_payload(payload)
            .map(|_| ())
            .map_err(|err| err.into_build_error())
    }

    pub fn checksum(&self) -> u16 {
        self.builder.checksum()
    }
}

/// [`SegmentFactory::build`] 的产出：可直接交给 [`crate::device`] 的字节，
/// 以及对应的 [`TcpSegment`] 记账视图。
#[derive(Debug, Clone)]
pub struct BuiltSegment {
    pub packet: Vec<u8>,
    pub segment: TcpSegment,
}

impl BuiltSegment {
    pub fn len(&self) -> usize {
        self.packet.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packet.is_empty()
    }
}

/// 便捷构造：定长首部（20 字节、无选项）的一次性段。用于握手/ACK/FIN/RST。
pub fn simple_segment(
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    flags: u16,
    window: u16,
    payload: &[u8],
    ip: [u8; 4],
) -> Result<BuiltSegment, SegmentError> {
    let tcp = [
        source_port.to_be_bytes()[0],
        source_port.to_be_bytes()[1],
        destination_port.to_be_bytes()[0],
        destination_port.to_be_bytes()[1],
        sequence.to_be_bytes()[0],
        sequence.to_be_bytes()[1],
        sequence.to_be_bytes()[2],
        sequence.to_be_bytes()[3],
        acknowledgment.to_be_bytes()[0],
        acknowledgment.to_be_bytes()[1],
        acknowledgment.to_be_bytes()[2],
        acknowledgment.to_be_bytes()[3],
        (5u8 << 4),
        (flags & 0xff) as u8,
        window.to_be_bytes()[0],
        window.to_be_bytes()[1],
        0,
        0,
        0,
        0,
    ];
    let mut factory = SegmentFactory::new(ip, tcp);
    factory.build(payload)
}
