//! TCP 段的纯内存解析与构造：无 IO、无系统调用、不触碰网卡。
//!
//! 只处理**调用方已定位好的 TCP 段字节**（不含 IP 头部）。IP 头部定位与五元组由
//! `packet::inspect` 负责，其 `payload_offset` 即 [`parse`] 的入参起点；传输层校验和由
//! `checksum::verify` 在传入本模块之前完成，这里不另写第二份校验和实现。
//!
//! 解析一律 fail-closed：数据偏移小于 5、段长不足头部长度、段长与数据偏移不符、保留位
//! 非零，都返回 [`Error`]，绝不 panic、不 unwrap、不裸索引。
//!
//! [`build`] 只构造段字节，不构造 IP 头部；校验和字段按 RFC 1071 就地填好（伪首部由调用方
//! 给出），产物可直接交给 `checksum::verify` 交叉验证。

use crate::checksum;

pub const MIN_HEADER: usize = 20;
pub const MAX_HEADER: usize = 60;
// 头部各字段偏移与掩码：序号 4、确认号 8、数据偏移字节 12（高 4 位为偏移，低 4 位为
// 保留位与 NS）、标志字节 13（CWR/ECE/URG/ACK/PSH/RST/SYN/FIN，RFC 9293 §3.1）、
// 窗口 14、校验和 16、紧急指针 18；数据偏移以 4 字节为单位。
const OFFSET_WINDOW: usize = 14;
const OFFSET_CHECKSUM: usize = 16;
const OFFSET_URGENT: usize = 18;
const OFFSET_SEQ: usize = 4;
const OFFSET_ACK: usize = 8;
const OFFSET_DATA_OFFSET: usize = 12;
const OFFSET_FLAGS: usize = 13;
const SHIFT_DATA_OFFSET: u32 = 4;
const OFFSET_UNIT: usize = 4;
const MASK_RESERVED_LOW: u8 = 0x0f;

/// 本模块的错误种类。全部是拒绝语义，不提供「尽量解析」的回退路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// 段短于 20 字节的固定头部。
    #[error("TCP 段短于最小头部")]
    Incomplete,
    /// 数据偏移小于 5 或超过 15，或大于实际段长。
    #[error("TCP 数据偏移非法：{0}")]
    DataOffset(usize),
    /// 段长与数据偏移声明不符（头部超出段长）。
    #[error("TCP 段长与数据偏移不符")]
    LengthMismatch,
    /// 数据偏移字节的低 4 位（3 位保留位 + NS）非零，本栈要求为零。
    #[error("TCP 保留位非零：0x{0:02x}")]
    Reserved(u8),
    /// 构造的段超出可表达的头部上限或载荷长度。
    #[error("要构造的 TCP 段长度非法：{0}")]
    BuildLength(usize),
    /// 构造入参自相矛盾（例如数据偏移小于 5）。
    #[error("构造 TCP 段的参数非法")]
    BuildArgument,
}

/// TCP 标志位，位值同 RFC 9293 §3.1：FIN=0x01、SYN=0x02、RST=0x04、PSH=0x08、
/// ACK=0x10。URG/ECE/CWR 与 NS 本栈不实现，解析时丢弃。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Flags(u8);

impl Flags {
    /// 无标志。
    pub const NONE: Flags = Flags(0);
    /// 发送端不再发送数据。
    pub const FIN: Flags = Flags(0x01);
    /// 同步序号。
    pub const SYN: Flags = Flags(0x02);
    /// 连接重置。
    pub const RST: Flags = Flags(0x04);
    /// 推给上层。
    pub const PSH: Flags = Flags(0x08);
    /// 确认号有效。
    pub const ACK: Flags = Flags(0x10);
    /// 已实现的标志位掩码：FIN/SYN/RST/PSH/ACK。
    const IMPLEMENTED: u8 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10;
    /// 由段内标志字节构造：只保留 SYN/ACK/FIN/RST/PSH 五位，其余位丢弃。
    pub fn from_byte(byte: u8) -> Self {
        Flags(byte & Flags::IMPLEMENTED)
    }
    /// 段内标志字节的原始值。
    pub fn bits(self) -> u8 {
        self.0
    }
    /// 是否含有 `other` 的全部位。
    pub fn contains(self, other: Flags) -> bool {
        self.0 & other.0 == other.0
    }
    pub fn has_syn(self) -> bool {
        self.contains(Flags::SYN)
    }
    pub fn has_ack(self) -> bool {
        self.contains(Flags::ACK)
    }
    pub fn has_fin(self) -> bool {
        self.contains(Flags::FIN)
    }
    pub fn has_rst(self) -> bool {
        self.contains(Flags::RST)
    }
    pub fn has_psh(self) -> bool {
        self.contains(Flags::PSH)
    }
    /// 是否携带任何标志；五项全零的段本栈只当作纯 ACK 处理。
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for Flags {
    type Output = Flags;
    fn bitor(self, other: Flags) -> Flags {
        Flags(self.0 | other.0)
    }
}

/// 已解析的 TCP 段：序号、确认号、标志与载荷视图。
///
/// `payload` 借自调用方的段字节，不复制、不持有所有权。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment<'a> {
    /// 发送端序号。
    pub seq: u32,
    /// 确认号；未置 ACK 时其值无意义，本模块原样保留。
    pub ack: u32,
    /// 标志位。
    pub flags: Flags,
    /// 接收窗口通告。
    pub window: u16,
    /// 载荷视图，长度即 `len - data_offset * 4`。
    pub payload: &'a [u8],
}

impl<'a> Segment<'a> {
    /// 序号消耗量：SYN 与 FIN 各占一个序号（RFC 9293 §3.4）。
    pub fn sequence_length(&self) -> u32 {
        let marks = u32::from(self.flags.has_syn()) + u32::from(self.flags.has_fin());
        marks + self.payload.len() as u32
    }
    /// 载荷之后的下一个序号（回绕安全）。
    pub fn next_seq(&self) -> u32 {
        self.seq.wrapping_add(self.sequence_length())
    }
    /// 载荷是否为空。
    pub fn is_empty_payload(&self) -> bool {
        self.payload.is_empty()
    }
    /// 窗口字段是否为零：用于识别对端宣告的零窗口。
    pub fn zero_window(&self) -> bool {
        self.window == 0
    }
}

/// 解析已定位好的 TCP 段字节（不含 IP 头部）。
///
/// 只接受数据偏移 5..=15、段长与数据偏移精确一致、第 13 字节低 4 位为零的段。
/// 调用方应先用 [`packet::inspect`] 取 `payload_offset`，再用 `&bytes[offset..]`
/// 调用本函数；如果传入的是整个 IP 报文，本函数会按段长不符拒绝而不是误解析。
pub fn parse(ip_payload: &[u8]) -> Result<Segment<'_>, Error> {
    if ip_payload.len() < MIN_HEADER {
        return Err(Error::Incomplete);
    }
    let offset_byte = *ip_payload
        .get(OFFSET_DATA_OFFSET)
        .ok_or(Error::Incomplete)?;
    let flag_byte = *ip_payload.get(OFFSET_FLAGS).ok_or(Error::Incomplete)?;
    let units = usize::from(offset_byte >> SHIFT_DATA_OFFSET);
    let header = units * OFFSET_UNIT;
    // 数据偏移本身必须合法，其次才谈得上与段长比对。
    if !(MIN_HEADER..=MAX_HEADER).contains(&header) {
        return Err(Error::DataOffset(header));
    }
    // 数据偏移给的是头部字节数，段长必须容纳头部；多出的部分就是载荷。
    if header > ip_payload.len() {
        return Err(Error::LengthMismatch);
    }
    let reserved = offset_byte & MASK_RESERVED_LOW;
    if reserved != 0 {
        return Err(Error::Reserved(reserved));
    }
    let payload = ip_payload.get(header..).ok_or(Error::LengthMismatch)?;
    Ok(Segment {
        seq: be32(ip_payload, OFFSET_SEQ)?,
        ack: be32(ip_payload, OFFSET_ACK)?,
        flags: Flags::from_byte(flag_byte),
        window: be16(ip_payload, OFFSET_WINDOW)?,
        payload,
    })
}

/// 构造 TCP 段的字节序列（不含 IP 头部）。
///
/// `header_len` 为数据偏移 × 4，必须落在 20..=60 且为 4 的倍数；`options` 必须
/// 恰好填满 `header_len - MIN_HEADER` 字节。伪首部 `pseudo` 由调用方按 IP 版本
/// 给出（协议号为 TCP），校验和按 RFC 1071 就地写入段内校验和字段。
///
/// 返回的段可直接交给 [`checksum::verify`] 交叉验证——这是本模块与校验和模块
/// 唯一的约定。
#[allow(clippy::too_many_arguments)]
pub fn build(
    source_port: u16,
    destination_port: u16,
    seq: u32,
    ack: u32,
    flags: Flags,
    window: u16,
    options: &[u8],
    payload: &[u8],
    pseudo: &[u8],
) -> Result<Vec<u8>, Error> {
    let header = MIN_HEADER
        .checked_add(options.len())
        .ok_or(Error::BuildLength(options.len()))?;
    let total = header
        .checked_add(payload.len())
        .ok_or(Error::BuildLength(payload.len()))?;
    if u16::try_from(total).is_err() || header > MAX_HEADER {
        return Err(Error::BuildLength(total));
    }
    if !options.len().is_multiple_of(OFFSET_UNIT) {
        return Err(Error::BuildArgument);
    }
    let mut segment = vec![0u8; total];
    segment[0..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[OFFSET_SEQ..OFFSET_SEQ + 4].copy_from_slice(&seq.to_be_bytes());
    segment[OFFSET_ACK..OFFSET_ACK + 4].copy_from_slice(&ack.to_be_bytes());
    let units = u8::try_from(header / OFFSET_UNIT).map_err(|_| Error::BuildArgument)?;
    segment[OFFSET_DATA_OFFSET] = units << SHIFT_DATA_OFFSET;
    segment[OFFSET_FLAGS] = flags.bits();
    segment[OFFSET_WINDOW..OFFSET_WINDOW + 2].copy_from_slice(&window.to_be_bytes());
    // 校验和字段（16..18）与紧急指针（18..20）保持为零：本栈不发紧急数据。
    segment[MIN_HEADER..header].copy_from_slice(options);
    segment[header..].copy_from_slice(payload);
    let sum = checksum::checksum_of(&[pseudo, &segment]);
    segment[OFFSET_CHECKSUM..OFFSET_URGENT].copy_from_slice(&sum.to_be_bytes());
    Ok(segment)
}

/// 读取大端 32 位字段；越界返回 [`Error::Incomplete`]，不裸索引。
fn be32(bytes: &[u8], at: usize) -> Result<u32, Error> {
    let end = at.checked_add(4).ok_or(Error::Incomplete)?;
    let slice = bytes.get(at..end).ok_or(Error::Incomplete)?;
    let mut value = [0u8; 4];
    value.copy_from_slice(slice);
    Ok(u32::from_be_bytes(value))
}

/// 读取大端 16 位字段；越界返回 [`Error::Incomplete`]。
fn be16(bytes: &[u8], at: usize) -> Result<u16, Error> {
    let end = at.checked_add(2).ok_or(Error::Incomplete)?;
    let slice = bytes.get(at..end).ok_or(Error::Incomplete)?;
    let mut value = [0u8; 2];
    value.copy_from_slice(slice);
    Ok(u16::from_be_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造校验和交叉验证用的 IPv4 伪首部（协议号固定为 TCP=6）。
    fn pseudo(len: usize) -> Vec<u8> {
        let mut p = vec![0u8; 12];
        p[0..4].copy_from_slice(&[10, 0, 0, 1]);
        p[4..8].copy_from_slice(&[10, 0, 0, 2]);
        p[9] = 6;
        p[10..12].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        p
    }

    /// 构造一个无选项段（其余字段固定）。
    fn sample(flags: Flags, payload: &[u8]) -> Vec<u8> {
        let ps = pseudo(MIN_HEADER + payload.len());
        build(
            1234,
            80,
            0x1122_3344,
            0x5566_7788,
            flags,
            4096,
            &[],
            payload,
            &ps,
        )
        .unwrap()
    }

    /// 把段接在一个最小 IPv4 头部后面，供 `checksum::verify` 交叉验证。
    fn wrap_ipv4(segment: &[u8]) -> Vec<u8> {
        let total = u16::try_from(20 + segment.len()).unwrap();
        let mut p = vec![0u8; 20 + segment.len()];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let hdr = checksum::checksum_of(&[&p[..20]]);
        p[10..12].copy_from_slice(&hdr.to_be_bytes());
        p[20..].copy_from_slice(segment);
        p
    }

    #[test]
    fn round_trip_and_checksum_cross_check() {
        let bytes = sample(Flags::SYN | Flags::ACK, b"hello");
        let parsed = parse(&bytes).unwrap();
        let (seq, ack, win) = (parsed.seq, parsed.ack, parsed.window);
        assert_eq!((seq, ack, win), (0x1122_3344, 0x5566_7788, 4096));
        let flags = Flags::SYN | Flags::ACK;
        assert_eq!((parsed.flags, parsed.payload), (flags, &b"hello"[..]));
        let (len, next) = (parsed.sequence_length(), parsed.next_seq());
        assert_eq!((len, next), (6, 0x1122_3344 + 6));
        // 构造的校验和必须被 checksum::verify 接受（与校验和模块的唯一约定）。
        let wrapped = sample(Flags::ACK | Flags::PSH, b"payload");
        let info = checksum::verify(&wrap_ipv4(&wrapped)).unwrap();
        assert_eq!((info.source_port, info.destination_port), (1234, 80));
        // 纯 ACK 段无载荷；FIN 也各占一个序号。
        let empty = sample(Flags::ACK, &[]);
        assert_eq!(parse(&empty).unwrap().sequence_length(), 0);
        let fin = sample(Flags::SYN | Flags::FIN, b"xy");
        assert_eq!(parse(&fin).unwrap().sequence_length(), 4);
    }

    #[test]
    fn options_are_carried_in_data_offset() {
        let payload = b"opt";
        let ps = pseudo(MIN_HEADER + 4 + 3);
        let segment = build(1, 2, 3, 4, Flags::ACK, 5, &[1, 1, 1, 1], payload, &ps).unwrap();
        assert_eq!(segment.len(), MIN_HEADER + 4 + 3);
        let parsed = parse(&segment).unwrap();
        assert_eq!((parsed.payload, parsed.window), (&payload[..], 5));
    }

    // ---- 畸形输入：以下每条都必须返回 Err 而不是 panic ----

    #[test]
    fn malformed_headers_are_rejected_not_panicked() {
        // 1) 截断到最小头部之下。
        for len in 0..MIN_HEADER {
            assert_eq!(parse(&vec![0x50u8; len]), Err(Error::Incomplete));
        }
        // 2) 数据偏移小于 5。
        let mut s = vec![0x50u8; MIN_HEADER];
        for units in 0..5u8 {
            s[12] = units << 4;
            assert_eq!(parse(&s), Err(Error::DataOffset(usize::from(units) * 4)));
        }
        // 3) 数据偏移超过段长（声称 60，段长 20）。
        s[12] = 0xf0;
        assert_eq!(parse(&s), Err(Error::LengthMismatch));
        // 补足到 60 字节后同一偏移可解析且载荷为空。
        let mut full = vec![0x50u8; MAX_HEADER];
        full[12] = 0xf0;
        assert!(parse(&full).unwrap().payload.is_empty());
        // 4) 头部加载荷是合法段，不是「段长不符」。
        let mut with_payload = vec![0x50u8; MIN_HEADER + 1];
        with_payload[12] = 0x50;
        assert_eq!(parse(&with_payload).unwrap().payload.len(), 1);
        // 5) 保留位（数据偏移字节低 4 位）非零一律拒绝。
        let mut r = vec![0x50u8; MIN_HEADER];
        for low in 1..=0x0fu8 {
            r[12] = 0x50 | low;
            assert_eq!(parse(&r), Err(Error::Reserved(low)));
        }
        // 6) 标志字节里的 CWR/ECE 不属实现位，被静默丢弃而非拒绝。
        r[12] = 0x50;
        r[13] = Flags::ACK.bits() | 0xc0;
        assert_eq!(parse(&r).unwrap().flags, Flags::ACK);
        // 7) 全零标志按纯 ACK 段解析。
        r[13] = 0;
        assert!(parse(&r).unwrap().flags.is_empty());
        // 8) 序号回绕边界：u32::MAX + SYN 的下一序号为 0。
        let mut w = vec![0x50u8; MIN_HEADER];
        w[12] = 0x50;
        w[13] = Flags::SYN.bits();
        w[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        let parsed = parse(&w).unwrap();
        let (seq, next, len) = (parsed.seq, parsed.next_seq(), parsed.sequence_length());
        assert_eq!((seq, next, len), (u32::MAX, 0, 1));
    }

    #[test]
    fn build_rejects_out_of_range_arguments() {
        let ps = pseudo(MIN_HEADER);
        let run = |opts: &[u8], pl: &[u8]| build(1, 2, 3, 4, Flags::ACK, 5, opts, pl, &ps);
        let too_long = Error::BuildLength(MIN_HEADER + 64);
        assert_eq!(run(&[0u8; 64], &[]), Err(too_long));
        assert_eq!(run(&[0u8; 3], &[]), Err(Error::BuildArgument));
        let huge = Error::BuildLength(70_000 + MIN_HEADER);
        assert_eq!(run(&[], &vec![0u8; 70_000]), Err(huge));
    }

    #[test]
    fn flags_are_masked_to_implemented_bits() {
        let all = Flags::SYN | Flags::ACK | Flags::FIN | Flags::RST | Flags::PSH;
        assert_eq!(Flags::from_byte(0xff), all);
        assert_eq!(Flags::from_byte(0x00), Flags::NONE);
        assert!(Flags::SYN.has_syn() && !Flags::SYN.has_ack());
    }
}
