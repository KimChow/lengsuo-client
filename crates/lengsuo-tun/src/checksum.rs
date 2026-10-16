//! TCP/UDP 传输层校验和验证：RFC 1071 一补码和，覆盖伪首部与整个传输段。
//!
//! 本模块的公开 API 只做验证，不改写报文、不创建平台 TUN 设备、不回填校验和，
//! 也不验证 TCP 状态机或任何应用层语义。头部结构检查复用 `packet::inspect`，
//! 因此分片、扩展头、长度不一致和 IPv4 头部校验和失败仍以其原始错误种类返回。
//!
//! 唯一的例外是本 crate 内部可见的 [`checksum_of`]：`mtu` 生成 PMTUD 错误报文时
//! 需要写入 ICMP 校验和，复用同一 RFC 1071 算法而不是另写一份。它不属于验证 API，
//! 不改变 `verify` 的任何语义。
//!
//! 已知范围限制：IPv4 的 UDP 校验和字段为 0 表示发送端未计算（RFC 768），本模块
//! 按未提供放行；IPv6 的 UDP 校验和字段为 0 一律拒绝（RFC 8200），TCP 在两个版本
//! 下都必须校验。通过本模块不等于报文来自可信对端，也不构成完整的入站安全验证。

use crate::packet::{self, PacketInfo, Transport};

/// 一个 16 位字占用的字节数。
const WORD: usize = 2;
/// IPv4 伪首部长度：源与目的地址各 4 字节、零字节、协议、16 位长度。
const IPV4_PSEUDO: usize = 12;
/// IPv6 伪首部长度：源与目的地址各 16 字节、32 位长度、三个零字节、下一头。
const IPV6_PSEUDO: usize = 40;
/// IPv6 固定头部长度，也就是 IPv6 传输段的起始偏移。
const IPV6_HEADER: usize = 40;
/// IPv4 IHL 字段的低位掩码，单位为 4 字节。
const IHL_MASK: u8 = 0x0f;
/// IHL 的单位字节数。
const IHL_UNIT: usize = 4;
/// IPv4 源地址起始偏移。
const IPV4_SOURCE: usize = 12;
/// IPv4 目的地址起始偏移。
const IPV4_DESTINATION: usize = 16;
/// IPv4 协议字段偏移。
const IPV4_PROTOCOL: usize = 9;
/// IPv6 源地址起始偏移（目的地址紧随其后，合计 8..40）。
const IPV6_SOURCE: usize = 8;
/// IPv6 目的地址起始偏移。
const IPV6_DESTINATION: usize = 24;
/// IPv6 下一头字段偏移。
const IPV6_NEXT_HEADER: usize = 6;
/// TCP 校验和字段在传输段内的偏移。
const TCP_CHECKSUM: usize = 16;
/// UDP 校验和字段在传输段内的偏移。
const UDP_CHECKSUM: usize = 6;
/// 一补码和折叠后的合法结果：接收端把收到的校验和字段一并计入时应得到全 1。
const VALID_SUM: u16 = 0xffff;

/// 本模块的错误种类。头部结构问题保留 `packet` 的原始种类，校验和问题单独返回。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// 报文头部解析失败，逐字保留 `packet::Error`。
    #[error("报文头部解析失败：{0}")]
    Packet(#[from] packet::Error),
    /// 伪首部与整个传输段的一补码和不为全 1，或按规则必须校验却收到零校验和。
    #[error("传输层校验和不正确")]
    TransportChecksum,
}

/// 伪首部按版本分别落在固定大小的数组里，避免为一次验证分配堆内存。
enum PseudoHeader {
    V4([u8; IPV4_PSEUDO]),
    V6([u8; IPV6_PSEUDO]),
}

impl PseudoHeader {
    fn as_bytes(&self) -> &[u8] {
        match self {
            PseudoHeader::V4(bytes) => bytes,
            PseudoHeader::V6(bytes) => bytes,
        }
    }
}

/// 先取得 `packet::inspect` 已核对的元数据，再验证 TCP/UDP 传输段校验和。
///
/// 校验和字段为 0 时：IPv4 UDP 视为未提供并放行；IPv6 UDP 返回 `TransportChecksum`；两个版本的 TCP 均按正常规则计算，
/// 字段为零不代表免校验。其余情况把伪首部和传输段（含校验和字段本身）一起计入
/// 一补码和，结果必须为全 1。
pub fn verify(packet: &[u8]) -> Result<PacketInfo, Error> {
    let info = packet::inspect(packet)?;
    let start = transport_start(packet)?;
    let segment = packet.get(start..).ok_or(packet::Error::Incomplete)?;
    let provided = be16(segment, checksum_field(info.protocol))?;
    if provided == 0 && info.protocol == Transport::Udp {
        // IPv4：字段为 0 表示发送端未计算校验和（RFC 768），按未提供放行。
        // IPv6：字段为 0 非法（RFC 8200），必须拒绝。
        return if info.source.is_ipv4() {
            Ok(info)
        } else {
            Err(Error::TransportChecksum)
        };
    }
    // TCP 即使在两个版本下都必须校验：字段为 0 时也照常计入求和，不跳过。
    let pseudo = pseudo_header(packet, segment.len())?;
    if ones_complement_sum(&[pseudo.as_bytes(), segment]) == VALID_SUM {
        Ok(info)
    } else {
        Err(Error::TransportChecksum)
    }
}

/// 传输段起始偏移：IPv4 为 IHL × 4，IPv6 为固定 40 字节。两处取值范围都已由
/// `packet::inspect` 核对（IHL 对应 20..=60 且不超过输入长度），这里只做防御性换算。
fn transport_start(packet: &[u8]) -> Result<usize, Error> {
    let first = *packet.first().ok_or(packet::Error::Incomplete)?;
    match first >> 4 {
        4 => usize::from(first & IHL_MASK)
            .checked_mul(IHL_UNIT)
            .ok_or(Error::Packet(packet::Error::HeaderLength)),
        6 => Ok(IPV6_HEADER),
        _ => Err(Error::Packet(packet::Error::UnsupportedVersion)),
    }
}

/// 按版本组装伪首部。长度字段 IPv4 为 16 位、IPv6 为 32 位，均为传输段字节数；
/// 协议号取自 IPv4 偏移 9 与 IPv6 偏移 6，与 `packet::inspect` 已接受的字段一致。
fn pseudo_header(packet: &[u8], segment_len: usize) -> Result<PseudoHeader, Error> {
    let first = *packet.first().ok_or(packet::Error::Incomplete)?;
    match first >> 4 {
        4 => {
            // IPv4 总长度为 16 位，inspect 已要求其与输入字节数精确一致。
            let length = u16::try_from(segment_len)
                .map_err(|_| Error::Packet(packet::Error::TotalLength))?;
            let mut bytes = [0u8; IPV4_PSEUDO];
            bytes[0..4].copy_from_slice(range(packet, IPV4_SOURCE, 4)?);
            bytes[4..8].copy_from_slice(range(packet, IPV4_DESTINATION, 4)?);
            bytes[9] = *packet
                .get(IPV4_PROTOCOL)
                .ok_or(Error::Packet(packet::Error::Incomplete))?;
            bytes[10..IPV4_PSEUDO].copy_from_slice(&length.to_be_bytes());
            Ok(PseudoHeader::V4(bytes))
        }
        6 => {
            let length = u32::try_from(segment_len)
                .map_err(|_| Error::Packet(packet::Error::TotalLength))?;
            let mut bytes = [0u8; IPV6_PSEUDO];
            bytes[0..16].copy_from_slice(range(packet, IPV6_SOURCE, 16)?);
            bytes[16..32].copy_from_slice(range(packet, IPV6_DESTINATION, 16)?);
            bytes[32..36].copy_from_slice(&length.to_be_bytes());
            bytes[39] = *packet
                .get(IPV6_NEXT_HEADER)
                .ok_or(Error::Packet(packet::Error::Incomplete))?;
            Ok(PseudoHeader::V6(bytes))
        }
        _ => Err(Error::Packet(packet::Error::UnsupportedVersion)),
    }
}

/// TCP 与 UDP 的校验和字段在传输段内的偏移。
fn checksum_field(protocol: Transport) -> usize {
    match protocol {
        Transport::Tcp => TCP_CHECKSUM,
        Transport::Udp => UDP_CHECKSUM,
    }
}

/// 本 crate 生成报文时写入校验和所需的内部入口：对给定各段求一补码和并取一补码。
/// 与 `verify` 共用同一段折叠算法，避免在 `mtu` 里重写第二份实现；只读入参，
/// 不改写任何缓冲区，也不参与 `verify` 的判定路径。
pub(crate) fn checksum_of(parts: &[&[u8]]) -> u16 {
    !ones_complement_sum(parts)
}

/// RFC 1071 一补码和：逐 16 位字累加，落单的末尾字节按尾部补零计入，再把进位
/// 循环折叠回 16 位。累加用 u64：达到溢出需要 2^48 个字，远超任何真实报文长度。
/// 所有非末尾分段均为偶数长度（伪首部 12 或 40 字节）；仅末尾传输段可补零。
pub(crate) fn ones_complement_sum(parts: &[&[u8]]) -> u16 {
    let mut sum: u64 = 0;
    for part in parts {
        let (words, tail) = part.as_chunks::<WORD>();
        for word in words {
            sum += u64::from(u16::from_be_bytes([word[0], word[1]]));
        }
        if let Some(odd) = tail.first() {
            sum += u64::from(*odd) << 8;
        }
    }
    let mut folded = sum;
    while folded >> 16 != 0 {
        folded = (folded & u64::from(VALID_SUM)) + (folded >> 16);
    }
    folded as u16
}

/// 读取传输段内的一个大端 16 位字段。
fn be16(bytes: &[u8], at: usize) -> Result<u16, Error> {
    let pair = range(bytes, at, WORD)?;
    Ok(u16::from_be_bytes([pair[0], pair[1]]))
}

/// 把「起点 + 长度」换算成结束下标后再取切片，溢出或越界都按不完整处理。
fn range(bytes: &[u8], start: usize, len: usize) -> Result<&[u8], Error> {
    let end = start.checked_add(len).ok_or(packet::Error::Incomplete)?;
    bytes
        .get(start..end)
        .ok_or(Error::Packet(packet::Error::Incomplete))
}

#[cfg(test)]
mod tests {
    use super::{ones_complement_sum, VALID_SUM};

    /// RFC 1071 的固定向量 `00 01 f2 03 f4 f5 f6 f7`：折叠和为 0xddf2，应写入的
    /// 校验和字段即其一补码 0x220d。两个期望值都取自 RFC 文本，不是由本实现反推。
    #[test]
    fn rfc1071_fixed_vector() {
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(ones_complement_sum(&[&data]), 0xddf2);
        assert_eq!(!ones_complement_sum(&[&data]), 0x220d);
        // 把参考校验和接在数据末尾后，接收端把整段计入的折叠和必须为全 1。
        let mut verified: Vec<u8> = data.to_vec();
        verified.extend_from_slice(&0x220du16.to_be_bytes());
        assert_eq!(ones_complement_sum(&[&verified]), VALID_SUM);
    }

    /// 末尾奇数字节按补零计入；逐段传入与传入连续缓冲结果一致。
    #[test]
    fn odd_tail_is_zero_padded() {
        assert_eq!(ones_complement_sum(&[&[0x00u8, 0xff, 0x00]]), 0x00ff);
        assert_eq!(ones_complement_sum(&[&[0xffu8, 0x00], &[0x01]]), 0x0001);
        assert_eq!(ones_complement_sum(&[&[]]), 0);
        assert_eq!(
            ones_complement_sum(&[&[0x12u8, 0x34, 0x56]]),
            ones_complement_sum(&[&[0x12u8, 0x34, 0x56, 0x00]])
        );
    }

    /// 进位必须循环折叠回 16 位，不能丢弃高位。
    #[test]
    fn carry_folds_back() {
        let all_ones = [0xffu8; 8];
        assert_eq!(ones_complement_sum(&[&all_ones]), VALID_SUM);
        // 4 个 0xffff 加 0x0001 = 0x3fffd -> 0xfffd + 3 = 0x10000 -> 0x0000 + 1。
        assert_eq!(ones_complement_sum(&[&all_ones, &[0x00u8, 0x01]]), 0x0001);
        // 8 个 0xffff = 0x7fff8 -> 0xfff8 + 7 = 0xffff，二次折叠不得停在 17 位。
        assert_eq!(ones_complement_sum(&[&all_ones, &all_ones]), VALID_SUM);
    }
}
