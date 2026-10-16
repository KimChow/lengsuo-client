//! 纯 Rust IP 报文元数据解析：fail-closed，全程带检查的切片访问，不改写报文。
//!
//! 覆盖 IPv4 固定/选项头部与 IPv6 固定 40 字节头部，仅接受直接承载的 TCP(6) 与
//! UDP(17)。IPv4 分片、IPv6 扩展头与长度不一致的报文一律显式拒绝。
//! 不校验 TCP/UDP 传输层校验和，因此不构成完整的入站安全验证。

use std::net::IpAddr;

/// IPv4 头部最小长度，即 IHL=5。
const IPV4_MIN_HEADER: usize = 20;
/// IPv4 IHL 上限：15 × 4 字节。
const IPV4_MAX_HEADER: usize = 60;
/// IPv6 头部固定 40 字节。
const IPV6_HEADER: usize = 40;
/// TCP 头部最小长度，即 data offset=5。
const TCP_MIN_HEADER: usize = 20;
/// TCP data offset 上限：15 × 4 字节。
const TCP_MAX_HEADER: usize = 60;
/// UDP 头部固定 8 字节。
const UDP_HEADER: usize = 8;

const PROTOCOL_TCP: u8 = 6;
const PROTOCOL_UDP: u8 = 17;
/// IPv4「更多分片」标志位。
const FLAG_MORE_FRAGMENTS: u16 = 0x2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// 输入短于头部或传输层头部所需字节。
    #[error("报文尚未完整")]
    Incomplete,
    /// IP 版本 nibble 不是 4 或 6。
    #[error("IP 版本不支持")]
    UnsupportedVersion,
    /// IHL 小于 5 或超出输入长度。
    #[error("IP 头部长度非法")]
    HeaderLength,
    /// 总长度/载荷长度字段与实际输入字节数不一致。
    #[error("IP 长度字段与输入不一致")]
    TotalLength,
    /// IPv4 存在 MF 标志或非零分片偏移。
    #[error("分片报文被拒绝")]
    Fragmented,
    /// IPv4 头部一补码和校验失败。
    #[error("IPv4 头部校验和不正确")]
    Checksum,
    /// 非 TCP/UDP，或 IPv6 携带扩展头与分片。
    #[error("仅支持直接承载的 TCP 与 UDP")]
    UnsupportedProtocol,
    /// TCP data offset 小于 5 或超出 IP 载荷。
    #[error("TCP 数据偏移非法")]
    TcpHeader,
    /// UDP 长度字段与 IP 载荷字节数不一致。
    #[error("UDP 长度与 IP 载荷不一致")]
    UdpLength,
}

/// 本解析器认可的传输协议。
#[derive(Hash, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// 可解析出的报文元数据。不含环境身份、进程或归属信息——这些上下文必须由
/// 调用方自行携带，本模块不会伪造。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInfo {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: Transport,
    pub source_port: u16,
    pub destination_port: u16,
    /// 应用载荷起始偏移（绝对字节位置），零载荷时等于输入长度。
    pub payload_offset: usize,
}

/// 解析单个 IP 报文的头部元数据。只读取，不重组分片，不改写字节。
pub fn inspect(packet: &[u8]) -> Result<PacketInfo, Error> {
    match version(packet)? {
        4 => inspect_ipv4(packet),
        6 => inspect_ipv6(packet),
        _ => Err(Error::UnsupportedVersion),
    }
}

fn version(packet: &[u8]) -> Result<u8, Error> {
    Ok(*packet.first().ok_or(Error::Incomplete)? >> 4)
}

fn inspect_ipv4(packet: &[u8]) -> Result<PacketInfo, Error> {
    if packet.len() < IPV4_MIN_HEADER {
        return Err(Error::Incomplete);
    }
    let header = ipv4_header_len(packet)?;
    if usize::from(be16(packet, 2)?) != packet.len() {
        return Err(Error::TotalLength);
    }
    let flags_fragment = be16(packet, 6)?;
    if flags_fragment & FLAG_MORE_FRAGMENTS != 0 || flags_fragment & 0x1fff != 0 {
        return Err(Error::Fragmented);
    }
    verify_checksum(slice(packet, 0, header)?)?;
    let payload = packet.get(header..).ok_or(Error::Incomplete)?;
    transport(
        payload,
        IpAddr::from(v4(packet, 12)?),
        IpAddr::from(v4(packet, 16)?),
        *packet.get(9).ok_or(Error::Incomplete)?,
        header,
    )
}

/// IHL 字段为 4 位、单位 4 字节，合法范围 20..=60 且不超出输入长度。
fn ipv4_header_len(packet: &[u8]) -> Result<usize, Error> {
    let ihl = u32::from(*packet.first().ok_or(Error::Incomplete)? & 0x0f);
    let header = usize::try_from(ihl * 4).map_err(|_| Error::HeaderLength)?;
    if !matches!(header, IPV4_MIN_HEADER..=IPV4_MAX_HEADER) || header > packet.len() {
        return Err(Error::HeaderLength);
    }
    Ok(header)
}

/// RFC 1071 一补码和：逐 16 位字求和并折叠进位，合法头部结果为 0xffff。
/// IPv4 头部长度恒为偶数，末尾奇数字节分支只是让本函数对任意输入都成立。
fn verify_checksum(header: &[u8]) -> Result<(), Error> {
    let mut sum: u32 = 0;
    let mut index = 0;
    while index + 1 < header.len() {
        sum = sum.wrapping_add(u32::from(be16(header, index)?));
        index += 2;
    }
    if let Some(odd) = header.get(index) {
        sum = sum.wrapping_add(u32::from(*odd) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    match sum & 0xffff {
        0xffff => Ok(()),
        _ => Err(Error::Checksum),
    }
}

fn inspect_ipv6(packet: &[u8]) -> Result<PacketInfo, Error> {
    if packet.len() < IPV6_HEADER {
        return Err(Error::Incomplete);
    }
    // 通信类与流量标签不参与分流判断，只核对载荷长度与下一头。
    let payload_len = usize::from(be16(packet, 4)?);
    let expected = IPV6_HEADER
        .checked_add(payload_len)
        .ok_or(Error::TotalLength)?;
    if expected != packet.len() {
        return Err(Error::TotalLength);
    }
    // 扩展头与分片必须显式拒绝：不遍历逐跳选项，也不重组分片。
    let protocol = *packet.get(6).ok_or(Error::Incomplete)?;
    if !matches!(protocol, PROTOCOL_TCP | PROTOCOL_UDP) {
        return Err(Error::UnsupportedProtocol);
    }
    let payload = packet.get(IPV6_HEADER..).ok_or(Error::Incomplete)?;
    transport(
        payload,
        IpAddr::from(v6(packet, 8)?),
        IpAddr::from(v6(packet, 24)?),
        protocol,
        IPV6_HEADER,
    )
}

/// 校验传输层头部并返回元数据；载荷长度不足最小头部时按不完整处理。
fn transport(
    payload: &[u8],
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    header_end: usize,
) -> Result<PacketInfo, Error> {
    let kind = match protocol {
        PROTOCOL_TCP => Transport::Tcp,
        PROTOCOL_UDP => Transport::Udp,
        _ => return Err(Error::UnsupportedProtocol),
    };
    let source_port = be16(payload, 0)?;
    let destination_port = be16(payload, 2)?;
    let offset = match kind {
        Transport::Tcp => {
            if payload.len() < TCP_MIN_HEADER {
                return Err(Error::Incomplete);
            }
            let offset = u32::from(*payload.get(12).ok_or(Error::Incomplete)? >> 4) * 4;
            let offset = usize::try_from(offset).map_err(|_| Error::TcpHeader)?;
            if !matches!(offset, TCP_MIN_HEADER..=TCP_MAX_HEADER) || offset > payload.len() {
                return Err(Error::TcpHeader);
            }
            offset
        }
        Transport::Udp => {
            if payload.len() < UDP_HEADER {
                return Err(Error::Incomplete);
            }
            // UDP 长度字段必须与 IP 载荷精确一致，多出的尾部垃圾同样拒绝。
            if usize::from(be16(payload, 4)?) != payload.len() {
                return Err(Error::UdpLength);
            }
            UDP_HEADER
        }
    };
    Ok(PacketInfo {
        source,
        destination,
        protocol: kind,
        source_port,
        destination_port,
        payload_offset: header_end.checked_add(offset).ok_or(Error::TcpHeader)?,
    })
}

fn be16(bytes: &[u8], at: usize) -> Result<u16, Error> {
    let pair = slice(bytes, at, 2)?;
    Ok(u16::from_be_bytes([pair[0], pair[1]]))
}

fn v4(bytes: &[u8], at: usize) -> Result<[u8; 4], Error> {
    let mut value = [0u8; 4];
    value.copy_from_slice(slice(bytes, at, 4)?);
    Ok(value)
}

fn v6(bytes: &[u8], at: usize) -> Result<[u8; 16], Error> {
    let mut value = [0u8; 16];
    value.copy_from_slice(slice(bytes, at, 16)?);
    Ok(value)
}

/// 把「起点 + 长度」换算成结束下标后再取切片，溢出或越界一律返回不完整。
fn slice(bytes: &[u8], start: usize, len: usize) -> Result<&[u8], Error> {
    let end = start.checked_add(len).ok_or(Error::Incomplete)?;
    bytes.get(start..end).ok_or(Error::Incomplete)
}
