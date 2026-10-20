//! 路径 MTU 判定与 PMTUD 错误报文生成原语；子模块 `probe` 提供 MSS clamp 与
//! 按 ICMP 过大通告下调路径 MTU 的状态机（纯逻辑，不探测真实网卡）。
//!
//! 输入只有接口 MTU、报文总长与方向，输出「可发 / 过大」决策；判定不依赖系统调用、
//! 不分片、不重组，也不发送任何报文——生成的错误报文以字节数组返回，是否写出由
//! 上层设备接入部分决定。
//!
//! 方向语义：
//! - [`Direction::Egress`]：本机或转发路径准备把报文交给链路，过大时**允许**回报
//!   PMTUD 错误（[`Decision::may_report`]）。
//! - [`Direction::Ingress`]：报文来自链路，过大时**不得**回报错误。RFC 1122 禁止对
//!   错误报文再回错误，对入站方向回报还会放大环路，因此该方向的判定只给出结果。
//!
//! 本模块不分片，也不看原报文的 DF 位：是否改走分片或丢弃属于上层策略。
//!
//! MTU 下限按协议族拒绝：IPv4 取 RFC 1191 的 576，IPv6 取 RFC 1981 与 RFC 8201 的
//! 1280；IPv4 的 Next-Hop MTU 字段只有低 15 位可用（RFC 1191 要求最高位为 0），
//! 因此上限 32767。校验和一律复用 [`crate::checksum`] 的 RFC 1071 折叠实现，
//! 本模块不重写第二份算法。

use std::net::IpAddr;

use crate::checksum;
use crate::packet;

mod probe;

pub use probe::{
    MssClamp, MtuError, PmtudState, IPV4_HEADER_BYTES, IPV6_HEADER_BYTES, MAX_MSS_V4, MAX_MSS_V6,
    MAX_MTU, MIN_MSS_V4, MIN_MSS_V6, MIN_MTU, RFC1191_PLATEAUS, TCP_HEADER_BYTES,
};

/// IPv4 协议字段偏移。
const IPV4_PROTOCOL: usize = 9;
/// IPv6 下一头字段偏移。
const IPV6_NEXT_HEADER: usize = 6;
/// TCP 协议号，与 `packet` 接受的集合一致。
const PROTOCOL_TCP: u8 = 6;
/// UDP 协议号，与 `packet` 接受的集合一致。
const PROTOCOL_UDP: u8 = 17;

/// IPv4 PMTU 下限（RFC 1191）。
pub const MIN_PATH_MTU_V4: u16 = 576;
/// IPv6 PMTU 下限（RFC 1981 与 RFC 8201 的最小链路 MTU）。
pub const MIN_PATH_MTU_V6: u16 = 1280;
/// IPv4 Next-Hop MTU 字段可用上限：RFC 1191 规定最高位必须清零，只剩 15 位。
pub const MAX_MTU_V4_FIELD: u16 = 32767;
/// IP 报文长度上限：IPv4 总长度与 IPv6 载荷长度都可表达的最大值。
pub const MAX_IP_LENGTH: usize = u16::MAX as usize;
/// 错误报文必须携带的上层头部字节数（RFC 792 与 RFC 4443 均要求至少 8 字节）。
pub const CARRY_TRANSPORT_BYTES: usize = 8;
/// IPv4 头部最小长度（IHL=5）。
const IHL_MIN: usize = 20;
/// IPv4 头部最大长度（IHL=15）。
const IHL_MAX: usize = 60;
/// IHL 字段的单位字节数。
const IHL_UNIT: usize = 4;
/// IPv6 固定头部长度。
const IPV6_HEADER: usize = 40;
/// ICMP 固定头部长度：类型、代码、校验和、四个零字节（IPv6 的 MTU 字段另计）。
const ICMP_HEADER: usize = 8;
/// 错误报文外层 IPv4 头部长度：本模块恒用 IHL=5。
const ERROR_IPV4_HEADER: usize = IHL_MIN;
/// IPv6 伪首部长度。
const IPV6_PSEUDO: usize = 40;
/// 错误报文的跳数/存活时间。
const ERROR_HOP_LIMIT: u8 = 255;
/// ICMPv4 Destination Unreachable（RFC 792）。
const ICMPV4_DEST_UNREACHABLE: u8 = 3;
/// ICMPv4 code 4：需要分片但设置了 DF（RFC 1191）。
const ICMPV4_FRAG_NEEDED: u8 = 4;
/// ICMPv4 的 IPv4 协议号。
const PROTOCOL_ICMPV4: u8 = 1;
/// ICMPv6 Packet Too Big（RFC 4443）。
const ICMPV6_PACKET_TOO_BIG: u8 = 2;
/// ICMPv6 的 IPv6 下一头值。
const NEXT_HEADER_ICMPV6: u8 = 58;

/// 判定与生成错误时使用的协议族。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    /// 该协议族的 PMTU 下限；低于此值的接口 MTU 一律拒绝。
    pub fn floor(self) -> u16 {
        match self {
            IpVersion::V4 => MIN_PATH_MTU_V4,
            IpVersion::V6 => MIN_PATH_MTU_V6,
        }
    }

    /// 从首字节版本 nibble 判定协议族，4 与 6 之外一律拒绝。
    pub fn of(packet: &[u8]) -> Result<Self, packet::Error> {
        match packet.first().ok_or(packet::Error::Incomplete)? >> 4 {
            4 => Ok(IpVersion::V4),
            6 => Ok(IpVersion::V6),
            _ => Err(packet::Error::UnsupportedVersion),
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (IpVersion::V4, IpAddr::V4(_)) | (IpVersion::V6, IpAddr::V6(_))
        )
    }
}

/// 报文相对本机的方向，决定过大时能否回报 PMTUD 错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// 交给链路发出。
    Egress,
    /// 来自链路。
    Ingress,
}

/// 本模块的错误种类。全部是拒绝语义，不存在「退回不分片」一类的静默回退。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// 接口 MTU 或要上报的 MTU 低于该协议族下限，或 IPv4 超出 15 位字段上限。
    #[error("MTU {value} 不在 {family:?} 的许可区间内")]
    MtuOutOfRange { family: IpVersion, value: u16 },
    /// 报文长度为 0 或超过 16 位可表达的范围。
    #[error("报文总长 {0} 非法")]
    PacketLength(usize),
    /// 原报文头部解析失败，逐字保留 `packet` 的原始种类。
    #[error("原报文头部解析失败：{0}")]
    Packet(#[from] packet::Error),
    /// 原报文已是 ICMP/IGMP/ICMPv6，或不是直接承载的 TCP/UDP：不得回报错误。
    #[error("该原报文不允许回报 PMTUD 错误")]
    NotReportable,
    /// 原报文短于「IP 头部 + 8 字节上层头部」，无法按 RFC 截取。
    #[error("原报文短于 IP 头部加 8 字节，无法截取")]
    IncompleteOriginal,
    /// 错误报文的目的地址（即原报文源地址）不可作为单播目标。
    #[error("错误报文目的地址不可用")]
    UnreachableTarget,
    /// 调用方给出的错误源地址与原报文协议族不一致。
    #[error("错误源地址与原报文协议族不一致")]
    SourceFamily,
}

/// 路径 MTU 判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// 报文总长不超过接口 MTU，可直接发出。
    Send,
    /// 报文总长超过接口 MTU。`mtu` 为接口 MTU，`direction` 决定能否回报错误。
    TooBig {
        mtu: u16,
        packet_len: usize,
        direction: Direction,
    },
}

impl Decision {
    pub fn is_send(self) -> bool {
        matches!(self, Decision::Send)
    }

    /// 过大时返回（接口 MTU, 报文总长）。
    pub fn too_big(self) -> Option<(u16, usize)> {
        match self {
            Decision::Send => None,
            Decision::TooBig {
                mtu, packet_len, ..
            } => Some((mtu, packet_len)),
        }
    }

    /// 仅 Egress 方向的过大判定允许生成 PMTUD 错误；入站与「可发」一律为假。
    pub fn may_report(self) -> bool {
        matches!(
            self,
            Decision::TooBig {
                direction: Direction::Egress,
                ..
            }
        )
    }
}

/// 判定报文能否按接口 MTU 发出。
///
/// `interface_mtu` 低于该协议族下限时返回 [`Error::MtuOutOfRange`]（拒绝，不是按
/// 下限夹紧）；`packet_len` 为 0 或超过 16 位时返回 [`Error::PacketLength`]。
/// 判定本身只看长度，方向只影响 [`Decision::may_report`]。
pub fn decide(
    family: IpVersion,
    interface_mtu: u16,
    packet_len: usize,
    direction: Direction,
) -> Result<Decision, Error> {
    check_floor(family, interface_mtu)?;
    if packet_len == 0 || packet_len > MAX_IP_LENGTH {
        return Err(Error::PacketLength(packet_len));
    }
    if packet_len <= usize::from(interface_mtu) {
        return Ok(Decision::Send);
    }
    Ok(Decision::TooBig {
        mtu: interface_mtu,
        packet_len,
        direction,
    })
}

/// 从报文首字节取协议族、以缓冲区实际长度做判定。
pub fn decide_from(
    packet: &[u8],
    interface_mtu: u16,
    direction: Direction,
) -> Result<Decision, Error> {
    let family = IpVersion::of(packet)?;
    decide(family, interface_mtu, packet.len(), direction)
}

/// 生成 PMTUD 错误报文：完整的外层 IP 头部加 ICMP/ICMPv6 消息。
///
/// `original` 必须是 [`packet::inspect`] 与 [`carried_prefix`] 都能接受的原始报文；
/// `next_hop_mtu` 是上报的 MTU；`source` 是本机在该链路上的地址，必须与原报文同族。
/// 错误报文的目的地址取自原报文的源地址，本函数不接受调用方覆盖，以免伪造目标。
///
/// 生成器不核对 `next_hop_mtu` 是否真的小于原包长度：那属于 [`decide`] 的判定职责，
/// 这里只保证字段与校验和的正确性。
pub fn error_packet(original: &[u8], next_hop_mtu: u16, source: IpAddr) -> Result<Vec<u8>, Error> {
    let family = IpVersion::of(original)?;
    check_floor(family, next_hop_mtu)?;
    if family == IpVersion::V4 && next_hop_mtu > MAX_MTU_V4_FIELD {
        return Err(Error::MtuOutOfRange {
            family,
            value: next_hop_mtu,
        });
    }
    if !family.contains(source) {
        return Err(Error::SourceFamily);
    }
    let prefix = carried_prefix(original)?;
    let info = packet::inspect(original)?;
    if !unicast_target(info.source) {
        return Err(Error::UnreachableTarget);
    }
    match family {
        IpVersion::V4 => build_v4(original, prefix, next_hop_mtu, source, info.source),
        IpVersion::V6 => build_v6(prefix, next_hop_mtu, source, info.source),
    }
}

/// 需要携带的前缀：原 IP 头部全部字节（含 IPv4 选项）加上层头部的前 8 字节。
/// 返回切片的长度恒为偶数（IP 头部 20/24/…/60 与 IPv6 固定 40 都是偶数，
/// 追加的 8 字节也是偶数），因此校验和计算不需要补白。
///
/// 本函数只做截取，不核对原报文的长度字段是否自洽：那是 [`packet::inspect`] 的职责，
/// 由 [`error_packet`] 在生成前调用。单独调用时它给出的是「若要回报该报文应携带的字节」，
/// 调用方仍需自行确认报文合法。
pub fn carried_prefix(original: &[u8]) -> Result<&[u8], Error> {
    let family = IpVersion::of(original)?;
    require_reportable(family, original)?;
    let header = ip_header_len(original)?;
    let end = header
        .checked_add(CARRY_TRANSPORT_BYTES)
        .ok_or(Error::IncompleteOriginal)?;
    original.get(..end).ok_or(Error::IncompleteOriginal)
}

/// 只有直接承载 TCP(6) 或 UDP(17) 的原报文才允许回报错误：RFC 1122 禁止对
/// ICMP/ICMPv6 错误报文再回错误（环路放大），IGMP 查询同样排除，其余协议本 crate
/// 不分片也不重组，一律不回报。检查直接落在 IPv4 偏移 9 / IPv6 偏移 6 的协议字段上，
/// 因此分片、扩展头之类的复杂输入也只会被判定为「不可回报」，不会误生成错误报文。
fn require_reportable(family: IpVersion, original: &[u8]) -> Result<(), Error> {
    let offset = match family {
        IpVersion::V4 => IPV4_PROTOCOL,
        IpVersion::V6 => IPV6_NEXT_HEADER,
    };
    let protocol = *original.get(offset).ok_or(packet::Error::Incomplete)?;
    if !matches!(protocol, PROTOCOL_TCP | PROTOCOL_UDP) {
        return Err(Error::NotReportable);
    }
    Ok(())
}

/// 错误报文目标地址的可用性：未指定地址与组播地址一律拒绝。
/// 回环与测试网段等普通单播允许，本机发出的流量经 TUN 回来时源地址可能就是回环。
fn unicast_target(address: IpAddr) -> bool {
    !address.is_unspecified() && !address.is_multicast()
}

/// IP 头部长度：IPv4 为 IHL × 4 且落在 20..=60，IPv6 固定 40。
/// `packet::inspect` 已核对同一区间，这里不依赖上游保证。
fn ip_header_len(packet: &[u8]) -> Result<usize, Error> {
    let first = *packet.first().ok_or(packet::Error::Incomplete)?;
    match first >> 4 {
        4 => {
            let header = usize::from(first & 0x0f) * IHL_UNIT;
            if !(IHL_MIN..=IHL_MAX).contains(&header) {
                return Err(Error::Packet(packet::Error::HeaderLength));
            }
            Ok(header)
        }
        6 => Ok(IPV6_HEADER),
        _ => Err(Error::Packet(packet::Error::UnsupportedVersion)),
    }
}

fn check_floor(family: IpVersion, mtu: u16) -> Result<(), Error> {
    if mtu < family.floor() {
        return Err(Error::MtuOutOfRange { family, value: mtu });
    }
    Ok(())
}

/// 组装 IPv4 错误报文：20 字节外层头部 + 8 字节 ICMP 头部 + 截取前缀。
/// 校验和分两次计算：ICMP 消息（含伪首部为零，RFC 792 只用 ICMP 段）与外层头部。
fn build_v4(
    original: &[u8],
    prefix: &[u8],
    next_hop_mtu: u16,
    source: IpAddr,
    destination: IpAddr,
) -> Result<Vec<u8>, Error> {
    let message_len = ICMP_HEADER + prefix.len();
    let total = ERROR_IPV4_HEADER + message_len;
    let total = u16::try_from(total).map_err(|_| Error::PacketLength(total))?;
    let mut packet = vec![0u8; usize::from(total)];
    packet[0] = 0x45;
    // RFC 1191 建议复制原报文的 TOS，使按服务类型维护的 PMTU 缓存保持一致。
    packet[1] = original.get(1).copied().unwrap_or_default();
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    // 标识、标志与片偏移保持为零：错误报文本身足够短，不需要分片。
    packet[8] = ERROR_HOP_LIMIT;
    packet[9] = PROTOCOL_ICMPV4;
    packet[12..16].copy_from_slice(&ip_bytes(source)[12..]);
    packet[16..20].copy_from_slice(&ip_bytes(destination)[12..]);
    let icmp = ERROR_IPV4_HEADER;
    packet[icmp] = ICMPV4_DEST_UNREACHABLE;
    packet[icmp + 1] = ICMPV4_FRAG_NEEDED;
    // icmp+2..+4 为校验和，+4..+6 为 RFC 792 保留的零字节，+6..+8 为 Next-Hop MTU。
    packet[icmp + 6..icmp + 8].copy_from_slice(&next_hop_mtu.to_be_bytes());
    packet[icmp + ICMP_HEADER..].copy_from_slice(prefix);
    let message = checksum::checksum_of(&[&packet[icmp..]]);
    packet[icmp + 2..icmp + 4].copy_from_slice(&message.to_be_bytes());
    let header = checksum::checksum_of(&[&packet[..ERROR_IPV4_HEADER]]);
    packet[10..12].copy_from_slice(&header.to_be_bytes());
    Ok(packet)
}

/// 组装 IPv6 错误报文：40 字节外层头部 + ICMPv6 Packet Too Big。
/// Packet Too Big 的固定头部就是 8 字节（类型、代码、校验和、32 位 MTU 字段），
/// MTU 字段取代了通用 ICMPv6 头部的保留位，因此不再额外加长。
/// ICMPv6 校验和必须带伪首部（RFC 4443 §2.4 与 RFC 8200），因此外层地址先就位再求和。
fn build_v6(
    prefix: &[u8],
    next_hop_mtu: u16,
    source: IpAddr,
    destination: IpAddr,
) -> Result<Vec<u8>, Error> {
    let message_len = ICMP_HEADER + prefix.len();
    let length = u16::try_from(message_len).map_err(|_| Error::PacketLength(message_len))?;
    let mut packet = vec![0u8; IPV6_HEADER + message_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&length.to_be_bytes());
    packet[6] = NEXT_HEADER_ICMPV6;
    packet[7] = ERROR_HOP_LIMIT;
    packet[8..24].copy_from_slice(&ip_bytes(source));
    packet[24..40].copy_from_slice(&ip_bytes(destination));
    let icmp = IPV6_HEADER;
    packet[icmp] = ICMPV6_PACKET_TOO_BIG;
    // icmp+2..+4 为校验和，+4..+8 为 MTU 字段（RFC 4443 中该字段取代保留位）。
    packet[icmp + 4..icmp + 8].copy_from_slice(&u32::from(next_hop_mtu).to_be_bytes());
    packet[icmp + ICMP_HEADER..].copy_from_slice(prefix);
    let mut pseudo = [0u8; IPV6_PSEUDO];
    pseudo[0..16].copy_from_slice(&ip_bytes(source));
    pseudo[16..32].copy_from_slice(&ip_bytes(destination));
    pseudo[32..36].copy_from_slice(&u32::try_from(message_len).unwrap_or(u32::MAX).to_be_bytes());
    pseudo[39] = NEXT_HEADER_ICMPV6;
    let message = checksum::checksum_of(&[&pseudo, &packet[icmp..]]);
    packet[icmp + 2..icmp + 4].copy_from_slice(&message.to_be_bytes());
    Ok(packet)
}

/// 地址的字节表示，IPv4 只占后 4 字节，IPv6 占满 16 字节。
fn ip_bytes(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(v4) => {
            let mut bytes = [0u8; 16];
            bytes[12..].copy_from_slice(&v4.octets());
            bytes
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}
