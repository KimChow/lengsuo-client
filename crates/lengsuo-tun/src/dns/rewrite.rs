//! DNS 查询转发重写与响应回注匹配：纯内存决策，不发包、不建设备、不碰路由。
//!
//! 职责分成两半，都只作用于「一个完整 IP 报文」的字节缓冲：
//! - [`plan_query`] / [`forward_query`]：核对一条 UDP:53 查询的结构与语义，给出
//!   「转发到哪个上游」以及「改址后是否需重算 UDP 校验和 / IPv4 头部校验和」。
//!   [`apply_query`] 按该计划就地改址并重算校验和。
//! - [`match_response`]：把一份上游响应与 [`PendingQuery`] 登记的原始查询逐字段
//!   比对，五元组、报文 ID、问题名字（ASCII 大小写不敏感）、qtype/qclass 全部
//!   一致才允许回注那条会话。
//!
//! 校验和一律转发到 [`crate::checksum::checksum_of`] 的 RFC 1071 折叠实现，
//! 本模块不写第二份求和算法。
//!
//! fail-closed 清单（任何一条不满足都返回 [`Error`]，调用方必须丢弃报文）：
//! - 非 UDP 一律拒绝：本层只实现 UDP DNS 转发语义，不处理 TCP:53 与 53 端口的 TCP。
//! - 查询方向只看目的端口、响应方向只看源端口是否为 53：与 `lengsuo-environment`
//!   的 `FlowKey::dns()`（按归一化键的应答侧端口判定）保持同一套端口语义。
//! - 上游必须是已指定、同地址族、端口为 53 的端点：否则无法在同一 IP 头部里原地
//!   改址，也绝不允许「退回原目的」之类的静默回退——那会把查询发往未授权出口。
//! - 上游端口非 53 同样拒绝：转发后回程不再满足 DNS 会话语义，会让环境侧的
//!   DNS 绑定检查失效。
//! - 响应侧：五元组不属于登记过的会话、ID 漂移（哪怕一位）、问题名字或
//!   qtype/qclass 不符，一律判为不匹配并丢弃。这正是防 DNS 劫持的要点：被改写的
//!   响应绝不能回注到另一条会话或另一个环境。
//!
//! 范围限制：本层不验证入站报文的传输层校验和（`crate::checksum::verify` 单独
//! 提供），[`apply_query`] 只保证「改写后校验和与字节一致」，不证明改写前的报文
//! 来自可信对端；不理解资源记录内容，也不判断 RCODE 是否代表伪造答案；环境归属
//! 与出口设备授权由 `lengsuo-environment::classify` 负责，本模块不复制那套权威状态。

use std::net::{IpAddr, SocketAddr};

use crate::checksum;
use crate::dns::{self, DNS_PORT};
use crate::packet::{self, PacketInfo, Transport};
use crate::session::SessionKey;

/// 转发与回注匹配的全部失败种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// IP/UDP 头部解析失败，逐字保留 `packet::Error`。
    #[error("报文头部解析失败：{0}")]
    Packet(#[from] packet::Error),
    /// DNS 报文结构非法或被截断，逐字保留 `dns::Error`。
    #[error("DNS 报文非法：{0}")]
    Dns(#[from] dns::Error),
    /// 不是 UDP：本层不转发 TCP DNS。
    #[error("仅转发 UDP DNS，收到 {0:?}")]
    NotUdp(Transport),
    /// 查询方向的目的端口不是 53。
    #[error("目的端口 {0} 不是 DNS 端口")]
    NotQueryPort(u16),
    /// 响应方向的源端口不是 53。
    #[error("源端口 {0} 不是 DNS 端口")]
    NotResponsePort(u16),
    /// 上游与查询地址族不一致：无法原地改址，也不得改发往他处。
    #[error("上游 {upstream} 与查询 {query} 的地址族不一致")]
    AddressFamilyMismatch { query: IpAddr, upstream: IpAddr },
    /// 上游未配置：地址为未指定地址或端口为 0。
    #[error("上游 {0} 不是可用的 DNS 端点")]
    InvalidUpstream(SocketAddr),
    /// 上游端口不是 53。
    #[error("上游端口 {0} 不是 DNS 端口")]
    InvalidUpstreamPort(u16),
    /// 报文五元组与计划登记的会话不一致，或响应五元组不属于待决查询的会话。
    #[error("五元组与会话不匹配")]
    SessionMismatch,
    /// 响应报文 ID 与查询不符（ID 漂移防护）。
    #[error("响应 ID {response} 与查询 ID {expected} 不一致")]
    IdMismatch { expected: u16, response: u16 },
    /// 响应问题区与查询不符：名字、qtype 或 qclass。
    #[error("响应问题区与查询不一致")]
    QuestionMismatch,
}

/// 查询重写决策：改址目标、校验和重算需求与发起侧会话键。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardPlan {
    /// 转发目标上游端点。
    pub upstream: SocketAddr,
    /// 是否需重算 UDP 校验和：伪首部覆盖源与目的地址，改址后原值必然失效。
    pub needs_udp_checksum: bool,
    /// 是否需重算 IPv4 头部校验和：IPv6 没有头部校验和，恒为 `false`。
    pub needs_ip_checksum: bool,
    /// 发起侧五元组，供上层登记会话、复用环境侧分类器。
    pub session: SessionKey,
}

/// 一条已转发、等待响应的查询：回程匹配的唯一凭据。
///
/// 定长（[`dns::Question`] 内部是固定数组），放进 [`crate::session::SessionTable`]
/// 时没有额外堆分配，也不携带可打印的隐私字符串。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingQuery {
    /// 发起侧五元组（应用 -> 本机登记的解析器:53），与环境侧会话键同源。
    pub session: SessionKey,
    /// 查询报文 ID。
    pub id: u16,
    /// 查询的问题区。
    pub question: dns::Question,
    /// 实际转发到的上游端点。
    pub upstream: SocketAddr,
}

impl PendingQuery {
    /// 重写之后真正上路的那条流：`应用 -> 上游:53`，源端不动。
    ///
    /// 响应匹配以此键的反向为准——回包来自上游而不是原始目的地址，用改写前的
    /// 键匹配会让每一条合法响应都被判为不匹配。
    pub fn forwarded(&self) -> SessionKey {
        SessionKey::new(
            self.session.protocol(),
            self.session.source(),
            self.session.source_port(),
            self.upstream.ip(),
            self.upstream.port(),
        )
    }
}

/// 解析并规划一条 DNS 查询的转发，不修改入参报文。
pub fn plan_query(packet: &[u8], upstream: SocketAddr) -> Result<ForwardPlan, Error> {
    Ok(plan(packet, upstream)?.0)
}

/// 一次完成解析、校验与规划，返回计划与回程凭据。
///
/// 计划里两个 `needs_*` 的依据是「改写是否真的动了字段」：上游与当前目的完全一致
/// 时无需改动，校验和保持原值；地址或端口不同则 UDP 校验和必须重算，IPv4 还要
/// 重算头部校验和（目的地址在头部校验和覆盖范围内）。
pub fn forward_query(
    packet: &[u8],
    upstream: SocketAddr,
) -> Result<(ForwardPlan, PendingQuery), Error> {
    let (plan, message) = plan(packet, upstream)?;
    let pending = PendingQuery {
        session: plan.session,
        id: message.header.id,
        question: message.question,
        upstream: plan.upstream,
    };
    Ok((plan, pending))
}

/// 由既有计划与已解析查询生成回程凭据，供上层复用同一次解析结果。
pub fn pending(plan: &ForwardPlan, message: &dns::Message) -> PendingQuery {
    PendingQuery {
        session: plan.session,
        id: message.header.id,
        question: message.question.clone(),
        upstream: plan.upstream,
    }
}

fn plan(packet: &[u8], upstream: SocketAddr) -> Result<(ForwardPlan, dns::Message), Error> {
    let info = packet::inspect(packet)?;
    validate_upstream(info.destination, upstream)?;
    if info.protocol != Transport::Udp {
        return Err(Error::NotUdp(info.protocol));
    }
    let message = dns::parse_query(payload(packet, &info)?)?;
    if info.destination_port != DNS_PORT {
        return Err(Error::NotQueryPort(info.destination_port));
    }
    let changed = info.destination != upstream.ip() || info.destination_port != upstream.port();
    Ok((
        ForwardPlan {
            upstream,
            needs_udp_checksum: changed,
            needs_ip_checksum: changed && info.destination.is_ipv4(),
            session: SessionKey::from_info(info),
        },
        message,
    ))
}

/// 按 [`ForwardPlan`] 把报文目的地址与 UDP 目的端口改写为上游，并重算校验和。
///
/// 报文总长度不变（只改址，不增删字节），源地址与源端口一律不动——源端口是回程
/// 匹配的凭据。`needs_udp_checksum` 为真时写入正确校验和：IPv4 若得一补码 0 则
/// 写作 0xffff，避免与「发送端未计算」的 0 混淆（RFC 768）；IPv6 本就不允许 0。
pub fn apply_query(packet: &mut [u8], plan: &ForwardPlan) -> Result<(), Error> {
    let info = packet::inspect(packet)?;
    if SessionKey::from_info(info) != plan.session {
        return Err(Error::SessionMismatch);
    }
    if info.destination.is_ipv4() != plan.upstream.ip().is_ipv4() {
        return Err(Error::AddressFamilyMismatch {
            query: info.destination,
            upstream: plan.upstream.ip(),
        });
    }
    let transport = transport_start(packet, &info)?;
    write_destination(packet, plan.upstream.ip())?;
    let port_field = checked(transport, DESTINATION_PORT, packet.len())?;
    packet[port_field..port_field + 2].copy_from_slice(&plan.upstream.port().to_be_bytes());
    if plan.needs_ip_checksum {
        rewrite_ip_checksum(packet, transport)?;
    }
    if plan.needs_udp_checksum {
        rewrite_udp_checksum(packet, transport, info.source.is_ipv6())?;
    }
    Ok(())
}

/// 校验一份上游响应能否回注到 `expected` 那条会话，通过则返回响应头部。
///
/// 逐层收紧：五元组（地址与端口）必须精确等于待决查询的反向键；QR、opcode、TC
/// 等结构问题由 [`dns::parse_response`] 拒绝；ID、问题名字、qtype、qclass 全部
/// 一致才放行。任何一处不符都返回 [`Error`]，调用方丢弃并记录原因。
pub fn match_response(packet: &[u8], expected: &PendingQuery) -> Result<dns::Header, Error> {
    let info = packet::inspect(packet)?;
    if info.protocol != Transport::Udp {
        return Err(Error::NotUdp(info.protocol));
    }
    if info.source_port != DNS_PORT {
        return Err(Error::NotResponsePort(info.source_port));
    }
    if SessionKey::from_info(info) != expected.forwarded().reversed() {
        return Err(Error::SessionMismatch);
    }
    let response = dns::parse_response(payload(packet, &info)?)?;
    if response.header.id != expected.id {
        return Err(Error::IdMismatch {
            expected: expected.id,
            response: response.header.id,
        });
    }
    if !response.question.name.matches(&expected.question.name)
        || response.question.qtype != expected.question.qtype
        || response.question.qclass != expected.question.qclass
    {
        return Err(Error::QuestionMismatch);
    }
    Ok(response.header)
}

/// UDP 头部固定 8 字节，也就是 `PacketInfo::payload_offset` 与传输段起点的差。
const UDP_HEADER: usize = 8;
/// IPv4 固定头部长度（IHL=5 时的传输段起点由 payload_offset 反推，这里只用于 IPv6）。
const IPV6_HEADER: usize = 40;
/// IPv4 伪首部长度。
const IPV4_PSEUDO: usize = 12;
/// IPv6 伪首部长度。
const IPV6_PSEUDO: usize = 40;
/// UDP 目的端口在传输段内的偏移。
const DESTINATION_PORT: usize = 2;
/// UDP 校验和在传输段内的偏移。
const UDP_CHECKSUM: usize = 6;
/// IPv4 头部校验和偏移。
const IP_CHECKSUM: usize = 10;
/// IPv4 源地址 / 目的地址 / 协议字段偏移。
const IPV4_SOURCE: usize = 12;
const IPV4_DESTINATION: usize = 16;
const IPV4_PROTOCOL: usize = 9;
/// IPv6 源地址 / 目的地址 / 下一头字段偏移。
const IPV6_SOURCE: usize = 8;
const IPV6_DESTINATION: usize = 24;
const IPV6_NEXT_HEADER: usize = 6;

/// 传输段起点：IPv4 由已核对的 payload_offset 回退 UDP 头部，IPv6 固定 40 字节。
fn transport_start(packet: &[u8], info: &PacketInfo) -> Result<usize, Error> {
    match packet.first().ok_or(packet::Error::Incomplete)? >> 4 {
        4 => info
            .payload_offset
            .checked_sub(UDP_HEADER)
            .ok_or(Error::Packet(packet::Error::UdpLength)),
        6 => Ok(IPV6_HEADER),
        _ => Err(Error::Packet(packet::Error::UnsupportedVersion)),
    }
}

/// DNS 载荷：`packet::inspect` 已核对 UDP 长度字段与 IP 载荷精确一致。
fn payload<'a>(packet: &'a [u8], info: &PacketInfo) -> Result<&'a [u8], Error> {
    packet
        .get(info.payload_offset..)
        .ok_or(Error::Packet(packet::Error::Incomplete))
}

/// 上游必须是已指定、同地址族、端口为 53 的端点。
fn validate_upstream(query: IpAddr, upstream: SocketAddr) -> Result<(), Error> {
    if upstream.ip().is_unspecified() || upstream.port() == 0 {
        return Err(Error::InvalidUpstream(upstream));
    }
    if upstream.port() != DNS_PORT {
        return Err(Error::InvalidUpstreamPort(upstream.port()));
    }
    if query.is_ipv4() != upstream.ip().is_ipv4() {
        return Err(Error::AddressFamilyMismatch {
            query,
            upstream: upstream.ip(),
        });
    }
    Ok(())
}

/// 写入目的地址（按地址族取 4 或 16 字节）。偏移与 `packet::inspect` 读取的
/// 字段位置一致，因此地址族匹配即保证区间落在已核对的头部内。
fn write_destination(packet: &mut [u8], address: IpAddr) -> Result<(), Error> {
    let (at, bytes): (usize, &[u8]) = match address {
        IpAddr::V4(v4) => (IPV4_DESTINATION, &v4.octets()),
        IpAddr::V6(v6) => (IPV6_DESTINATION, &v6.octets()),
    };
    let start = checked(at, bytes.len(), packet.len())?;
    packet[start..start + bytes.len()].copy_from_slice(bytes);
    Ok(())
}

/// 把「起点 + 长度」换成可写区间，越界按不完整拒绝。
fn checked(start: usize, len: usize, total: usize) -> Result<usize, Error> {
    let end = start.checked_add(len).ok_or(packet::Error::Incomplete)?;
    if end > total {
        return Err(Error::Packet(packet::Error::Incomplete));
    }
    Ok(start)
}

/// 重算 IPv4 头部校验和：字段先置零，对整段头部求一补码和并写入其反码。
fn rewrite_ip_checksum(packet: &mut [u8], transport: usize) -> Result<(), Error> {
    let start = checked(IP_CHECKSUM, 2, transport)?;
    packet[start..start + 2].copy_from_slice(&0u16.to_be_bytes());
    let header = &packet[..transport];
    let value = checksum::checksum_of(&[header]);
    packet[start..start + 2].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

/// 重算 UDP 校验和：伪首部（源与目的地址、协议、传输段长度）加整个传输段。
fn rewrite_udp_checksum(packet: &mut [u8], transport: usize, ipv6: bool) -> Result<(), Error> {
    let field = checked(transport + UDP_CHECKSUM, 2, packet.len())?;
    packet[field..field + 2].copy_from_slice(&0u16.to_be_bytes());
    let segment_len = packet
        .len()
        .checked_sub(transport)
        .ok_or(packet::Error::Incomplete)?;
    let pseudo = pseudo_header(packet, segment_len, ipv6)?;
    let value = checksum::checksum_of(&[pseudo.as_bytes(), &packet[transport..]]);
    // IPv4 的 0 与「未提供校验和」同值，按 RFC 768 写作 0xffff；IPv6 的 0 本就非法。
    let value = match (value, ipv6) {
        (0, false) => 0xffff,
        (other, _) => other,
    };
    packet[field..field + 2].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

enum Pseudo {
    V4([u8; IPV4_PSEUDO]),
    V6([u8; IPV6_PSEUDO]),
}

impl Pseudo {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Pseudo::V4(bytes) => bytes,
            Pseudo::V6(bytes) => bytes,
        }
    }
}

/// 组装伪首部。长度字段 IPv4 为 16 位、IPv6 为 32 位，均为传输段字节数；协议号取自
/// IPv4 偏移 9 / IPv6 偏移 6，与 `packet::inspect` 已接受的值一致。
fn pseudo_header(packet: &[u8], segment_len: usize, ipv6: bool) -> Result<Pseudo, Error> {
    if ipv6 {
        let length =
            u32::try_from(segment_len).map_err(|_| Error::Packet(packet::Error::TotalLength))?;
        let mut bytes = [0u8; IPV6_PSEUDO];
        bytes[0..16].copy_from_slice(copied(packet, IPV6_SOURCE, 16)?);
        bytes[16..32].copy_from_slice(copied(packet, IPV6_DESTINATION, 16)?);
        bytes[32..36].copy_from_slice(&length.to_be_bytes());
        bytes[39] = *packet
            .get(IPV6_NEXT_HEADER)
            .ok_or(Error::Packet(packet::Error::Incomplete))?;
        Ok(Pseudo::V6(bytes))
    } else {
        let length =
            u16::try_from(segment_len).map_err(|_| Error::Packet(packet::Error::TotalLength))?;
        let mut bytes = [0u8; IPV4_PSEUDO];
        bytes[0..4].copy_from_slice(copied(packet, IPV4_SOURCE, 4)?);
        bytes[4..8].copy_from_slice(copied(packet, IPV4_DESTINATION, 4)?);
        bytes[9] = *packet
            .get(IPV4_PROTOCOL)
            .ok_or(Error::Packet(packet::Error::Incomplete))?;
        bytes[10..IPV4_PSEUDO].copy_from_slice(&length.to_be_bytes());
        Ok(Pseudo::V4(bytes))
    }
}

fn copied(packet: &[u8], at: usize, len: usize) -> Result<&[u8], Error> {
    let end = at.checked_add(len).ok_or(packet::Error::Incomplete)?;
    packet
        .get(at..end)
        .ok_or(Error::Packet(packet::Error::Incomplete))
}
