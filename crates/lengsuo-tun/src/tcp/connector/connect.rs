//! 主动方向的报文构造与入向分发。
//!
//! 本模块是 [`ActiveConnection`] 状态机与「链路」之间的胶水层，职责两件：
//! ① 报文构造：把待发段编成完整 IP 报文（IPv4/IPv6），交给上层写设备；
//! ② 入向分发：校验入向 IP 报文，定位 TCP 段、解析对端 MSS，喂给状态机。
//!
//! **不打开设备、不写 socket、不读系统路由表**：路由查表在 [`super::route`]。
//! 出站报文的长度受接口 MTU 约束：超 MTU 一律 fail-closed 报错，不发超大报文。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::checksum;
use crate::mtu::{self, Direction, IpVersion};
use crate::session::Clock;
use crate::tcp::active::{
    ActiveConfig, ActiveConnection, ActiveError, ActiveOutcome, OutboundSegment,
};
use crate::tcp::segment;

use super::route::RouteTable;

/// IPv4 头部固定长度（本栈不发 IP 选项）。
const IPV4_HEADER: usize = 20;
/// IPv6 固定头部长度。
const IPV6_HEADER: usize = 40;
/// IPv4 IHL 字段的低位掩码，单位为 4 字节。
const IHL_MASK: u8 = 0x0f;
/// IHL 字段的单位字节数。
const IHL_UNIT: usize = 4;
/// TCP 协议号。
const PROTOCOL_TCP: u8 = 6;
/// 出站 IPv4 头部：恒用 IHL=5。
const IPV4_IHL: u8 = 0x45;
/// 出站 IPv4 的标志位：DF（不分片）。
const IPV4_FLAG_DF: u16 = 0x4000;

/// 一次入向处理的结果：待发报文、交付载荷与失败原因。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectorResult {
    /// 要写回链路的完整 IP 报文（可能零条）。
    pub packets: Vec<Vec<u8>>,
    /// 按序到达、应交给上层读端的应用载荷（可能为空）。
    pub delivered: Vec<u8>,
    /// 连接失败原因；`None` 表示连接仍然健康。
    pub failure: Option<ActiveError>,
}

/// 主动方向的接入层：路由查表 + 报文构造 + 入向分发。
#[derive(Debug, Clone, Default)]
pub struct Connector {
    routes: RouteTable,
}

impl Connector {
    /// 用给定路由表建立接入层。
    pub fn new(routes: RouteTable) -> Self {
        Self { routes }
    }

    /// 只读路由表。
    pub fn routes(&self) -> &RouteTable {
        &self.routes
    }

    /// 发起一次主动打开：先查路由，命中后用路由给出的源地址与出接口补齐配置。
    ///
    /// 查不到出接口时 fail-closed 报错（[`ActiveError::NoRoute`]），不构造半成品连接。
    pub fn open(&self, mut config: ActiveConfig) -> Result<ActiveConnection, ActiveError> {
        let entry = self
            .routes
            .lookup(config.remote)
            .ok_or(ActiveError::NoRoute(config.remote))?;
        config.local = entry.source;
        config.interface_index = entry.interface_index;
        ActiveConnection::new(config)
    }

    /// 处理一个入向 IP 报文，产出待发报文与交付载荷。
    ///
    /// 处理链：校验（`checksum::verify` → `packet::inspect`）→ 方向与地址核对 →
    /// 定位 TCP 段 → `segment::parse` → 解析对端 MSS → 喂给状态机 → 构造回包。
    /// 任一步失败都 fail-closed：不产出回包，不改连接状态。
    pub fn on_packet(
        &self,
        connection: &mut ActiveConnection,
        ip_packet: &[u8],
        now: Clock,
    ) -> Result<ConnectorResult, ActiveError> {
        let info = checksum::verify(ip_packet)?;
        if info.protocol != crate::packet::Transport::Tcp {
            return Err(ActiveError::NotTcp);
        }
        // 地址与端口必须与连接的四元组一致：串话一律拒绝。
        if info.source != connection.remote()
            || info.destination != connection.local()
            || info.source_port != connection.remote_port()
            || info.destination_port != connection.local_port()
        {
            return Err(ActiveError::NotTcp);
        }
        let Some(segment_bytes) = tcp_segment_bytes(ip_packet, info.payload_offset) else {
            return Err(ActiveError::Length(ip_packet.len()));
        };
        let Ok(seg) = segment::parse(segment_bytes) else {
            // 截断的 TCP 段（头部截断 / 选项区截断）在此 fail-closed，不 panic。
            return Err(ActiveError::Length(segment_bytes.len()));
        };
        // 对端通告的 MSS：解析失败或缺省都不改变本端行为（保持夹紧后的值）。
        if let Some(peer_mss) =
            crate::tcp::active::parse_mss_option(tcp_options(segment_bytes, &seg))
        {
            connection.set_peer_mss(peer_mss);
        }
        let outcome = connection.on_segment(&seg, now);
        let mut result = ConnectorResult::default();
        match outcome {
            ActiveOutcome::Send(out) => {
                result.packets = self.build_packets(connection, &[out])?;
            }
            ActiveOutcome::Deliver(bytes) => {
                result.delivered = bytes;
            }
            ActiveOutcome::Failed { reason, reset } => {
                if let Some(reset) = reset {
                    result.packets = self.build_packets(connection, &[reset])?;
                }
                result.failure = Some(reason);
            }
            ActiveOutcome::Discarded(_) | ActiveOutcome::None => {}
        }
        Ok(result)
    }

    /// 把状态机产出的段编成完整 IP 报文（零到多条）。
    ///
    /// 出站报文长度受出接口 MTU 约束：超 MTU 返回 [`ActiveError::Length`]，
    /// 不产出超大报文（fail-closed，不分片）。
    pub fn build_packets(
        &self,
        connection: &ActiveConnection,
        segments: &[OutboundSegment],
    ) -> Result<Vec<Vec<u8>>, ActiveError> {
        let mut packets = Vec::with_capacity(segments.len());
        for segment in segments {
            let packet = build_packet(
                connection.local(),
                connection.remote(),
                connection.local_port(),
                connection.remote_port(),
                connection.ttl(),
                segment,
            )?;
            let family = if connection.local().is_ipv4() {
                IpVersion::V4
            } else {
                IpVersion::V6
            };
            match mtu::decide(
                family,
                connection.interface_mtu(),
                packet.len(),
                Direction::Egress,
            ) {
                Ok(decision) if decision.is_send() => {}
                _ => return Err(ActiveError::Length(packet.len())),
            }
            packets.push(packet);
        }
        Ok(packets)
    }
}

/// 从 IP 报文里取出 TCP 段字节（含 TCP 头部）。
///
/// `payload_offset` 是应用载荷偏移（已越过 TCP 头部）；段首按报文自身的版本与
/// IHL 字段算出，再校验段首不晚于载荷偏移。
fn tcp_segment_bytes(ip_packet: &[u8], payload_offset: usize) -> Option<&[u8]> {
    let first = *ip_packet.first()?;
    let start = match first >> 4 {
        4 => usize::from(first & IHL_MASK) * IHL_UNIT,
        6 => IPV6_HEADER,
        _ => return None,
    };
    if start == 0 || start > payload_offset || payload_offset > ip_packet.len() {
        return None;
    }
    ip_packet.get(start..)
}

/// 从段字节里取出选项区（固定头部之后、载荷之前）。
///
/// 用「段总长 − 载荷长」反推头部长度，不重写 `segment` 模块的头部解析。
fn tcp_options<'a>(segment_bytes: &'a [u8], seg: &segment::Segment<'_>) -> &'a [u8] {
    let header_len = segment_bytes.len().saturating_sub(seg.payload.len());
    segment_bytes
        .get(segment::MIN_HEADER..header_len)
        .unwrap_or(&[])
}

/// 构造完整 IP 报文（IPv4 或 IPv6）+ TCP 段。
fn build_packet(
    local: IpAddr,
    remote: IpAddr,
    local_port: u16,
    remote_port: u16,
    ttl: u8,
    out: &OutboundSegment,
) -> Result<Vec<u8>, ActiveError> {
    match (local, remote) {
        (IpAddr::V4(local), IpAddr::V4(remote)) => {
            build_ipv4(local, remote, local_port, remote_port, ttl, out)
        }
        (IpAddr::V6(local), IpAddr::V6(remote)) => {
            build_ipv6(local, remote, local_port, remote_port, ttl, out)
        }
        // 地址族不一致：fail-closed，不构造报文。
        _ => Err(ActiveError::FamilyMismatch),
    }
}

/// 组装 IPv4 报文：20 字节固定头部 + TCP 段。
fn build_ipv4(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    ttl: u8,
    out: &OutboundSegment,
) -> Result<Vec<u8>, ActiveError> {
    let seg_len = segment::MIN_HEADER
        .checked_add(out.options.len())
        .and_then(|n| n.checked_add(out.payload.len()))
        .and_then(|n| u16::try_from(n).ok())
        .ok_or(ActiveError::Length(out.payload.len()))?;
    let pseudo = pseudo_v4(source, destination, seg_len);
    let tcp = segment::build(
        source_port,
        destination_port,
        out.seq,
        out.ack,
        out.flags,
        out.window,
        &out.options,
        &out.payload,
        &pseudo,
    )
    .map_err(|_| ActiveError::Length(out.payload.len()))?;
    let total = IPV4_HEADER
        .checked_add(tcp.len())
        .ok_or(ActiveError::Length(tcp.len()))?;
    let total_u16 = u16::try_from(total).map_err(|_| ActiveError::Length(total))?;
    let mut packet = vec![0u8; total];
    packet[0] = IPV4_IHL;
    packet[1] = 0;
    packet[2..4].copy_from_slice(&total_u16.to_be_bytes());
    packet[4..6].copy_from_slice(&0u16.to_be_bytes());
    packet[6..8].copy_from_slice(&IPV4_FLAG_DF.to_be_bytes());
    packet[8] = ttl;
    packet[9] = PROTOCOL_TCP;
    packet[10..12].copy_from_slice(&0u16.to_be_bytes());
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let header_sum = !checksum::ones_complement_sum(&[&packet[..IPV4_HEADER]]);
    packet[10..12].copy_from_slice(&header_sum.to_be_bytes());
    packet[IPV4_HEADER..].copy_from_slice(&tcp);
    Ok(packet)
}

/// 组装 IPv6 报文：40 字节固定头部 + TCP 段。
fn build_ipv6(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    ttl: u8,
    out: &OutboundSegment,
) -> Result<Vec<u8>, ActiveError> {
    let seg_len = segment::MIN_HEADER
        .checked_add(out.options.len())
        .and_then(|n| n.checked_add(out.payload.len()))
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(ActiveError::Length(out.payload.len()))?;
    let pseudo = pseudo_v6(source, destination, seg_len);
    let tcp = segment::build(
        source_port,
        destination_port,
        out.seq,
        out.ack,
        out.flags,
        out.window,
        &out.options,
        &out.payload,
        &pseudo,
    )
    .map_err(|_| ActiveError::Length(out.payload.len()))?;
    let payload_len = u16::try_from(tcp.len()).map_err(|_| ActiveError::Length(tcp.len()))?;
    let mut packet = vec![0u8; IPV6_HEADER + tcp.len()];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    packet[6] = PROTOCOL_TCP;
    packet[7] = ttl;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[IPV6_HEADER..].copy_from_slice(&tcp);
    Ok(packet)
}

/// IPv4 TCP 伪首部（12 字节）。
fn pseudo_v4(source: Ipv4Addr, destination: Ipv4Addr, len: u16) -> [u8; 12] {
    let mut p = [0u8; 12];
    p[0..4].copy_from_slice(&source.octets());
    p[4..8].copy_from_slice(&destination.octets());
    p[9] = PROTOCOL_TCP;
    p[10..12].copy_from_slice(&len.to_be_bytes());
    p
}

/// IPv6 TCP 伪首部（40 字节）：源/目的地址、32 位段长、三个零字节、下一头。
fn pseudo_v6(source: Ipv6Addr, destination: Ipv6Addr, len: u32) -> [u8; 40] {
    let mut p = [0u8; 40];
    p[0..16].copy_from_slice(&source.octets());
    p[16..32].copy_from_slice(&destination.octets());
    p[32..36].copy_from_slice(&len.to_be_bytes());
    p[39] = PROTOCOL_TCP;
    p
}
