//! 主动打开端到端用例的共享构件：报文构造器与内存对端。
//!
//! 这些是**测试侧的字节桥**：一侧是本卡的用户态 TCP 主动方，另一侧是用既有
//! `tcp::segment` / `tcp::state` 构件拼出来的内存对端。全部在内存里完成，
//! 不接真实网卡、不建真实 socket。
//!
//! 被两个测试二进制共享：各二进制只用到其中一部分项，未用到的按测试夹具惯例豁免
//! dead-code 警告（行为不变，只是不因「另一个二进制不用」而报警）。

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use lengsuo_tun::route::RouteDestination;
use lengsuo_tun::tcp::active::{ActiveConfig, ActiveConnection};
use lengsuo_tun::tcp::connector::{Connector, RouteTable};
use lengsuo_tun::tcp::segment::{self, Flags};
use lengsuo_tun::tcp::state::{Config as ConnConfig, Connection, Outcome, SendSegment, State};

/// 本端地址。
pub const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// 远端地址。
pub const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// 本端端口。
pub const LOCAL_PORT: u16 = 40000;
/// 远端端口。
pub const REMOTE_PORT: u16 = 80;
/// 用例使用的单调时钟刻度。
pub const NOW: u64 = 1_000;
/// 主动方允许的最大 SYN 重传次数。
pub const MAX_RETRIES: u32 = 3;

/// 主动方的测试配置：固定 ISN 种子、固定 RTO，行为可复现。
pub fn active_config() -> ActiveConfig {
    ActiveConfig {
        local: LOCAL_IP.into(),
        local_port: LOCAL_PORT,
        remote: REMOTE_IP.into(),
        remote_port: REMOTE_PORT,
        iss_seed: 0x1000_0000,
        receive_window: 4096,
        mss: 0,
        interface_mtu: 1500,
        interface_index: 3,
        ttl: 64,
        rto_ms: 100,
        max_rto_ms: 1000,
        max_retries: MAX_RETRIES,
    }
}

/// 建一条带路由的主动连接（路由表把 REMOTE_IP 指向 LOCAL_IP 这个源地址）。
pub fn open_connection() -> (Connector, ActiveConnection) {
    let mut routes = RouteTable::new();
    routes
        .insert_host(REMOTE_IP.into(), 3, LOCAL_IP.into())
        .unwrap();
    routes
        .insert(
            RouteDestination::prefix("10.0.0.0".parse().unwrap(), 24).unwrap(),
            7,
            LOCAL_IP.into(),
        )
        .unwrap();
    let connector = Connector::new(routes);
    let connection = connector.open(active_config()).unwrap();
    (connector, connection)
}

/// IPv4 TCP 伪首部（12 字节）。
pub fn pseudo_v4(src: Ipv4Addr, dst: Ipv4Addr, len: u16) -> [u8; 12] {
    let mut p = [0u8; 12];
    p[0..4].copy_from_slice(&src.octets());
    p[4..8].copy_from_slice(&dst.octets());
    p[9] = 6;
    p[10..12].copy_from_slice(&len.to_be_bytes());
    p
}

/// RFC 1071 一补码和（测试本地实现，与栈内构造路径相互独立）。
pub fn checksum_of(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (words, odd) = bytes.as_chunks::<2>();
    for w in words {
        sum += u32::from(u16::from_be_bytes(*w));
    }
    if let Some(&byte) = odd.first() {
        sum += u32::from(byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// 加 20 字节 IPv4 头（IHL=5）：`packet::inspect` 要求头部校验和正确、长度自洽。
pub fn wrap_ipv4(src: Ipv4Addr, dst: Ipv4Addr, tcp: Vec<u8>) -> Vec<u8> {
    let total = 20 + tcp.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 6;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let sum = !checksum_of(&p[..20]);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    p[20..].copy_from_slice(&tcp);
    p
}

/// 加 40 字节 IPv6 固定头部：只用于构造「地址族不一致」的负例报文。
pub fn wrap_ipv6(src: Ipv6Addr, dst: Ipv6Addr, tcp: Vec<u8>) -> Vec<u8> {
    let mut p = vec![0u8; 40 + tcp.len()];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
    p[6] = 6;
    p[7] = 64;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p[40..].copy_from_slice(&tcp);
    p
}

/// 按地址族包装 IP 头：IPv4 与 IPv6 都能构造，便于负例覆盖地址族不一致。
pub fn wrap_ip(src: IpAddr, dst: IpAddr, tcp: Vec<u8>) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => wrap_ipv4(src, dst, tcp),
        (IpAddr::V6(src), IpAddr::V6(dst)) => wrap_ipv6(src, dst, tcp),
        // 族不一致：按 IPv4 处理（负例只要求解析层拒绝，不要求报文自洽）。
        _ => wrap_ipv4(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, tcp),
    }
}

/// 合成一个完整的 IP+TCP 报文（按地址族选 IPv4 / IPv6 头）。
///
/// 参数超过七个时按职责分组：地址与端口一组、序号与标志一组、其余一组。
#[allow(clippy::too_many_arguments)]
pub fn build_packet(
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: Flags,
    window: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let len = (segment::MIN_HEADER + options.len() + payload.len()) as u16;
    let tcp = match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let pseudo = pseudo_v4(src, dst, len);
            segment::build(
                src_port, dst_port, seq, ack, flags, window, options, payload, &pseudo,
            )
            .unwrap()
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut pseudo = [0u8; 40];
            pseudo[0..16].copy_from_slice(&src.octets());
            pseudo[16..32].copy_from_slice(&dst.octets());
            pseudo[32..36].copy_from_slice(&u32::from(len).to_be_bytes());
            pseudo[39] = 6;
            segment::build(
                src_port, dst_port, seq, ack, flags, window, options, payload, &pseudo,
            )
            .unwrap()
        }
        // 族不一致：伪首部按 IPv4 口径给（负例只要求被解析层拒绝，不要求报文自洽）。
        _ => {
            let pseudo = pseudo_v4(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, len);
            segment::build(
                src_port, dst_port, seq, ack, flags, window, options, payload, &pseudo,
            )
            .unwrap()
        }
    };
    wrap_ip(src, dst, tcp)
}

/// TCP 段起始偏移 = IPv4 IHL×4。
pub fn tcp_start(ipv4: &[u8]) -> usize {
    usize::from(ipv4[0] & 0x0f) * 4
}

/// 从完整 IP 报文里解析出的段字段（顺带取回选项区）。
pub struct Parsed {
    pub flags: Flags,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub payload: Vec<u8>,
    pub options: Vec<u8>,
}

/// 解析一个完整 IP 报文里的 TCP 段。
pub fn parse_out(packet: &[u8]) -> Parsed {
    let bytes = &packet[tcp_start(packet)..];
    let seg = segment::parse(bytes).unwrap();
    let header_len = bytes.len() - seg.payload.len();
    Parsed {
        flags: seg.flags,
        seq: seg.seq,
        ack: seg.ack,
        window: seg.window,
        payload: seg.payload.to_vec(),
        options: bytes[segment::MIN_HEADER..header_len].to_vec(),
    }
}

/// 被动对端：复用既有 `tcp::state` 的 `Listen` 路径（`state.rs` 是已验收子树）。
pub struct PassivePeer {
    connection: Connection,
    /// 对端状态机已发出的最后一个序号（含 SYN/FIN 占位）。
    snd_nxt: u32,
    /// 对端状态机期望收到的下一个序号。
    rcv_nxt: u32,
}

impl PassivePeer {
    /// 建立处于 `Listen` 的被动对端。
    pub fn new() -> Self {
        let mut connection = Connection::new(ConnConfig {
            receive_window: 4096,
            reorder_slots: 4,
            iss_seed: 0x2000_0000,
        });
        connection.listen();
        Self {
            connection,
            snd_nxt: 0,
            rcv_nxt: 0,
        }
    }

    /// 对端状态机当前状态（供用例断言）。
    pub fn state(&self) -> State {
        self.connection.state()
    }

    /// 吃一个报文，返回要回送的报文（零到多条）与按序交付的载荷。
    ///
    /// 既有被动栈对**按序**数据段的语义是「交付载荷、不单独回 ACK」（确认由后续段捎带），
    /// 因此这里同时暴露 `delivered`，用例才能断言载荷逐字节一致。
    pub fn feed(&mut self, packet: &[u8]) -> (Vec<Vec<u8>>, Vec<u8>) {
        let seg = segment::parse(&packet[tcp_start(packet)..]).unwrap();
        match self.connection.advance(&seg, NOW) {
            Outcome::SendSegment(s) => {
                // 记录对端状态机的序号推进（既有栈的记账口径）：
                // SYN/FIN 各占一个序号，载荷按字节数消耗。
                self.snd_nxt = s.seq.wrapping_add(s.payload.len() as u32);
                self.rcv_nxt = s.ack;
                (vec![self.reply(&s)], Vec::new())
            }
            Outcome::Deliver(bytes) => {
                self.snd_nxt = self.snd_nxt.wrapping_add(bytes.len() as u32);
                (Vec::new(), bytes)
            }
            _ => (Vec::new(), Vec::new()),
        }
    }

    /// 把对端状态机的待发段编成完整 IP 报文。
    fn reply(&self, s: &SendSegment) -> Vec<u8> {
        build_packet(
            REMOTE_IP.into(),
            LOCAL_IP.into(),
            REMOTE_PORT,
            LOCAL_PORT,
            s.seq,
            s.ack,
            s.flags,
            s.window,
            &[],
            &s.payload,
        )
    }

    /// 对端主动发一段数据（seq 取对端状态机的已发序号）。
    pub fn send_data(&mut self, payload: &[u8]) -> Vec<u8> {
        let s = SendSegment {
            seq: self.snd_nxt,
            ack: self.rcv_nxt,
            flags: Flags::ACK | Flags::PSH,
            window: self.connection.advertised_window(),
            payload: payload.to_vec(),
        };
        self.snd_nxt = self.snd_nxt.wrapping_add(payload.len() as u32);
        self.reply(&s)
    }
}

/// 主动对端：用既有 `tcp::segment` 构件拼出的最小 SYN 发起方（本卡当被动端）。
pub struct ActivePeer {
    seq: u32,
    ack: u32,
}

impl ActivePeer {
    /// 以给定 ISN 建立主动对端。
    pub fn new(isn: u32) -> Self {
        Self { seq: isn, ack: 0 }
    }

    /// 对端当前的下一个发送序号（发 SYN 后为 ISN+1）。
    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// 发出裸 SYN（不带 ACK）。
    pub fn syn(&mut self) -> Vec<u8> {
        let packet = build_packet(
            REMOTE_IP.into(),
            LOCAL_IP.into(),
            REMOTE_PORT,
            LOCAL_PORT,
            self.seq,
            0,
            Flags::SYN,
            4096,
            &[],
            &[],
        );
        self.seq = self.seq.wrapping_add(1);
        packet
    }

    /// 收到本卡的 SYN-ACK 后回最终 ACK。
    pub fn ack(&mut self, syn_ack: &Parsed) -> Vec<u8> {
        assert_eq!(syn_ack.ack, self.seq, "SYN-ACK 必须确认我们的 SYN");
        self.ack = syn_ack.seq.wrapping_add(1);
        build_packet(
            REMOTE_IP.into(),
            LOCAL_IP.into(),
            REMOTE_PORT,
            LOCAL_PORT,
            self.seq,
            self.ack,
            Flags::ACK,
            4096,
            &[],
            &[],
        )
    }
}
