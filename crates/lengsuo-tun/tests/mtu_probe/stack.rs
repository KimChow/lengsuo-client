//! 超 MTU 分段用例：用 clamp 后的 MSS 切分载荷，再驱动既有用户态 TCP 栈重组。
//!
//! 这里只做**测试侧驱动**：三次握手与数据段的报文构造模仿
//! `tests/tcp_stack_e2e.rs`，被测栈本身仍是 `lengsuo_tun::tcp::listener::TcpListener`，
//! 没有重写或绕过任何栈逻辑。

use std::net::Ipv4Addr;

use lengsuo_tun::mtu::{MssClamp, IPV4_HEADER_BYTES, MIN_MTU, TCP_HEADER_BYTES};
use lengsuo_tun::packet;
use lengsuo_tun::tcp::listener::{Config as ListenerConfig, TcpListener};
use lengsuo_tun::tcp::segment::{self, Flags};
use lengsuo_tun::tcp::state::Config as ConnConfig;

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const SERVER_PORT: u16 = 8080;
const CLIENT_PORT: u16 = 40000;
const NOW: u64 = 1;

/// 客户端侧最小驱动：只做三次握手与按序数据段，服务端由被测 `TcpListener` 承担。
struct Client {
    listener: TcpListener,
    seq: u32,
    ack: u32,
}

impl Client {
    fn new(mtu: u16) -> Self {
        Self {
            listener: TcpListener::new(ListenerConfig {
                connection: ConnConfig {
                    receive_window: 4096,
                    reorder_slots: 4,
                    iss_seed: 0,
                },
                session_capacity: 8,
                session_ttl: 30,
                interface_mtu: mtu,
                iss_seed_start: 1000,
            }),
            seq: 7000,
            ack: 0,
        }
    }

    fn push(&mut self, flags: Flags, payload: &[u8]) -> Vec<u8> {
        let packet = ipv4_client_to_server(self.seq, self.ack, flags, payload);
        let feed = self.listener.feed(&packet, NOW).unwrap();
        self.seq = self
            .seq
            .wrapping_add(u32::from(flags.has_syn()) + payload.len() as u32);
        for reply in &feed.replies {
            packet::inspect(reply).unwrap();
            let seg = segment::parse(&reply[tcp_start(reply)..]).unwrap();
            self.ack = seg.seq.wrapping_add(seg.sequence_length());
            if seg.flags.has_syn() {
                self.ack = seg.seq.wrapping_add(1);
            }
        }
        feed.delivered
    }

    fn handshake(&mut self) {
        assert!(self.push(Flags::SYN, &[]).is_empty());
        assert!(self.push(Flags::ACK, &[]).is_empty());
        assert_eq!(self.listener.stats().established, 1);
    }
}

fn ipv4_client_to_server(seq: u32, ack: u32, flags: Flags, payload: &[u8]) -> Vec<u8> {
    let pseudo = pseudo_v4(
        CLIENT_IP,
        SERVER_IP,
        (segment::MIN_HEADER + payload.len()) as u16,
    );
    let tcp = segment::build(
        CLIENT_PORT,
        SERVER_PORT,
        seq,
        ack,
        flags,
        4096,
        &[],
        payload,
        &pseudo,
    )
    .unwrap();
    wrap_ipv4(CLIENT_IP, SERVER_IP, tcp)
}

fn pseudo_v4(src: Ipv4Addr, dst: Ipv4Addr, len: u16) -> [u8; 12] {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src.octets());
    pseudo[4..8].copy_from_slice(&dst.octets());
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&len.to_be_bytes());
    pseudo
}

/// 加 20 字节 IPv4 头（IHL=5），填好头部校验和供 `checksum::verify` 接受。
fn wrap_ipv4(src: Ipv4Addr, dst: Ipv4Addr, tcp: Vec<u8>) -> Vec<u8> {
    let total = 20 + tcp.len();
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let sum = !checksum_of(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet[20..].copy_from_slice(&tcp);
    packet
}

/// RFC 1071 一补码和（测试本地实现，与被测路径相互独立）。
fn checksum_of(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (words, odd) = bytes.as_chunks::<2>();
    for word in words {
        sum += u32::from(u16::from_be_bytes(*word));
    }
    if let Some(&byte) = odd.first() {
        sum += u32::from(byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// TCP 段起始偏移 = IPv4 IHL×4。
fn tcp_start(ipv4: &[u8]) -> usize {
    usize::from(ipv4[0] & 0x0f) * 4
}

#[test]
fn oversize_payload_is_split_by_clamped_mss_and_reassembles() {
    let mtu = MIN_MTU; // 576：IPv4 最小路径 MTU
    let mss = usize::from(MssClamp::new(mtu).unwrap().mss_for_v4().unwrap());
    assert_eq!(mss, 536);

    let payload: Vec<u8> = (0..1300u32).map(|i| (i % 251) as u8).collect();
    let segments: Vec<&[u8]> = payload.chunks(mss).collect();
    assert_eq!(segments.len(), 3, "1300 字节按 MSS 536 应分为 3 段");
    assert_eq!(
        segments.iter().map(|s| s.len()).collect::<Vec<_>>(),
        vec![536, 536, 228]
    );
    for segment in &segments {
        assert!(
            IPV4_HEADER_BYTES + TCP_HEADER_BYTES + segment.len() as u16 <= mtu,
            "每段封包不得超过 clamp 后的 MTU"
        );
    }

    let mut client = Client::new(mtu);
    client.handshake();
    let mut reassembled = Vec::new();
    for &segment in &segments {
        let delivered = client.push(Flags::ACK | Flags::PSH, segment);
        assert_eq!(delivered.as_slice(), segment, "每段应按序整段交付");
        reassembled.extend_from_slice(&delivered);
    }
    assert_eq!(reassembled, payload, "重组后必须与原载荷逐字节一致");
    assert_eq!(
        client.listener.stats().delivered_bytes,
        payload.len() as u64
    );
    assert_eq!(
        client.listener.stats().oversize,
        0,
        "clamp 后不应触发 oversize"
    );
}
