//! `TcpListener::send` 的生产分段用例：载荷按 clamp 后的有效 MSS 切成多段，
//! 每段独立构造成 IP+TCP 报文返回（不再是测试侧手工切分）。
//!
//! 夹具做法：用一份手工构造的 SYN 驱动既有被动打开路径建立会话，再用同一五元组
//! 构造 [`SessionKey`] 调 `send`；返回的 IP 报文按版本定位 TCP 段首（IPv4 `IHL×4`、
//! IPv6 固定 40）解析序号、标志与载荷。全程纯内存，不建设备、不发真实报文。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use lengsuo_tun::checksum;
use lengsuo_tun::mtu::MssClamp;
use lengsuo_tun::packet::Transport;
use lengsuo_tun::session::SessionKey;
use lengsuo_tun::tcp::listener::{Config as ListenerConfig, TcpListener};
use lengsuo_tun::tcp::segment::{self, Flags};

const CLIENT_PORT: u16 = 40000;
const SERVER_PORT: u16 = 8080;
const CLIENT_SEQ: u32 = 7000;
const NOW: u64 = 1;

const CLIENT_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
const SERVER_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const CLIENT_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
const SERVER_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));

/// 已建立的会话夹具。`base` 是握手完成后发送端的起始序号（即当时的 `snd_nxt`）。
struct Fixture {
    listener: TcpListener,
    key: SessionKey,
    base: u32,
}

impl Fixture {
    /// 用 `(client, server)` 地址族完成三次握手；握手报文被 MTU 判定拒绝时返回 `None`。
    fn establish(interface_mtu: u16, client: IpAddr, server: IpAddr) -> Option<Self> {
        let mut listener = TcpListener::new(ListenerConfig {
            interface_mtu,
            ..Default::default()
        });
        let syn = client_packet(client, server, CLIENT_SEQ, 0, Flags::SYN, &[]);
        let feed = listener.feed(&syn, NOW).ok()?;
        let synack = feed.replies.first()?;
        let base = segment::parse(&synack[tcp_start(synack)..])
            .ok()?
            .seq
            .wrapping_add(1);
        let ack = client_packet(
            client,
            server,
            CLIENT_SEQ.wrapping_add(1),
            base,
            Flags::ACK,
            &[],
        );
        listener.feed(&ack, NOW).ok()?;
        assert_eq!(
            listener.stats().established,
            1,
            "MTU {interface_mtu} 下三次握手应完成"
        );
        let key = SessionKey::new(Transport::Tcp, client, CLIENT_PORT, server, SERVER_PORT);
        Some(Self {
            listener,
            key,
            base,
        })
    }
}

fn v4(mtu: u16) -> Option<Fixture> {
    Fixture::establish(mtu, CLIENT_V4, SERVER_V4)
}

fn v6(mtu: u16) -> Option<Fixture> {
    Fixture::establish(mtu, CLIENT_V6, SERVER_V6)
}

/// 一次 `send` 产出的单个 IP 报文解析结果。
struct Sent {
    seq: u32,
    flags: Flags,
    payload: Vec<u8>,
    /// IP 报文总长（含 IP 与 TCP 头部）。
    ip_len: usize,
}

fn parse_replies(packets: &[Vec<u8>]) -> Vec<Sent> {
    packets
        .iter()
        .map(|packet| {
            // 先交叉验证校验和，确保返回的确是能上链路的完整报文。
            checksum::verify(packet).expect("send 返回的报文应通过校验和验证");
            let seg = segment::parse(&packet[tcp_start(packet)..]).expect("TCP 段应可解析");
            Sent {
                seq: seg.seq,
                flags: seg.flags,
                payload: seg.payload.to_vec(),
                ip_len: packet.len(),
            }
        })
        .collect()
}

fn lengths(sent: &[Sent]) -> Vec<usize> {
    sent.iter().map(|s| s.payload.len()).collect()
}

/// 字节模式 `i % 251`，便于重组后逐字节比对。
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn mss_v4(mtu: u16) -> usize {
    usize::from(MssClamp::new(mtu).unwrap().mss_for_v4().unwrap())
}

/// 合成 客户端 → 服务端 的完整 IP+TCP 报文。
fn client_packet(
    src: IpAddr,
    dst: IpAddr,
    seq: u32,
    ack: u32,
    flags: Flags,
    payload: &[u8],
) -> Vec<u8> {
    let seg_len = (segment::MIN_HEADER + payload.len()) as u16;
    let tcp = match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let pseudo = pseudo_v4(src, dst, seg_len);
            segment::build(
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
            .unwrap()
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut pseudo = [0u8; 40];
            pseudo[0..16].copy_from_slice(&src.octets());
            pseudo[16..32].copy_from_slice(&dst.octets());
            pseudo[32..36].copy_from_slice(&u32::from(seg_len).to_be_bytes());
            pseudo[39] = 6;
            segment::build(
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
            .unwrap()
        }
        _ => unreachable!("夹具只构造同族地址"),
    };
    wrap_ip(src, dst, tcp)
}

fn pseudo_v4(src: Ipv4Addr, dst: Ipv4Addr, len: u16) -> [u8; 12] {
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src.octets());
    pseudo[4..8].copy_from_slice(&dst.octets());
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&len.to_be_bytes());
    pseudo
}

/// 加 IP 头：IPv4 为 20 字节（IHL=5）、IPv6 为 40 字节固定头；均填好可验证的头部。
fn wrap_ip(src: IpAddr, dst: IpAddr, tcp: Vec<u8>) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
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
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut packet = vec![0u8; 40 + tcp.len()];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
            packet[6] = 6;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&src.octets());
            packet[24..40].copy_from_slice(&dst.octets());
            packet[40..].copy_from_slice(&tcp);
            packet
        }
        _ => unreachable!("夹具只构造同族地址"),
    }
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

/// TCP 段起始偏移：IPv4 为 IHL×4，IPv6 固定 40（本栈回包头部固定无选项）。
fn tcp_start(ip: &[u8]) -> usize {
    match ip[0] >> 4 {
        4 => usize::from(ip[0] & 0x0f) * 4,
        _ => 40,
    }
}

#[test]
fn payload_below_mss_emits_single_segment() {
    let mss = mss_v4(1500);
    let mut fixture = v4(1500).expect("握手应成功");
    let payload = pattern(mss - 1);
    let sent = parse_replies(&fixture.listener.send(fixture.key, &payload, NOW));
    assert_eq!(
        lengths(&sent),
        vec![mss - 1],
        "len={} 应 1 段，实际 {:?}",
        payload.len(),
        lengths(&sent)
    );
}

#[test]
fn payload_exactly_mss_emits_single_segment() {
    let mss = mss_v4(1500);
    let mut fixture = v4(1500).expect("握手应成功");
    let payload = pattern(mss);
    let sent = parse_replies(&fixture.listener.send(fixture.key, &payload, NOW));
    assert_eq!(
        lengths(&sent),
        vec![mss],
        "len={mss} 恰好一段，实际 {:?}",
        lengths(&sent)
    );
}

#[test]
fn payload_mss_plus_one_emits_two_segments() {
    let mss = mss_v4(1500);
    let mut fixture = v4(1500).expect("握手应成功");
    let payload = pattern(mss + 1);
    let sent = parse_replies(&fixture.listener.send(fixture.key, &payload, NOW));
    assert_eq!(
        lengths(&sent),
        vec![mss, 1],
        "len={} 应 {mss}+1 两段，实际 {:?}",
        payload.len(),
        lengths(&sent)
    );
}

#[test]
fn payload_three_mss_plus_five_emits_four_segments() {
    let mss = mss_v4(1500);
    let mut fixture = v4(1500).expect("握手应成功");
    let payload = pattern(3 * mss + 5);
    let sent = parse_replies(&fixture.listener.send(fixture.key, &payload, NOW));
    assert_eq!(
        lengths(&sent),
        vec![mss, mss, mss, 5],
        "len={} 应四段，实际 {:?}",
        payload.len(),
        lengths(&sent)
    );
}

#[test]
fn every_segment_fits_interface_mtu() {
    let mtu = 1500u16;
    let mss = mss_v4(mtu);
    let mut fixture = v4(mtu).expect("握手应成功");
    let payload = pattern(3 * mss + 5);
    let sent = parse_replies(&fixture.listener.send(fixture.key, &payload, NOW));
    for (index, segment) in sent.iter().enumerate() {
        assert!(
            segment.ip_len <= usize::from(mtu),
            "第 {index} 段 IP 总长 {} 超过接口 MTU {mtu}",
            segment.ip_len
        );
    }
}

#[test]
fn sequence_numbers_are_contiguous() {
    let mss = mss_v4(1500);
    let mut fixture = v4(1500).expect("握手应成功");
    let payload = pattern(3 * mss + 5);
    let sent = parse_replies(&fixture.listener.send(fixture.key, &payload, NOW));
    assert!(!sent.is_empty(), "非空载荷应产出段");
    assert_eq!(
        sent[0].seq, fixture.base,
        "首段序号应为握手后的 snd_nxt {}，实际 {}",
        fixture.base, sent[0].seq
    );
    let mut expected = fixture.base;
    for (index, segment) in sent.iter().enumerate() {
        assert_eq!(
            segment.seq, expected,
            "第 {index} 段序号应为 {expected}，实际 {}",
            segment.seq
        );
        expected = expected.wrapping_add(segment.payload.len() as u32);
    }
}

#[test]
fn only_last_segment_carries_psh() {
    let mss = mss_v4(1500);
    let mut fixture = v4(1500).expect("握手应成功");
    let payload = pattern(2 * mss + 1);
    let sent = parse_replies(&fixture.listener.send(fixture.key, &payload, NOW));
    assert_eq!(sent.len(), 3, "应产出 3 段，实际 {}", sent.len());
    for (index, segment) in sent.iter().enumerate() {
        assert!(
            segment.flags.has_ack(),
            "第 {index} 段应带 ACK，实际 flags=0x{:02x}",
            segment.flags.bits()
        );
        if index + 1 == sent.len() {
            assert!(
                segment.flags.has_psh(),
                "末段应带 PSH，实际 flags=0x{:02x}",
                segment.flags.bits()
            );
        } else {
            assert!(
                !segment.flags.has_psh(),
                "非末段（第 {index} 段）不应带 PSH，实际 flags=0x{:02x}",
                segment.flags.bits()
            );
        }
    }
}

#[test]
fn ipv6_uses_1220_mss_at_min_path_mtu() {
    let mtu = 1280u16;
    let mss = usize::from(MssClamp::new(mtu).unwrap().mss_for_v6().unwrap());
    assert_eq!(mss, 1220, "1280 − 40 − 20 应为 1220");
    let mut fixture = v6(mtu).expect("IPv6 握手应成功");
    let payload = pattern(2000);
    let sent = parse_replies(&fixture.listener.send(fixture.key, &payload, NOW));
    assert_eq!(
        lengths(&sent),
        vec![1220, 780],
        "2000 字节按 v6 MSS 1220 应分两段，实际 {:?}",
        lengths(&sent)
    );
    for (index, segment) in sent.iter().enumerate() {
        assert!(
            segment.payload.len() <= 1220,
            "第 {index} 段载荷 {} 超过 IPv6 MSS 1220",
            segment.payload.len()
        );
        assert!(
            segment.ip_len <= usize::from(mtu),
            "第 {index} 段 IP 总长 {} 超过接口 MTU {mtu}",
            segment.ip_len
        );
    }
}

#[test]
fn empty_payload_emits_nothing() {
    let mss = mss_v4(1500);
    let mut fixture = v4(1500).expect("握手应成功");
    assert!(
        fixture.listener.send(fixture.key, &[], NOW).is_empty(),
        "空载荷应产出 0 段"
    );
    // 空载荷不得推进 snd_nxt：随后发送的首段序号仍应等于握手后的基准。
    let payload = pattern(mss);
    let sent = parse_replies(&fixture.listener.send(fixture.key, &payload, NOW));
    assert_eq!(sent.len(), 1, "非空载荷应产出 1 段，实际 {}", sent.len());
    assert_eq!(
        sent[0].seq, fixture.base,
        "空载荷不应推进序号：首段序号应为 {}，实际 {}",
        fixture.base, sent[0].seq
    );
}

#[test]
fn unknown_session_emits_nothing_and_does_not_advance() {
    let mss = mss_v4(1500);
    let mut fixture = v4(1500).expect("握手应成功");
    let unknown = SessionKey::new(
        Transport::Tcp,
        CLIENT_V4,
        CLIENT_PORT + 1,
        SERVER_V4,
        SERVER_PORT,
    );
    assert!(
        fixture
            .listener
            .send(unknown, &pattern(100), NOW)
            .is_empty(),
        "未建连的键应产出 0 段"
    );
    // 未命中会话不得改动真实会话的发送序号。
    let payload = pattern(mss);
    let sent = parse_replies(&fixture.listener.send(fixture.key, &payload, NOW));
    assert_eq!(sent.len(), 1, "真实会话应照常产出 1 段");
    assert_eq!(
        sent[0].seq, fixture.base,
        "未命中会话不应推进序号：首段序号应为 {}，实际 {}",
        fixture.base, sent[0].seq
    );
}

#[test]
fn underrun_interface_mtu_fails_closed() {
    let mtu = 500u16;
    assert!(
        MssClamp::new(mtu).is_err(),
        "MTU {mtu} 应低于 MssClamp 下限 576"
    );
    // 该 MTU 下入站过大判定会拒绝 SYN，无法建立会话：send 无段可发，也不推进任何序号。
    assert!(v4(mtu).is_none(), "MTU {mtu} 下不应建立会话");

    let mut listener = TcpListener::new(ListenerConfig {
        interface_mtu: mtu,
        ..Default::default()
    });
    let syn = client_packet(CLIENT_V4, SERVER_V4, CLIENT_SEQ, 0, Flags::SYN, &[]);
    let feed = listener.feed(&syn, NOW).unwrap();
    assert!(
        feed.replies.is_empty(),
        "MTU {mtu} 下 SYN 应被过大门槛拒绝，实际回包 {} 条",
        feed.replies.len()
    );
    assert_eq!(listener.session_count(), 0, "MTU {mtu} 下会话表应保持为空");
    let key = SessionKey::new(
        Transport::Tcp,
        CLIENT_V4,
        CLIENT_PORT,
        SERVER_V4,
        SERVER_PORT,
    );
    assert!(
        listener.send(key, &pattern(100), NOW).is_empty(),
        "MSS 无法换算时应 fail-closed 返回 0 段"
    );
    assert!(
        listener.send(key, &pattern(100), NOW).is_empty(),
        "重复调用仍应 fail-closed 返回 0 段"
    );
}

#[test]
fn reassembled_payload_is_byte_identical() {
    let mss = mss_v4(1500);
    let mut fixture = v4(1500).expect("握手应成功");
    let payload = pattern(3 * mss + 5);
    let sent = parse_replies(&fixture.listener.send(fixture.key, &payload, NOW));
    let mut reassembled = Vec::new();
    for segment in &sent {
        reassembled.extend_from_slice(&segment.payload);
    }
    assert_eq!(
        reassembled.len(),
        payload.len(),
        "重组长度应为 {}，实际 {}",
        payload.len(),
        reassembled.len()
    );
    assert_eq!(
        reassembled, payload,
        "按序拼接各段载荷必须与原载荷逐字节一致"
    );
}
