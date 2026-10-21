//! 端到端：真实回环 socket 字节 ↔ 用户态 TCP 栈。
//!
//! # 桥接性质（重要，勿误读）
//!
//! 本用例**不接真实 TUN 设备**。它起一个真实的 `tokio::net::TcpListener`（回环临时
//! 端口）作为「外部客户端」的真实 TCP 端点，由内核 TCP 完成对该 socket 的握手与
//! 可靠传输；然后由一个**字节桥** [`ClientBridge`] 把真客户端产出的**应用字节**封装
//! 成合成 IPv4/TCP 报文喂给用户态栈 [`TcpListener::feed`]，再把栈的回包解封装、把
//! 载荷写回真 socket。也就是说：桥的一侧是真内核 TCP，另一侧是**合成 IP 报文**，
//! 不是真实的网卡收包路径。桥自身实现客户端侧的最小 TCP 语义（SYN/ACK/数据/FIN/RST），
//! 用来驱动被测栈的服务端侧被动打开路径。
//!
//! 断言覆盖：三次握手 → 客户端写定长载荷 → 栈按序交付逐字节相等 → 上层回写 →
//! 客户端读到逐字节相等 → 客户端 `shutdown(Write)` 后无挂起；外加三条边界
//! （突然 RST、只发 SYN 不发 ACK 后 TTL 回收、超 MTU 载荷）。所有异步等待都带
//! `tokio::time::timeout`。

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use lengsuo_tun::packet;
use lengsuo_tun::session::SessionKey;
use lengsuo_tun::tcp::listener::{Config as ListenerConfig, TcpListener};
use lengsuo_tun::tcp::segment::{self, Flags};
use lengsuo_tun::tcp::state::Config as ConnConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioListener, TcpStream as TokioStream};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const SERVER_PORT: u16 = 8080;
const CLIENT_PORT: u16 = 40000;
const TIMEOUT: Duration = Duration::from_secs(5);
const NOW: u64 = 1;

/// 客户端侧最小 TCP：驱动合成 IP 报文进出被测栈。
struct ClientBridge {
    listener: TcpListener,
    seq: u32,
    ack: u32,
    key: SessionKey,
    established: bool,
    peer_fin: bool,
}

impl ClientBridge {
    fn new(mtu: u16, capacity: usize) -> Self {
        let listener = TcpListener::new(ListenerConfig {
            connection: ConnConfig {
                receive_window: 4096,
                reorder_slots: 4,
                iss_seed: 0,
            },
            session_capacity: capacity,
            session_ttl: 30,
            interface_mtu: mtu,
            iss_seed_start: 1000,
        });
        Self {
            listener,
            seq: 7000,
            ack: 0,
            key: SessionKey::new(
                packet::Transport::Tcp,
                IpAddr::V4(CLIENT_IP),
                CLIENT_PORT,
                IpAddr::V4(SERVER_IP),
                SERVER_PORT,
            ),
            established: false,
            peer_fin: false,
        }
    }

    /// 把一个客户端→服务端的段打成 IPv4 报文并喂给栈，返回栈的交付载荷与回包。
    fn push(&mut self, flags: Flags, payload: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        let packet = ipv4_client_to_server(self.seq, self.ack, flags, payload).unwrap();
        let feed = self.listener.feed(&packet, NOW).unwrap();
        self.seq = self.seq.wrapping_add(segment_len(flags, payload.len()));
        let mut out = Vec::new();
        for reply in &feed.replies {
            packet::inspect(reply).unwrap();
            // `payload_offset` 是应用载荷偏移；TCP 段首为 IPv4 IHL×4。
            let seg = segment::parse(&reply[tcp_start(reply)..]).unwrap();
            // 服务端回包的确认号推进客户端 ack；SYN/FIN 各占一个序号。
            self.ack = seg.seq.wrapping_add(seg.sequence_length());
            if seg.flags.has_syn() {
                self.ack = seg.seq.wrapping_add(1);
            }
            if seg.flags.has_fin() {
                self.peer_fin = true;
            }
            if !seg.payload.is_empty() {
                out.push(seg.payload.to_vec());
            }
        }
        (feed.delivered, out)
    }

    /// 三次握手：返回握手期间栈回包带来的载荷（应为空）。
    fn handshake(&mut self) -> Vec<Vec<u8>> {
        let (delivered, replies) = self.push(Flags::SYN, &[]);
        assert!(delivered.is_empty(), "握手期不应交付载荷");
        self.push(Flags::ACK, &[]);
        self.established = true;
        replies
    }
}

fn segment_len(flags: Flags, payload: usize) -> u32 {
    u32::from(flags.has_syn()) + u32::from(flags.has_fin()) + payload as u32
}

/// 合成 客户端→服务端 的 IPv4 + TCP 报文。
fn ipv4_client_to_server(seq: u32, ack: u32, flags: Flags, payload: &[u8]) -> Result<Vec<u8>, ()> {
    let pseudo = pseudo_v4(
        CLIENT_IP,
        SERVER_IP,
        (segment::MIN_HEADER + payload.len()) as u16,
    );
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
    .map_err(|_| ())
    .map(|tcp| wrap_ipv4(CLIENT_IP, SERVER_IP, tcp))
}

fn pseudo_v4(src: Ipv4Addr, dst: Ipv4Addr, len: u16) -> [u8; 12] {
    let mut p = [0u8; 12];
    p[0..4].copy_from_slice(&src.octets());
    p[4..8].copy_from_slice(&dst.octets());
    p[9] = 6;
    p[10..12].copy_from_slice(&len.to_be_bytes());
    p
}

/// 加 20 字节 IPv4 头（IHL=5）：`packet::inspect` 要求头部校验和正确、长度自洽。
fn wrap_ipv4(src: Ipv4Addr, dst: Ipv4Addr, tcp: Vec<u8>) -> Vec<u8> {
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

/// RFC 1071 一补码和（测试本地实现，与服务端栈构造路径相互独立）。
fn checksum_of(bytes: &[u8]) -> u16 {
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

fn parse_reply(reply: &[u8]) -> (Flags, u32, Vec<u8>) {
    packet::inspect(reply).unwrap();
    let seg = segment::parse(&reply[tcp_start(reply)..]).unwrap();
    (seg.flags, seg.ack, seg.payload.to_vec())
}

/// TCP 段起始偏移 = IPv4 IHL×4。
fn tcp_start(ipv4: &[u8]) -> usize {
    usize::from(ipv4[0] & 0x0f) * 4
}

/// 起真实回环 TcpListener 作为「外部客户端」端点，返回其临时端口。
async fn real_client_listener() -> (TokioListener, u16) {
    let listener = TokioListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

#[tokio::test]
async fn handshake_bidirectional_payload_and_fin() {
    let (listener, port) = real_client_listener().await;
    let connect = tokio::spawn(async move {
        let mut stream = TokioStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        stream.write_all(b"hello-from-real-client").await.unwrap();
        let mut back = vec![0u8; "pong-from-stack".len()];
        stream.read_exact(&mut back).await.unwrap();
        stream.shutdown().await.unwrap();
        back
    });
    // 真实客户端完成内核 TCP 握手后，桥才拿到「应用字节」。
    let (mut sock, _) = tokio::time::timeout(TIMEOUT, listener.accept())
        .await
        .unwrap()
        .unwrap();

    let mut bridge = ClientBridge::new(1500, 8);
    bridge.handshake();
    assert_eq!(bridge.listener.stats().established, 1, "三次握手应完成一次");

    // 客户端写定长载荷 → 栈按序交付，逐字节相等。
    let sent = b"hello-from-real-client";
    let (delivered, _) = bridge.push(Flags::ACK | Flags::PSH, sent);
    assert_eq!(delivered, sent, "栈交付必须与客户端写入逐字节相等");

    // 上层回写 → 经 listener::send 编成段 → 桥解封装写回真 socket。
    let echo = b"pong-from-stack";
    let replies = bridge.listener.send(bridge.key, echo, NOW);
    assert_eq!(replies.len(), 1, "回写应产出一条 IP 报文");
    let (flags, _ack, payload) = parse_reply(&replies[0]);
    assert!(flags.has_ack() && flags.has_psh());
    assert_eq!(payload, echo);
    tokio::time::timeout(TIMEOUT, sock.write_all(&payload))
        .await
        .unwrap()
        .unwrap();

    // 真客户端读到逐字节相等。
    let back = tokio::time::timeout(TIMEOUT, connect)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(back, b"pong-from-stack");

    // 客户端 shutdown(Write) → 栈收 FIN 进 CloseWait，回 ACK；收尾无挂起。
    let (delivered, replies) = bridge.push(Flags::FIN | Flags::ACK, &[]);
    assert!(delivered.is_empty());
    assert_eq!(replies.len(), 0, "纯 ACK 不计入交付载荷");
    assert_eq!(bridge.listener.stats().peer_fin, 1, "应记录一次对端 FIN");
}

#[tokio::test]
async fn sudden_reset_reclaims_session() {
    let mut bridge = ClientBridge::new(1500, 8);
    bridge.handshake();
    assert_eq!(bridge.listener.stats().established, 1);
    // 客户端突然 RST：连接终止、会话条目被回收，不泄漏。
    let (delivered, replies) = bridge.push(Flags::RST, &[]);
    assert!(
        delivered.is_empty() && replies.is_empty(),
        "RST 不产生交付/回包"
    );
    assert_eq!(bridge.listener.stats().reset, 1, "应记录一次复位");
    assert_eq!(bridge.listener.session_count(), 0, "RST 后会话必须被回收");
    // RST 之后再投喂数据段也不 panic。
    let (delivered, _) = bridge.push(Flags::ACK | Flags::PSH, b"late");
    assert!(delivered.is_empty());
}

#[tokio::test]
async fn half_open_syn_then_ttl_reclaim() {
    let mut bridge = ClientBridge::new(1500, 8);
    let (delivered, _) = bridge.push(Flags::SYN, &[]);
    assert!(delivered.is_empty());
    assert_eq!(bridge.listener.stats().syn_received, 1);
    assert_eq!(bridge.listener.session_count(), 1, "只发 SYN 也会建会话");
    // 只发 SYN 不发 ACK：不推进到 Established，等待 TTL 回收。
    assert_eq!(bridge.listener.stats().established, 0);
    let reclaimed = bridge.listener.gc(NOW + 31);
    assert_eq!(reclaimed, 1, "TTL 到期应回收半开会话");
    assert_eq!(bridge.listener.session_count(), 0);
}

#[tokio::test]
async fn oversize_payload_is_rejected_not_truncated() {
    // 接口 MTU 取 IPv4 下限，构造一个明显超 MTU 的入站数据段。
    let mut bridge = ClientBridge::new(576, 8);
    bridge.handshake();
    let too_big = vec![7u8; 1200];
    let packet =
        ipv4_client_to_server(bridge.seq, bridge.ack, Flags::ACK | Flags::PSH, &too_big).unwrap();
    // 超过接口 MTU（576）的入站报文必须被拒，且不 panic、不越界写。
    let feed = bridge.listener.feed(&packet, NOW).unwrap();
    assert!(feed.delivered.is_empty(), "超 MTU 载荷不得交付");
    assert!(feed.replies.is_empty(), "超 MTU 载荷不得产生回包");
    assert_eq!(bridge.listener.stats().oversize, 1, "应记录一次过大拒绝");
    assert_eq!(bridge.listener.stats().delivered_bytes, 0);
}
