//! L1 传输接线层的**往返**用例：内存环回端到端 + 「链路上跑的是密文」。
//!
//! 覆盖任务书 §五 第 2 条的前两项：
//! - 环回端到端：对端拿到的**明文**与发出的一致；
//! - **链路上跑的是密文**（断言环回里搬运的字节 ≠ 明文）。
//!
//! ⛔ 本文件**不**证明与任何真实端互通：只证明「L2 封帧 → L1 搬运 → L2 解帧」
//! 这条接线在**同一进程内**自洽。真实 UDP 互通由 `crates/lengsuo-tunnel` 的卡负责。
//!
//! 全部是**测试专用假密钥**（0x11 / 0x22 模式字节），不代表任何真实凭据。
//! 对端公钥与 `tests/session_roundtrip.rs` 用的是同一组**仓外独立实现**
//! （Python `cryptography` 的 X25519）算出的常量。

use std::time::Instant;

use lengsuo_link_core::frame::{FrameType, FRAME_HEADER_LEN};
use lengsuo_link_core::session::{Session, SessionConfig, SessionRole};
use lengsuo_link_core::transport::{Link, Loopback, Transport, TransportError};

// ---------------------------------------------------------------- 假密钥材料

/// 发起方静态私钥（测试专用）。
const INITIATOR_STATIC: [u8; 32] = [0x11; 32];
/// 响应方静态私钥（测试专用）。
const RESPONDER_STATIC: [u8; 32] = [0x22; 32];
/// 发起方静态公钥（仓外 Python `cryptography` 的 X25519 独立算出）。
const INITIATOR_PUBLIC: [u8; 32] = [
    0x7b, 0x4e, 0x90, 0x9b, 0xbe, 0x7f, 0xfe, 0x44, 0xc4, 0x65, 0xa2, 0x20, 0x03, 0x7d, 0x60, 0x8e,
    0xe3, 0x58, 0x97, 0xd3, 0x1e, 0xf9, 0x72, 0xf0, 0x7f, 0x74, 0x89, 0x2c, 0xb0, 0xf7, 0x3f, 0x13,
];
/// 响应方静态公钥（仓外 Python `cryptography` 的 X25519 独立算出）。
const RESPONDER_PUBLIC: [u8; 32] = [
    0x0f, 0xaa, 0x68, 0x4e, 0xd2, 0x88, 0x67, 0xb9, 0x7f, 0x4a, 0x6a, 0x2d, 0xee, 0x5d, 0xf8, 0xce,
    0x97, 0x4e, 0x76, 0xb7, 0x01, 0x8e, 0x3f, 0x22, 0xa1, 0xc4, 0xcf, 0x26, 0x78, 0x57, 0x0f, 0x20,
];

// ---------------------------------------------------------------- 测试用传输

/// 记录**线上字节**的传输（测试专用）。
///
/// 用途：断言「链路上跑的是密文」——搬运层看到的字节必须是 AEAD 密文，
/// 而不是调用方交出去的明文。
#[derive(Debug)]
struct RecordingTransport {
    /// 真正搬运字节的内层传输。
    inner: Loopback,
    /// 已经发出去的字节（按发送顺序）。
    sent: Vec<Vec<u8>>,
}

impl RecordingTransport {
    fn new(inner: Loopback) -> Self {
        Self {
            inner,
            sent: Vec::new(),
        }
    }

    /// 已经发出去的字节。
    fn sent_bytes(&self) -> &[Vec<u8>] {
        &self.sent
    }
}

impl Transport for RecordingTransport {
    fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.sent.push(bytes.to_vec());
        self.inner.send(bytes)
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        self.inner.recv()
    }
}

// ---------------------------------------------------------------- 夹具

/// 构造（发起方, 响应方)一对**未握手**的会话。
fn session_pair() -> (Session, Session) {
    let initiator = Session::new(SessionConfig::new(
        SessionRole::Initiator,
        INITIATOR_STATIC,
        RESPONDER_PUBLIC,
    ))
    .expect("发起方会话可构造");
    let responder = Session::new(SessionConfig::new(
        SessionRole::Responder,
        RESPONDER_STATIC,
        INITIATOR_PUBLIC,
    ))
    .expect("响应方会话可构造");
    (initiator, responder)
}

/// 在同一对会话对象上跑完一轮握手（L2 已交付，本卡只调用不修改）。
fn handshake_round(
    initiator: &mut Session,
    responder: &mut Session,
    index_base: u32,
    seed_base: u8,
    now: Instant,
) {
    let initiation = initiator
        .create_initiation([seed_base; 32], index_base, now)
        .expect("initiation 可生成");
    responder
        .consume_initiation(&initiation, now)
        .expect("initiation 可剥壳");
    let response = responder
        .create_response([seed_base.wrapping_add(1); 32], index_base + 1, now)
        .expect("response 可生成");
    initiator
        .consume_response(&response, now)
        .expect("response 可消费");
}

/// 造一对**已握手**的链路接线（发起方带记录器，响应方裸环回）。
fn linked_pair() -> (Link<RecordingTransport>, Link<Loopback>) {
    let (mut initiator, mut responder) = session_pair();
    handshake_round(&mut initiator, &mut responder, 100, 0xA1, Instant::now());
    let (a, b) = Loopback::pair();
    (
        Link::new(initiator, RecordingTransport::new(a)),
        Link::new(responder, b),
    )
}

// ---------------------------------------------------------------- 环回端到端

#[test]
fn loopback_roundtrip_delivers_identical_plaintext() {
    let (mut a, mut b) = linked_pair();

    let plaintext = b"\x00\x01\x02ACP frame payload\xff\xfe".to_vec();
    a.send_frame(FrameType::Data, 42, &plaintext)
        .expect("发帧成功");

    let opened = b.recv_frame().expect("收帧成功");
    assert_eq!(opened.plaintext, plaintext, "对端明文必须与发出的一致");
    assert_eq!(opened.frame_type, FrameType::Data);
    assert_eq!(opened.seq, 42);
}

#[test]
fn loopback_carries_ciphertext_not_plaintext() {
    let (mut a, mut b) = linked_pair();

    let plaintext = b"plaintext-must-not-appear-on-the-wire".to_vec();
    a.send_frame(FrameType::Data, 1, &plaintext)
        .expect("发帧成功");

    // 搬运层看到的字节（线上字节）。
    let wire = a.transport().sent_bytes()[0].clone();
    assert_ne!(wire, plaintext, "线上字节不得等于明文");
    assert!(
        !wire
            .windows(plaintext.len())
            .any(|w| w == plaintext.as_slice()),
        "线上字节里不得出现明文片段"
    );

    // 线上字节是**合法的 L3 帧**（帧头 + AEAD 密文包），载荷不是明文。
    let frame = lengsuo_link_core::frame::decode_exact(&wire).expect("线上字节是合法帧");
    assert_eq!(frame.frame_type, FrameType::Data);
    assert_eq!(frame.seq, 1);
    assert_ne!(frame.payload, plaintext, "帧载荷必须是密文包");
    assert!(wire.len() > FRAME_HEADER_LEN, "帧载荷必须非空（密文包）");

    // 对端解出来的仍然是**明文**。
    let opened = b.recv_frame().expect("收帧成功");
    assert_eq!(opened.plaintext, plaintext);
}

#[test]
fn both_directions_work_over_the_same_link() {
    let (mut a, mut b) = linked_pair();

    let request = b"ping".to_vec();
    a.send_frame(FrameType::Data, 1, &request)
        .expect("发帧成功");
    assert_eq!(b.recv_frame().expect("收帧成功").plaintext, request);

    let reply = b"pong".to_vec();
    b.send_frame(FrameType::Data, 2, &reply).expect("发帧成功");
    assert_eq!(a.recv_frame().expect("收帧成功").plaintext, reply);
}

#[test]
fn multiple_sequential_frames_roundtrip() {
    let (mut a, mut b) = linked_pair();

    for round in 0..8u64 {
        let payload = vec![round as u8; (round as usize) * 17 + 1];
        a.send_frame(FrameType::Data, round, &payload)
            .expect("发帧成功");
        let opened = b.recv_frame().expect("收帧成功");
        assert_eq!(opened.plaintext, payload, "第 {round} 帧明文必须逐字节相同");
        assert_eq!(opened.seq, round);
    }
}

#[test]
fn control_and_keepalive_frames_roundtrip() {
    let (mut a, mut b) = linked_pair();

    a.send_frame(FrameType::Control, 7, b"negotiate")
        .expect("控制帧可发");
    let opened = b.recv_frame().expect("控制帧可收");
    assert_eq!(opened.frame_type, FrameType::Control);
    assert_eq!(opened.plaintext, b"negotiate".to_vec());

    a.send_frame(FrameType::Keepalive, 0, &[])
        .expect("keepalive 可发");
    let opened = b.recv_frame().expect("keepalive 可收");
    assert_eq!(opened.frame_type, FrameType::Keepalive);
    assert!(opened.plaintext.is_empty());
}

#[test]
fn empty_link_reports_would_block_instead_of_fabricating_bytes() {
    // 没有对端数据时，收帧必须**明确报错**，不得凭空造出字节。
    let (mut solo, other) = Loopback::pair();
    let error = solo.recv().expect_err("空线路必须报错");
    assert!(
        matches!(error, TransportError::WouldBlock),
        "期望 WOULD_BLOCK，实际 {error:?}"
    );
    drop(other);
}

// ---------------------------------------------------------------- 链路状态可见

#[test]
fn link_exposes_session_and_transport_state() {
    let (a, b) = linked_pair();
    assert!(a.session().is_established());
    assert!(b.session().is_established());
    // 传输是**字节搬运**，不暴露明文语义：会话对象不因搬运失败而失效。
    assert_eq!(a.session().generation(), b.session().generation());
}
