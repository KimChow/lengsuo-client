//! `link-core` 的 L1 `Transport` + L2 `Session` 接进 PC 端运行时的验收用例。
//!
//! 覆盖：
//!
//! 1. **跨端字节逐字节相同**（独立参照）：移动端 `link-core::session::Session`
//!    与 PC 端 `assembly` 的 `Keypair::seal` 路径，各自跑完一轮**独立**握手
//!    （墙钟时间戳不同），封出的 L3 帧必须**逐字节相同**。
//! 2. **生产路径真实收发**：`Link::send_frame` / `Link::recv_frame` 走真 UDP。
//! 3. **fail-closed 三条**：认证失败、超长字节、会话失效。
//! 4. **`WouldBlock` 不是失败**：空队列必须返回它。
//! 5. **明文不上线**：线上数据报不得包含明文（明文旁路禁令）。
//!
//! 纪律：每个异步用例都带硬超时，不许挂死。
//!
//! ⛔ **假凭据**：本文件的静态私钥/公钥是固定测试夹具，不是任何真实凭据。

use std::time::{Duration, Instant};

use lengsuo_link_core::frame::{FrameType, OpenedFrame, MAX_FRAME_LEN};
use lengsuo_link_core::session::{Session, SessionConfig, SessionError, SessionRole};
use lengsuo_link_core::transport::{Link, Transport, TransportError};
use lengsuo_tunnel::assembly::{
    Assembly, AssemblyConfig, InitiatorHandshake, ResponderHandshake, Role,
};
use lengsuo_tunnel::link::{spawn_link, UdpTransport};
use lengsuo_tunnel::udp::UdpEndpoint;

/// 异步用例的硬超时。
const TIMEOUT: Duration = Duration::from_secs(5);

/// 发起方静态私钥（**假凭据**，仅测试用）。
const INITIATOR_SECRET: [u8; 32] = [0x11; 32];
/// 响应方静态私钥（**假凭据**，仅测试用）。
const RESPONDER_SECRET: [u8; 32] = [0x22; 32];
/// 发起方静态公钥（由 `INITIATOR_SECRET` 派生）。
const INITIATOR_PUBLIC: [u8; 32] = [
    0x7b, 0x4e, 0x90, 0x9b, 0xbe, 0x7f, 0xfe, 0x44, 0xc4, 0x65, 0xa2, 0x20, 0x03, 0x7d, 0x60, 0x8e,
    0xe3, 0x58, 0x97, 0xd3, 0x1e, 0xf9, 0x72, 0xf0, 0x7f, 0x74, 0x89, 0x2c, 0xb0, 0xf7, 0x3f, 0x13,
];
/// 响应方静态公钥（由 `RESPONDER_SECRET` 派生）。
const RESPONDER_PUBLIC: [u8; 32] = [
    0x0f, 0xaa, 0x68, 0x4e, 0xd2, 0x88, 0x67, 0xb9, 0x7f, 0x4a, 0x6a, 0x2d, 0xee, 0x5d, 0xf8, 0xce,
    0x97, 0x4e, 0x76, 0xb7, 0x01, 0x8e, 0x3f, 0x22, 0xa1, 0xc4, 0xcf, 0x26, 0x78, 0x57, 0x0f, 0x20,
];

/// 发起方临时密钥种子（确定性 ⇒ 可复现）。
const SEED: [u8; 32] = [0xAA; 32];
/// 响应方临时密钥种子。
const RESPONDER_SEED: [u8; 32] = [0xBB; 32];
/// 发起方本轮 index（两侧必须显式对齐）。
const INITIATOR_INDEX: u32 = 0x1026_1234;
/// 响应方本轮 index。
const RESPONDER_INDEX: u32 = 0x2026_1234;

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("回环地址可解析")
}

/// 建一对互指的对端。
async fn endpoint_pair() -> (UdpEndpoint, UdpEndpoint) {
    let mut a = UdpEndpoint::bind(loopback()).await.expect("绑定 a");
    let mut b = UdpEndpoint::bind(loopback()).await.expect("绑定 b");
    a.set_peer_endpoint(b.local_addr().expect("取 b 地址"))
        .await
        .expect("设置 a 的对端");
    b.set_peer_endpoint(a.local_addr().expect("取 a 地址"))
        .await
        .expect("设置 b 的对端");
    (a, b)
}

/// 移动端路径：用 `link-core::session::Session` 跑完一轮握手。
fn mobile_sessions() -> (Session, Session) {
    let mut initiator = Session::new(SessionConfig::new(
        SessionRole::Initiator,
        INITIATOR_SECRET,
        RESPONDER_PUBLIC,
    ))
    .expect("发起方会话可建");
    let mut responder = Session::new(SessionConfig::new(
        SessionRole::Responder,
        RESPONDER_SECRET,
        INITIATOR_PUBLIC,
    ))
    .expect("响应方会话可建");

    let now = Instant::now();
    let initiation = initiator
        .create_initiation(SEED, INITIATOR_INDEX, now)
        .expect("initiation 可产出");
    responder
        .consume_initiation(&initiation, now)
        .expect("initiation 必须被接受");
    let response = responder
        .create_response(RESPONDER_SEED, RESPONDER_INDEX, now)
        .expect("response 可产出");
    initiator
        .consume_response(&response, now)
        .expect("response 必须被接受");
    (initiator, responder)
}

/// PC 端路径：用 `assembly` 的 `Keypair::seal` 路径跑完一轮握手。
fn pc_initiator_assembly() -> Assembly {
    let pc = Assembly::new(
        AssemblyConfig::new(Role::Initiator, INITIATOR_SECRET, RESPONDER_PUBLIC)
            .with_local_index(INITIATOR_INDEX),
    )
    .expect("PC 发起方可建");
    let peer = Assembly::new(
        AssemblyConfig::new(Role::Responder, RESPONDER_SECRET, INITIATOR_PUBLIC)
            .with_local_index(RESPONDER_INDEX),
    )
    .expect("PC 响应方可建");

    let mut handshake = InitiatorHandshake::new(&pc, SEED).expect("PC 握手可建");
    let initiation = handshake.create_initiation(SEED).expect("PC initiation");
    let mut responder = ResponderHandshake::new(&peer).expect("PC 响应方握手可建");
    responder
        .consume_initiation(&initiation)
        .expect("接受 PC initiation");
    let (response, _keys) = responder
        .create_response(RESPONDER_SEED, RESPONDER_INDEX)
        .expect("PC response");
    let keys = handshake
        .consume_response(&response)
        .expect("接受 PC response");

    let mut pc = pc;
    pc.install_keys(&keys).expect("落地 PC 密钥");
    pc
}

/// 轮询收帧，直到拿到非 `WouldBlock` 的结果。
async fn recv_until(link: &mut Link<UdpTransport>) -> Result<OpenedFrame, TransportError> {
    loop {
        match link.recv_frame() {
            Err(TransportError::WouldBlock) => tokio::time::sleep(Duration::from_millis(2)).await,
            other => return other,
        }
    }
}

/// 轮询收帧，直到拿到错误。
async fn recv_error(link: &mut Link<UdpTransport>) -> TransportError {
    loop {
        match link.recv_frame() {
            Err(TransportError::WouldBlock) => tokio::time::sleep(Duration::from_millis(2)).await,
            Err(error) => return error,
            Ok(_) => panic!("不应解出帧"),
        }
    }
}

/// 轮询 transport，直到拿到非 `WouldBlock` 的错误。
async fn transport_error(transport: &mut UdpTransport) -> TransportError {
    loop {
        match transport.recv() {
            Err(TransportError::WouldBlock) => tokio::time::sleep(Duration::from_millis(2)).await,
            Err(error) => return error,
            Ok(bytes) => panic!("不应收到合法字节：{bytes:?}"),
        }
    }
}

/// 子串包含（明文泄漏判定）。
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ------------------------------------------------- 2.3 跨端字节逐字节相同

/// 两条**独立**路径各跑一轮握手（墙钟时间戳不同），封出的帧必须逐字节相同。
///
/// 参照物：PC 端 `Assembly::seal_frame`（内部走 `Keypair::seal`，即现有 `assembly`
/// 路径）。被测方：移动端 `Session::seal_frame`（`Link::send_frame` 的下半截）。
/// ⛔ 这不是「自己封自己解」的闭环——是两套独立实现产出的字节对拍。
#[test]
fn cross_stack_seal_frame_bytes_are_identical() {
    let (mut mobile, _mobile_peer) = mobile_sessions();
    let mut pc = pc_initiator_assembly();

    let plain = b"cross-end byte-for-byte";
    let seq = 7;

    let mobile_bytes = mobile
        .seal_frame(FrameType::Data, seq, plain)
        .expect("移动端封帧");
    let pc_bytes = pc
        .seal_frame(FrameType::Data, seq, plain)
        .expect("PC 端封帧")
        .encode()
        .expect("帧编码");

    assert!(!mobile_bytes.is_empty(), "封帧结果不应为空");
    assert_eq!(
        mobile_bytes, pc_bytes,
        "两端封出的 L3 帧必须逐字节相同（跨端一致）"
    );
}

// ------------------------------------------------- 2.2 生产路径上的真实收发

#[tokio::test]
async fn link_roundtrip_over_real_udp() {
    let (a_endpoint, b_endpoint) = endpoint_pair().await;
    let (session_a, session_b) = mobile_sessions();
    let mut link_a = spawn_link(session_a, a_endpoint);
    let mut link_b = spawn_link(session_b, b_endpoint);

    let plain = b"production path over real udp";
    link_a
        .send_frame(FrameType::Data, 1, plain)
        .expect("发送应成功");

    let opened = tokio::time::timeout(TIMEOUT, recv_until(&mut link_b))
        .await
        .expect("必须在超时内收到")
        .expect("收帧应成功");
    assert_eq!(opened.plaintext, plain, "收到的明文必须与发出的相同");
}

// ------------------------------------------------------------ fail-closed

/// 超长**发送**：明确 `TooLong`，⛔ 不截断、不入队。
#[tokio::test]
async fn send_rejects_oversize_without_truncation() {
    let endpoint = UdpEndpoint::bind(loopback()).await.expect("绑定");
    let mut transport = UdpTransport::new(endpoint);

    let bytes = vec![0x5A; MAX_FRAME_LEN + 1];
    assert_eq!(
        transport.send(&bytes),
        Err(TransportError::TooLong {
            actual: MAX_FRAME_LEN + 1,
            limit: MAX_FRAME_LEN,
        }),
        "超长发送必须明确报错（不截断）"
    );
    // 被拒绝的字节没有入队。
    assert_eq!(transport.recv(), Err(TransportError::WouldBlock));
}

/// 超长**接收**：明确 `TooLong`，且该包被丢弃（不会卡住接收侧）。
#[tokio::test]
async fn recv_rejects_oversize_and_discards_packet() {
    let (a_endpoint, b_endpoint) = endpoint_pair().await;
    let mut transport = UdpTransport::new(b_endpoint);

    a_endpoint
        .send_raw(&vec![0xAB; MAX_FRAME_LEN + 1])
        .await
        .expect("发出超长数据报");

    let error = tokio::time::timeout(TIMEOUT, transport_error(&mut transport))
        .await
        .expect("必须在超时内收到 TooLong");
    assert_eq!(
        error,
        TransportError::TooLong {
            actual: MAX_FRAME_LEN + 1,
            limit: MAX_FRAME_LEN,
        },
        "超长接收必须明确报错（不截断）"
    );
    assert_eq!(
        transport.recv(),
        Err(TransportError::WouldBlock),
        "超长包必须被丢弃，不能留在队列里"
    );
}

/// 空队列 ⇒ `WouldBlock`（**不是失败**）。
#[tokio::test]
async fn recv_without_data_returns_would_block() {
    let endpoint = UdpEndpoint::bind(loopback()).await.expect("绑定");
    let mut transport = UdpTransport::new(endpoint);

    assert_eq!(
        transport.recv(),
        Err(TransportError::WouldBlock),
        "空队列必须是 WouldBlock（不是 Closed、不是失败）"
    );
}

/// 认证失败：明确报错、会话失效、⛔ 不回退明文。
#[tokio::test]
async fn auth_failure_fails_closed_and_invalidates_session() {
    let (a_endpoint, b_endpoint) = endpoint_pair().await;
    let (mut session_a, session_b) = mobile_sessions();
    let mut link_b = spawn_link(session_b, b_endpoint);

    // A 侧直接封帧（不经 Link），这样能拿到线上字节并逐字节篡改。
    let mut sealed = session_a
        .seal_frame(FrameType::Data, 1, b"tamper me")
        .expect("封帧");
    // 破坏 Poly1305 标签的最后一个字节：帧头 CRC 与计数器仍然合法，
    // 只有 AEAD 认证会失败 ⇒ 必须走到 `AuthFailed` 而不是别的错误。
    let last = sealed.len() - 1;
    sealed[last] ^= 0xFF;
    a_endpoint.send_raw(&sealed).await.expect("发出篡改帧");

    let error = tokio::time::timeout(TIMEOUT, recv_error(&mut link_b))
        .await
        .expect("必须在超时内收到错误");
    assert!(
        matches!(error, TransportError::Session(SessionError::AuthFailed)),
        "认证失败必须明确报错，实际 {error:?}"
    );
    assert!(link_b.session().is_invalidated(), "认证失败后会话必须失效");

    // 失效后收发立即被拒（⛔ 不回退明文）。
    assert!(
        matches!(
            link_b.recv_frame(),
            Err(TransportError::Session(SessionError::Invalidated))
        ),
        "失效会话的收必须立即被拒"
    );
    assert!(
        matches!(
            link_b.send_frame(FrameType::Data, 2, b"x"),
            Err(TransportError::Session(SessionError::Invalidated))
        ),
        "失效会话的发必须立即被拒"
    );
}

/// 显式作废：收发立即被拒。
#[tokio::test]
async fn invalidated_session_rejects_send_and_recv() {
    let (mut session, _peer) = mobile_sessions();
    session.invalidate();
    let endpoint = UdpEndpoint::bind(loopback()).await.expect("绑定");
    let mut link = spawn_link(session, endpoint);

    assert!(
        matches!(
            link.send_frame(FrameType::Data, 1, b"after invalidate"),
            Err(TransportError::Session(SessionError::Invalidated))
        ),
        "失效会话的发必须立即被拒"
    );
    assert!(
        matches!(
            link.recv_frame(),
            Err(TransportError::Session(SessionError::Invalidated))
        ),
        "失效会话的收必须立即被拒"
    );
}

// -------------------------------------------------------- H3 明文不上线

#[tokio::test]
async fn data_plaintext_never_appears_on_the_wire() {
    const PLAIN: &[u8] = b"PLAINTEXT-MUST-NOT-LEAK-4C0FFEE";

    let (a_endpoint, b_endpoint) = endpoint_pair().await;
    let (session_a, _session_b) = mobile_sessions();
    let mut link_a = spawn_link(session_a, a_endpoint);

    link_a
        .send_frame(FrameType::Data, 1, PLAIN)
        .expect("发送应成功");

    let mut buf = vec![0u8; MAX_FRAME_LEN + 1];
    let (len, _source) = tokio::time::timeout(TIMEOUT, b_endpoint.recv_raw(&mut buf))
        .await
        .expect("必须在超时内收到数据报")
        .expect("必须收到数据报");
    assert!(
        !contains(&buf[..len], PLAIN),
        "线上数据报不得包含明文（明文旁路禁令）"
    );
}
