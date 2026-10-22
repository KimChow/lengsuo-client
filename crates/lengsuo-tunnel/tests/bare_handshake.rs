//! 裸握手（bare handshake）线上格式用例。
//!
//! 覆盖任务书三·1–3：
//!
//! 1. **线上字节**：initiation 数据报 **148B / 首字节 0x01**，response
//!    **92B / 首字节 0x02**；⛔ 旧的帧封装长度（168 / 112）**不得**出现；
//! 2. **首字节分流**：见 `src/udp/datagram.rs` 的单元测试（纯函数 ≥5 条）；
//! 3. **跨栈字节等价性**：移动端路径（`lengsuo_link_core::session`）与
//!    PC 端路径（`lengsuo_tunnel::assembly`）产出的裸字节**逐字节相同**
//!    （墙钟依赖区段除外）。
//!
//! 纪律：每个异步用例都带硬超时，不许挂死。
//!
//! ⛔ **假凭据**：本文件的静态私钥/公钥是**固定的测试夹具**，不是任何真实凭据。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use lengsuo_link_core::frame::MAX_FRAME_LEN;
use lengsuo_link_core::session::{Session, SessionConfig, SessionRole};
use lengsuo_tunnel::assembly::{Assembly, AssemblyConfig, InitiatorHandshake, Role};
use lengsuo_tunnel::udp::{
    Cancel, HandshakeKind, UdpEndpoint, UdpEvent, DEFAULT_RECV_QUEUE_CAPACITY,
};

/// 异步用例的硬超时。
const TIMEOUT: Duration = Duration::from_secs(5);

/// 发起方静态私钥（**假凭据**，仅测试用）。
const INITIATOR_SECRET: [u8; 32] = [0x11; 32];
/// 响应方静态私钥（**假凭据**，仅测试用）。
const RESPONDER_SECRET: [u8; 32] = [0x22; 32];
/// 发起方静态公钥（由 `INITIATOR_SECRET` 派生，见 `x25519_pub`）。
const INITIATOR_PUBLIC: [u8; 32] = [
    0x7b, 0x4e, 0x90, 0x9b, 0xbe, 0x7f, 0xfe, 0x44, 0xc4, 0x65, 0xa2, 0x20, 0x03, 0x7d, 0x60, 0x8e,
    0xe3, 0x58, 0x97, 0xd3, 0x1e, 0xf9, 0x72, 0xf0, 0x7f, 0x74, 0x89, 0x2c, 0xb0, 0xf7, 0x3f, 0x13,
];
/// 响应方静态公钥（由 `RESPONDER_SECRET` 派生，见 `x25519_pub`）。
const RESPONDER_PUBLIC: [u8; 32] = [
    0x0f, 0xaa, 0x68, 0x4e, 0xd2, 0x88, 0x67, 0xb9, 0x7f, 0x4a, 0x6a, 0x2d, 0xee, 0x5d, 0xf8, 0xce,
    0x97, 0x4e, 0x76, 0xb7, 0x01, 0x8e, 0x3f, 0x22, 0xa1, 0xc4, 0xcf, 0x26, 0x78, 0x57, 0x0f, 0x20,
];

/// 发起方的临时密钥种子（确定性 ⇒ 可复现）。
const INITIATOR_SEED: [u8; 32] = [0xAA; 32];
/// 响应方的临时密钥种子。
const RESPONDER_SEED: [u8; 32] = [0xBB; 32];
/// 发起方本轮 index（两侧必须**显式对齐**，否则字节不同）。
const INITIATOR_INDEX: u32 = 0x1026_1234;
/// 响应方本轮 index。
const RESPONDER_INDEX: u32 = 0x2026_1234;

/// initiation 的**墙钟依赖区段**（向量口径：`88-132`）。
///
/// `bytes[88..116]` = TAI64N 时间戳密文（28B），`bytes[116..132]` = 覆盖前者的
/// MAC1（16B）。⇒ 这 44 字节每次跑都不一样，比对前必须清零。
const INITIATION_VOLATILE: (usize, usize) = (88, 132);
/// response 的**墙钟依赖区段**（向量口径：`44-76`）。
///
/// `bytes[44..60]` = empty 密文（16B，AAD = 当前 hash 链），
/// `bytes[60..76]` = 覆盖前者的 MAC1（16B）。
const RESPONSE_VOLATILE: (usize, usize) = (44, 76);

/// 把一段区段清零（比对前的**唯一**合法归一化方式）。
fn zeroed(bytes: &[u8], range: (usize, usize)) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[range.0..range.1].fill(0);
    out
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().expect("回环地址可解析")
}

async fn endpoint() -> UdpEndpoint {
    UdpEndpoint::bind(loopback())
        .await
        .expect("绑定回环端口应当成功")
}

/// 建一对互指的对端。
async fn pair() -> (UdpEndpoint, UdpEndpoint) {
    let mut a = endpoint().await;
    let mut b = endpoint().await;
    a.set_peer_endpoint(b.local_addr().expect("取本端地址"))
        .await
        .expect("设置对端地址应当成功");
    b.set_peer_endpoint(a.local_addr().expect("取本端地址"))
        .await
        .expect("设置对端地址应当成功");
    (a, b)
}

/// 一块足以放下「一个满帧 + 1 字节」的接收缓冲。
fn buffer() -> Vec<u8> {
    vec![0u8; MAX_FRAME_LEN + 1]
}

/// PC 端（tunnel）的发起方装配层。
fn pc_initiator() -> Assembly {
    Assembly::new(
        AssemblyConfig::new(Role::Initiator, INITIATOR_SECRET, RESPONDER_PUBLIC)
            .with_local_index(INITIATOR_INDEX),
    )
    .expect("发起方装配层可建")
}

/// 移动端（link-core）的会话。
fn mobile_session(role: SessionRole) -> Session {
    let config = match role {
        SessionRole::Initiator => SessionConfig::new(role, INITIATOR_SECRET, RESPONDER_PUBLIC),
        SessionRole::Responder => SessionConfig::new(role, RESPONDER_SECRET, INITIATOR_PUBLIC),
    };
    Session::new(config).expect("会话可建")
}

// ------------------------------------------------ 1. 线上字节：148B / 92B 裸报文

#[tokio::test]
async fn bare_handshake_datagrams_are_148_and_92_bytes_without_frame_header() {
    let (a_socket, b_socket) = pair().await;
    let assembly = pc_initiator();
    let mut handshake = InitiatorHandshake::new(&assembly, INITIATOR_SEED).expect("握手上下文可建");
    let initiation = handshake
        .create_initiation(INITIATOR_SEED)
        .expect("initiation 可构造");

    // 发起方**裸**发出（⛔ 不是 send_frame）。
    a_socket
        .send_raw(&initiation)
        .await
        .expect("initiation 应当发出");

    let mut buf = buffer();
    let (len, _source) = tokio::time::timeout(TIMEOUT, b_socket.recv_raw(&mut buf))
        .await
        .expect("响应方必须在超时内收到 initiation")
        .expect("必须收到一个裸数据报");
    assert_eq!(len, 148, "initiation 线上必须是 148 字节（裸报文）");
    assert_eq!(buf[0], 0x01, "initiation 首字节必须是 0x01（类型字段）");
    assert_eq!(
        &buf[..len],
        &initiation[..],
        "线上字节必须与产出的裸握手**逐字节相同**"
    );
    // ⛔ 旧的帧封装长度（20B 帧头 + 148B）不得再出现。
    assert_ne!(len, 168, "不得再套 L3 帧头（168B 是旧格式）");

    // 响应方：消费 initiation → 产出 response（92B 裸报文）。
    let responder = Assembly::new(
        AssemblyConfig::new(Role::Responder, RESPONDER_SECRET, INITIATOR_PUBLIC)
            .with_local_index(RESPONDER_INDEX),
    )
    .expect("响应方装配层可建");
    let mut responder_hs = lengsuo_tunnel::assembly::ResponderHandshake::new(&responder)
        .expect("响应方握手上下文可建");
    responder_hs
        .consume_initiation(&initiation)
        .expect("initiation 必须被接受");
    let (response, _keys) = responder_hs
        .create_response(RESPONDER_SEED, RESPONDER_INDEX)
        .expect("response 可构造");
    b_socket
        .send_raw(&response)
        .await
        .expect("response 应当发出");

    let mut buf = buffer();
    let (len, _source) = tokio::time::timeout(TIMEOUT, a_socket.recv_raw(&mut buf))
        .await
        .expect("发起方必须在超时内收到 response")
        .expect("必须收到一个裸数据报");
    assert_eq!(len, 92, "response 线上必须是 92 字节（裸报文）");
    assert_eq!(buf[0], 0x02, "response 首字节必须是 0x02（类型字段）");
    assert_eq!(
        &buf[..len],
        &response[..],
        "response 线上字节必须逐字节相同"
    );
    // ⛔ 旧的帧封装长度（20B 帧头 + 92B）不得再出现。
    assert_ne!(len, 112, "不得再套 L3 帧头（112B 是旧格式）");
}

// ------------------------------------- 2. 收循环按首字节分流：裸握手走 Handshake 事件

#[tokio::test]
async fn recv_loop_delivers_bare_handshake_as_handshake_event() {
    let (a_socket, b_socket) = pair().await;
    let assembly = pc_initiator();
    let mut handshake = InitiatorHandshake::new(&assembly, INITIATOR_SEED).expect("握手上下文可建");
    let initiation = handshake
        .create_initiation(INITIATOR_SEED)
        .expect("initiation 可构造");

    let cancel = Cancel::new();
    let (mut events, handle) = lengsuo_tunnel::udp::spawn_recv_loop(
        b_socket.clone(),
        DEFAULT_RECV_QUEUE_CAPACITY,
        cancel.clone(),
    );

    a_socket
        .send_raw(&initiation)
        .await
        .expect("initiation 应当发出");

    let event = tokio::time::timeout(TIMEOUT, events.recv())
        .await
        .expect("事件必须在超时内到达")
        .expect("事件通道不应关闭");
    match &event {
        UdpEvent::Handshake {
            kind,
            bytes,
            source,
        } => {
            assert_eq!(*kind, HandshakeKind::Initiation);
            assert_eq!(bytes.len(), 148, "裸握手必须是 148 字节");
            assert_eq!(bytes, &initiation.to_vec(), "裸握手字节必须原样上交");
            assert_eq!(*source, a_socket.local_addr().expect("取对端地址"));
            assert_eq!(event.severity(), None, "握手报文不是错误");
            assert!(!event.is_fatal(), "握手报文不致命");
        }
        other => panic!("裸握手必须以 Handshake 事件上交，实际 {other:?}"),
    }

    let outcome = tokio::time::timeout(TIMEOUT, handle.stop())
        .await
        .expect("循环必须在超时内退出");
    assert!(matches!(
        outcome,
        lengsuo_tunnel::udp::LoopOutcome::Cancelled
    ));
}

// ------------------------------------------- 3. 跨栈字节等价性（移动端 vs PC 端）

/// 跨栈等价性：移动端（`lengsuo-link-core`）与 PC 端（`lengsuo-tunnel`）
/// 产出的裸握手字节，在**墙钟依赖区段之外**逐字节相同。
///
/// ⛔ 两侧的 `local_index` 必须**显式对齐**：移动端由参数传，PC 端靠
/// `AssemblyConfig::with_local_index` 钉住，否则默认从 seed 派生 ⇒ 字节不同。
#[test]
fn bare_handshake_bytes_are_identical_across_stacks() {
    // ---- 发起方：initiation ----
    let mut mobile = mobile_session(SessionRole::Initiator);
    let mobile_initiation = mobile
        .create_initiation(INITIATOR_SEED, INITIATOR_INDEX, Instant::now())
        .expect("移动端 initiation 可产出");

    let assembly = pc_initiator();
    let mut handshake = InitiatorHandshake::new(&assembly, INITIATOR_SEED).expect("握手上下文可建");
    let pc_initiation = handshake
        .create_initiation(INITIATOR_SEED)
        .expect("PC 端 initiation 可产出");

    assert_eq!(mobile_initiation.len(), 148, "initiation 必须是 148 字节");
    assert_eq!(pc_initiation.len(), 148, "initiation 必须是 148 字节");
    assert_eq!(
        zeroed(&mobile_initiation, INITIATION_VOLATILE),
        zeroed(&pc_initiation, INITIATION_VOLATILE),
        "两侧的 initiation 在墙钟区段之外必须逐字节相同"
    );

    // ---- 响应方：response ----
    // 两侧消费**同一份** initiation 字节（PC 端那份），保证输入完全一致。
    let mut mobile_responder = mobile_session(SessionRole::Responder);
    mobile_responder
        .consume_initiation(&pc_initiation, Instant::now())
        .expect("移动端必须接受该 initiation");
    let mobile_response = mobile_responder
        .create_response(RESPONDER_SEED, RESPONDER_INDEX, Instant::now())
        .expect("移动端 response 可产出");

    let responder = Assembly::new(
        AssemblyConfig::new(Role::Responder, RESPONDER_SECRET, INITIATOR_PUBLIC)
            .with_local_index(RESPONDER_INDEX),
    )
    .expect("响应方装配层可建");
    let mut responder_hs = lengsuo_tunnel::assembly::ResponderHandshake::new(&responder)
        .expect("响应方握手上下文可建");
    responder_hs
        .consume_initiation(&pc_initiation)
        .expect("PC 端必须接受该 initiation");
    let (pc_response, _keys) = responder_hs
        .create_response(RESPONDER_SEED, RESPONDER_INDEX)
        .expect("PC 端 response 可产出");

    assert_eq!(mobile_response.len(), 92, "response 必须是 92 字节");
    assert_eq!(pc_response.len(), 92, "response 必须是 92 字节");
    assert_eq!(
        zeroed(&mobile_response, RESPONSE_VOLATILE),
        zeroed(&pc_response, RESPONSE_VOLATILE),
        "两侧的 response 在墙钟区段之外必须逐字节相同"
    );
}
