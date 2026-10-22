//! 装配层端到端用例：握手 → 密钥落地 → 数据往返 → 漫游 → keepalive。
//!
//! 覆盖任务书四·2 的六项（用例名里含关键词，便于机器 grep）：
//!
//! 1. `initiator_responder_handshake_completes` —— 握手成功并落到会话密钥；
//! 2. `handshake_failure_is_reported` —— 握手失败**显式报错**，**不**回退明文；
//! 3. `data_round_trip_through_assembly` —— 装配层收发数据往返；
//! 4. `roam_updates_peer_endpoint` —— 漫游更新 endpoint；
//! 5. `failed_auth_does_not_update_endpoint` —— 认证失败**不**更新 endpoint；
//! 6. `keepalive_starts_only_after_session_ready` —— 会话未就绪不发 keepalive。
//!
//! 纪律：每个异步用例都带硬超时，不许挂死。
//!
//! ⛔ **假凭据**：本文件的静态私钥/公钥是**固定的测试夹具**，不是任何真实凭据。

// 用例按主题拆到 `tests/assembly_roundtrip/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。
// 常量与 helper 被多个子文件共用，也一并留在本入口文件。

use std::net::SocketAddr;
use std::time::Duration;

use lengsuo_link_core::frame::{Frame, FrameType, MAX_FRAME_LEN};
use lengsuo_tunnel::assembly::{
    Assembly, AssemblyConfig, AssemblyError, AssemblyEvent, HandshakeCodec, InitiatorHandshake,
    KeepaliveDriver, ResponderHandshake, Role, SessionKeys,
};
use lengsuo_tunnel::udp::{KeepaliveConfig, UdpEndpoint};

/// 异步用例的硬超时。
const TIMEOUT: Duration = Duration::from_secs(5);
/// 「确认没有收到」用的短超时。
const QUIET: Duration = Duration::from_millis(300);

// ---------------------------------------------------------------- 测试夹具

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

/// 本轮临时密钥种子（确定性 ⇒ 可复现）。
const SEED: [u8; 32] = [0xAA; 32];
/// 响应方的临时密钥种子。
const RESPONDER_SEED: [u8; 32] = [0xBB; 32];
/// 响应方本轮 index。
const RESPONDER_INDEX: u32 = 0x2026_1234;

/// 发起方装配层配置。
fn initiator_config() -> AssemblyConfig {
    AssemblyConfig::new(Role::Initiator, INITIATOR_SECRET, RESPONDER_PUBLIC)
}

/// 响应方装配层配置。
fn responder_config() -> AssemblyConfig {
    AssemblyConfig::new(Role::Responder, RESPONDER_SECRET, INITIATOR_PUBLIC)
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

/// 跑完一整轮握手，把两端的会话密钥都落地。
///
/// 这是本文件的核心夹具：**真的走 UDP**（不是自环），所以它同时验证
/// 「裸握手报文 → 发 → 收 → 剥壳 → 落地密钥」整条链路。
///
/// ⚠️ 握手报文**不套 L3 帧头**（契约：initiation 148B / response 92B），
/// 所以收发都走 `send_raw` / `recv_raw`（见 `docs/spec/01-session-flow.md` §4）。
///
/// 返回两端装配层 + 两端的会话密钥（供断言 index 与密钥的镜像关系）。
async fn handshake_over_udp() -> (Assembly, Assembly, SessionKeys, SessionKeys) {
    let (a_socket, b_socket) = pair().await;
    let mut initiator = Assembly::new(initiator_config()).expect("发起方装配层可建");
    let mut responder = Assembly::new(responder_config()).expect("响应方装配层可建");

    // ① 发起方构造 initiation，**裸报文**发出。
    let mut initiator_hs = InitiatorHandshake::new(&initiator, SEED).expect("发起方握手上下文可建");
    let initiation = initiator_hs
        .create_initiation(SEED)
        .expect("initiation 可构造");
    let payload = HandshakeCodec::encode(&initiation).expect("initiation 是合法的裸握手");
    a_socket
        .send_raw(payload)
        .await
        .expect("initiation 应当发出");

    // ② 响应方收**裸数据报** → 剥壳 → 造 response → 落地密钥 → 发出。
    let mut buf = buffer();
    let (len, _source) = tokio::time::timeout(TIMEOUT, b_socket.recv_raw(&mut buf))
        .await
        .expect("响应方必须在超时内收到 initiation")
        .expect("initiation 必须是一个裸数据报");
    let payload = HandshakeCodec::decode(&buf[..len]).expect("initiation 是合法的裸握手");
    let mut responder_hs = ResponderHandshake::new(&responder).expect("响应方握手上下文可建");
    responder_hs
        .consume_initiation(payload)
        .expect("initiation 必须被接受");
    let (response, responder_keys) = responder_hs
        .create_response(RESPONDER_SEED, RESPONDER_INDEX)
        .expect("response 可构造");
    responder
        .install_keys(&responder_keys)
        .expect("响应方密钥应当能落地");
    let payload = HandshakeCodec::encode(&response).expect("response 是合法的裸握手");
    b_socket.send_raw(payload).await.expect("response 应当发出");

    // ③ 发起方收 response → 认证 → 落地密钥。
    let mut buf = buffer();
    let (len, _source) = tokio::time::timeout(TIMEOUT, a_socket.recv_raw(&mut buf))
        .await
        .expect("发起方必须在超时内收到 response")
        .expect("response 必须是一个裸数据报");
    let payload = HandshakeCodec::decode(&buf[..len]).expect("response 是合法的裸握手");
    let initiator_keys = initiator_hs
        .consume_response(payload)
        .expect("response 必须通过认证");
    initiator
        .install_keys(&initiator_keys)
        .expect("发起方密钥应当能落地");

    (initiator, responder, initiator_keys, responder_keys)
}

// ------------------------------------------------------------ 主题分组用例

include!("assembly_roundtrip/handshake.rs");
include!("assembly_roundtrip/data_plane.rs");
include!("assembly_roundtrip/endpoint.rs");
include!("assembly_roundtrip/lifecycle.rs");
