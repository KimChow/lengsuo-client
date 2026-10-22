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
/// 「握手报文装帧 → 发 → 收 → 剥壳 → 落地密钥」整条链路。
///
/// 返回两端装配层 + 两端的会话密钥（供断言 index 与密钥的镜像关系）。
async fn handshake_over_udp() -> (Assembly, Assembly, SessionKeys, SessionKeys) {
    let (a_socket, b_socket) = pair().await;
    let mut initiator = Assembly::new(initiator_config()).expect("发起方装配层可建");
    let mut responder = Assembly::new(responder_config()).expect("响应方装配层可建");

    // ① 发起方构造 initiation，装进 L3 帧，发出。
    let mut initiator_hs = InitiatorHandshake::new(&initiator, SEED).expect("发起方握手上下文可建");
    let initiation = initiator_hs
        .create_initiation(SEED)
        .expect("initiation 可构造");
    let frame = HandshakeCodec::encode(1, &initiation).expect("initiation 可装帧");
    a_socket
        .send_frame(&frame)
        .await
        .expect("initiation 应当发出");

    // ② 响应方收帧 → 剥壳 → 造 response → 落地密钥 → 发出。
    let mut buf = buffer();
    let got = tokio::time::timeout(TIMEOUT, b_socket.recv_frame(&mut buf))
        .await
        .expect("响应方必须在超时内收到 initiation")
        .expect("initiation 必须是一个合法帧");
    let payload = HandshakeCodec::decode(&got).expect("initiation 装在控制帧里");
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
    let frame = HandshakeCodec::encode(2, &response).expect("response 可装帧");
    b_socket
        .send_frame(&frame)
        .await
        .expect("response 应当发出");

    // ③ 发起方收 response → 认证 → 落地密钥。
    let mut buf = buffer();
    let got = tokio::time::timeout(TIMEOUT, a_socket.recv_frame(&mut buf))
        .await
        .expect("发起方必须在超时内收到 response")
        .expect("response 必须是一个合法帧");
    let payload = HandshakeCodec::decode(&got).expect("response 装在控制帧里");
    let initiator_keys = initiator_hs
        .consume_response(payload)
        .expect("response 必须通过认证");
    initiator
        .install_keys(&initiator_keys)
        .expect("发起方密钥应当能落地");

    (initiator, responder, initiator_keys, responder_keys)
}

// ------------------------------------------------------- 1. 握手成功并落地

#[tokio::test]
async fn initiator_responder_handshake_completes() {
    let (initiator, responder, initiator_keys, responder_keys) = handshake_over_udp().await;

    assert!(initiator.is_established(), "发起方会话必须已建立");
    assert!(responder.is_established(), "响应方会话必须已建立");

    // 发起方的 keypair **真的**落进了 Device 的 current 槽位
    // （对照参考 `BeginSymmetricSession` 的 initiator 分支：新 keypair 直接上位）。
    let initiator_key = initiator
        .device()
        .keypairs()
        .current()
        .expect("发起方的 current keypair 必须存在（密钥已落地）");
    assert_eq!(initiator_key.local_index, initiator_keys.local_index);
    assert_eq!(initiator_key.remote_index, initiator_keys.remote_index);

    // 响应方的 keypair 落在 **next** 槽位（对照参考的 responder 分支：新 keypair
    // 先进 next，等第一个用它的数据报文确认后才晋升）⇒ 此刻 current 仍为空。
    // ⛔ 这不是「没落地」：它等的是**对端的第一个数据报文**来确认。
    assert!(
        responder.device().keypairs().current().is_none(),
        "响应方在收到首个数据报文前，current 槽位应当仍为空（keypair 在 next）"
    );

    // 两侧的 index 必须**互为镜像**（发起方 send 的 receiver == 响应方的 local）。
    assert_eq!(
        initiator_keys.remote_index, responder_keys.local_index,
        "发起方写入的对端 index 必须等于响应方的本端 index"
    );
    assert_eq!(
        responder_keys.remote_index, initiator_keys.local_index,
        "响应方写入的对端 index 必须等于发起方的本端 index"
    );
    // 收发密钥必须**互为镜像**（发起方 send == 响应方 receive，反之亦然）。
    assert_eq!(
        initiator_keys.send, responder_keys.receive,
        "发起方发送密钥必须等于响应方接收密钥"
    );
    assert_eq!(
        initiator_keys.receive, responder_keys.send,
        "发起方接收密钥必须等于响应方发送密钥"
    );
}

// ------------------------------------------- 2. 握手失败显式报错（不回退明文）

#[tokio::test]
async fn handshake_failure_is_reported() {
    // ⛔ 用一个**从未握手成功**的装配层：失败之后它必须**仍然**未就绪。
    let mut initiator = Assembly::new(initiator_config()).expect("发起方装配层可建");
    let mut handshake = InitiatorHandshake::new(&initiator, SEED).expect("发起方握手上下文可建");
    handshake
        .create_initiation(SEED)
        .expect("initiation 可构造");

    // 一个**长度合法但 MAC1 全零**的 response ⇒ 认证必然失败。
    let mut broken = [0u8; 92];
    broken[..4].copy_from_slice(&2u32.to_le_bytes());
    broken[4..8].copy_from_slice(&RESPONDER_INDEX.to_le_bytes());
    broken[8..12].copy_from_slice(&handshake.local_index().to_le_bytes());

    let err = handshake
        .consume_response(&broken)
        .expect_err("被篡改的 response 必须被拒绝");
    match err {
        AssemblyError::HandshakeRejected { reason } => {
            assert!(
                !reason.is_empty(),
                "失败原因必须给出固定短语（不含报文内容）"
            );
            assert_eq!(reason, "响应报文认证失败", "失败原因必须可判定");
        }
        other => panic!("期望 HandshakeRejected，实际 {other:?}"),
    }

    // ⛔ **不回退明文**：会话**不得**因失败而变成「已建立」。
    assert!(
        !initiator.is_established(),
        "握手失败后不得把会话标成已建立（不回退明文）"
    );
    // 数据面必须**拒绝**收发（而不是放行明文）。
    let err = initiator
        .seal_frame(FrameType::Data, 1, b"plaintext-must-not-escape")
        .expect_err("会话未建立时必须拒绝封装");
    assert!(
        matches!(err, AssemblyError::SessionNotEstablished),
        "期望 SessionNotEstablished，实际 {err:?}"
    );
    let err = initiator
        .receive_frame(
            "203.0.113.5:1234".parse().expect("测试地址可解析"),
            Frame::new(FrameType::Data, 1, vec![0u8; 32]),
        )
        .expect_err("会话未建立时必须拒绝收包");
    assert!(
        matches!(err, AssemblyError::SessionNotEstablished),
        "期望 SessionNotEstablished，实际 {err:?}"
    );
}

// --------------------------------------------------- 3. 数据往返（装配层）

#[tokio::test]
async fn data_round_trip_through_assembly() {
    let (mut initiator, mut responder, _, _) = handshake_over_udp().await;
    let (a_socket, b_socket) = pair().await;

    let plain = b"assembly-round-trip-payload";
    let seq = 42u64;

    // 发起方封装 → 装帧 → 发出。
    let frame = initiator
        .seal_frame(FrameType::Data, seq, plain)
        .expect("应当能封装数据帧");
    let bytes = frame.encode().expect("帧应当能编码");
    a_socket.send_raw(&bytes).await.expect("数据帧应当发出");

    // 响应方收字节 → 装配层处理 → 拿到明文。
    let mut buf = buffer();
    let got = tokio::time::timeout(TIMEOUT, b_socket.recv_frame(&mut buf))
        .await
        .expect("响应方必须在超时内收到数据")
        .expect("数据必须是一个合法帧");
    let src = b_socket.local_addr().expect("取源地址");
    let event = responder
        .receive_frame(src, got)
        .expect("装配层应当能处理数据帧");
    match event {
        AssemblyEvent::Delivered {
            frame_type,
            seq: got_seq,
            plaintext_len,
            ..
        } => {
            assert_eq!(frame_type, FrameType::Data);
            assert_eq!(got_seq, seq, "帧序号必须原样传下去");
            assert_eq!(plaintext_len, plain.len(), "明文长度必须正确");
        }
        other => panic!("期望 Delivered，实际 {other:?}"),
    }

    // 响应方的 keypair 在收到这个报文时**晋升**为 current（对照参考
    // `ReceivedWithKeypair`）⇒ 现在它也能发。
    assert!(
        responder.device().keypairs().current().is_some(),
        "响应方收到首个数据报文后，keypair 应当晋升为 current"
    );

    // 反向：响应方回一帧。
    let frame = responder
        .seal_frame(FrameType::Data, seq + 1, b"reply-payload")
        .expect("响应方应当能封装");
    let bytes = frame.encode().expect("帧应当能编码");
    b_socket.send_raw(&bytes).await.expect("回帧应当发出");
    let mut buf = buffer();
    let got = tokio::time::timeout(TIMEOUT, a_socket.recv_frame(&mut buf))
        .await
        .expect("发起方必须在超时内收到回帧")
        .expect("回帧必须是一个合法帧");
    let src = a_socket.local_addr().expect("取源地址");
    let event = initiator
        .receive_frame(src, got)
        .expect("装配层应当能处理回帧");
    assert!(
        matches!(event, AssemblyEvent::Delivered { .. }),
        "反向也必须成功解密，实际 {event:?}"
    );
}

// --------------------------------------------------------- 4. 漫游更新 endpoint

#[tokio::test]
async fn roam_updates_peer_endpoint() {
    let (mut initiator, mut responder, _, _) = handshake_over_udp().await;

    // 首次：还没有 endpoint。
    assert!(
        responder.peer_endpoint().is_none(),
        "初始状态不得有 endpoint"
    );

    // 模拟一次**已认证**的收包（源地址 = 对端的新地址）。
    let new_src: SocketAddr = "203.0.113.9:40001".parse().expect("测试地址可解析");
    let frame = initiator
        .seal_frame(FrameType::Data, 1, b"roam-payload")
        .expect("应当能封装");
    let event = responder
        .receive_frame(new_src, frame)
        .expect("装配层应当能处理该帧");
    assert!(
        event.roamed(),
        "源地址变了 ⇒ 必须是漫游事件，实际 {event:?}"
    );
    assert_eq!(
        responder.peer_endpoint(),
        Some(new_src),
        "漫游后 peer endpoint 必须更新为新源地址"
    );

    // 同一地址再来一次 ⇒ **不再**漫游（幂等）。
    let frame = initiator
        .seal_frame(FrameType::Data, 2, b"same-addr-payload")
        .expect("应当能封装");
    let event = responder
        .receive_frame(new_src, frame)
        .expect("装配层应当能处理该帧");
    assert!(
        !event.roamed(),
        "地址未变 ⇒ 不得再判定为漫游，实际 {event:?}"
    );
    assert_eq!(
        responder.peer_endpoint(),
        Some(new_src),
        "endpoint 必须保持为同一个地址"
    );
}

// --------------------------------------------- 5. 认证失败不更新 endpoint

#[tokio::test]
async fn failed_auth_does_not_update_endpoint() {
    let (mut initiator, mut responder, _, _) = handshake_over_udp().await;

    // 先建立一个已知的 endpoint。
    let known: SocketAddr = "198.51.100.7:51820".parse().expect("测试地址可解析");
    responder
        .set_peer_endpoint(Some(known))
        .expect("设置 endpoint 应当成功");
    assert_eq!(responder.peer_endpoint(), Some(known));

    // 让响应方先收到一个数据报文（触发 next → current 晋升，它才能封装）。
    let warmup = initiator
        .seal_frame(FrameType::Data, 1, b"warmup-payload")
        .expect("应当能封装");
    responder
        .receive_frame(known, warmup)
        .expect("装配层应当能处理该帧");

    // 一个**认证失败**的报文（密文被篡改）⇒ 丢弃，⛔ **不**更新 endpoint。
    let mut frame = responder
        .seal_frame(FrameType::Data, 2, b"will-be-tampered")
        .expect("应当能封装");
    let last = frame.payload.len() - 1;
    frame.payload[last] ^= 0xFF;
    let forged: SocketAddr = "203.0.113.66:1234".parse().expect("测试地址可解析");

    let event = responder
        .receive_frame(forged, frame)
        .expect("认证失败的报文不该让装配层报错（只丢这一包）");
    assert!(
        matches!(event, AssemblyEvent::Dropped { .. }),
        "篡改后的报文必须被丢弃，实际 {event:?}"
    );
    assert!(!event.roamed(), "认证失败的报文不得判定为漫游");
    assert_eq!(
        responder.peer_endpoint(),
        Some(known),
        "⛔ 认证失败的报文绝不允许更新 endpoint"
    );
}

// ---------------------------------- 6. 会话未就绪不发 keepalive（就绪后才发）

#[tokio::test]
async fn keepalive_starts_only_after_session_ready() {
    let (a_socket, b_socket) = pair().await;

    // 会话**未就绪**：keepalive 任务**尚未启动** ⇒ 一个字节都不发。
    let mut driver = KeepaliveDriver::new(KeepaliveConfig {
        interval: Some(Duration::from_millis(50)),
    })
    .expect("keepalive 驱动可建");
    assert!(
        !driver.is_running(),
        "会话未就绪时 keepalive 任务不得已启动"
    );
    // 未 `activate` ⇒ 对端收不到任何东西。
    let mut buf = buffer();
    let quiet = tokio::time::timeout(QUIET, b_socket.recv_frame(&mut buf)).await;
    assert!(quiet.is_err(), "会话未就绪时不得发出任何 keepalive");

    // 会话**未就绪**时，装配层**拒绝**启动 keepalive。
    let mut assembly = Assembly::new(initiator_config()).expect("发起方装配层可建");
    let err = assembly
        .start_keepalive(&mut driver, a_socket.clone())
        .expect_err("会话未就绪时必须拒绝启动 keepalive");
    assert!(
        matches!(err, AssemblyError::SessionNotEstablished),
        "期望 SessionNotEstablished，实际 {err:?}"
    );
    assert!(
        !driver.is_running(),
        "拒绝之后 keepalive 任务仍然不得已启动"
    );

    // 会话**就绪** ⇒ 启动任务 ⇒ 对端开始收到 keepalive。
    let (mut initiator, _responder, _, _) = handshake_over_udp().await;
    initiator
        .start_keepalive(&mut driver, a_socket)
        .expect("就绪后 keepalive 应当能启动");
    assert!(driver.is_running(), "就绪后 keepalive 任务必须已启动");

    let mut buf = buffer();
    let got = tokio::time::timeout(TIMEOUT, b_socket.recv_frame(&mut buf))
        .await
        .expect("就绪后 keepalive 必须在超时内到达")
        .expect("应当收到一个合法帧");
    assert_eq!(
        got.frame_type,
        FrameType::Keepalive,
        "keepalive 帧类型必须正确"
    );
    assert!(got.payload.is_empty(), "keepalive 的载荷必须零长");

    tokio::time::timeout(TIMEOUT, driver.stop())
        .await
        .expect("keepalive 任务必须在超时内退出");
}

// ------------------------------------------------------- 附加：cookie 路径

#[tokio::test]
async fn mac_failure_is_reported_so_caller_can_issue_cookie_reply() {
    let responder = Assembly::new(responder_config()).expect("响应方装配层可建");
    let mut responder_hs = ResponderHandshake::new(&responder).expect("响应方握手上下文可建");

    // 一条**长度合法但 MAC1 不对**的 initiation。
    let mut broken = [0u8; 148];
    broken[..4].copy_from_slice(&1u32.to_le_bytes());
    broken[4..8].copy_from_slice(&7u32.to_le_bytes());

    let err = responder_hs
        .consume_initiation(&broken)
        .expect_err("MAC1 不符必须被拒绝");
    match err {
        AssemblyError::HandshakeRejected { reason } => {
            assert_eq!(reason, "MAC1 校验失败", "失败原因必须可判定");
        }
        other => panic!("期望 HandshakeRejected，实际 {other:?}"),
    }

    // ⛔ 失败**不得**直接丢弃：调用方据此签发 cookie reply（64 字节）。
    let reply = responder_hs
        .create_cookie_reply(&broken, b"203.0.113.1:51820", [0x44; 32], [0x55; 24])
        .expect("cookie reply 必须能签发");
    assert_eq!(reply.len(), 64, "cookie reply 必须是 64 字节");
    assert_eq!(
        &reply[..4],
        &3u32.to_le_bytes(),
        "cookie reply 的类型字段必须是 3"
    );
}

// ------------------------------------------------- 附加：角色错配被拒

#[tokio::test]
async fn wrong_role_operations_are_rejected() {
    let initiator = Assembly::new(initiator_config()).expect("发起方装配层可建");
    let err = ResponderHandshake::new(&initiator).expect_err("发起方不得当响应方用");
    assert!(
        matches!(err, AssemblyError::WrongRole { .. }),
        "期望 WrongRole，实际 {err:?}"
    );

    let responder = Assembly::new(responder_config()).expect("响应方装配层可建");
    let err = InitiatorHandshake::new(&responder, SEED).expect_err("响应方不得当发起方用");
    assert!(
        matches!(err, AssemblyError::WrongRole { .. }),
        "期望 WrongRole，实际 {err:?}"
    );
}

// --------------------------------------- 附加：零间隔 keepalive 被拒（busy loop）

#[tokio::test]
async fn zero_interval_keepalive_is_rejected() {
    let err = KeepaliveDriver::new(KeepaliveConfig {
        interval: Some(Duration::ZERO),
    })
    .expect_err("零间隔必须被拒绝（busy loop）");
    assert!(
        matches!(err, AssemblyError::KeepaliveDisabled(_)),
        "期望 KeepaliveDisabled，实际 {err:?}"
    );
}

// --------------------------------- 附加：会话未就绪时数据面拒绝收发

#[tokio::test]
async fn session_not_established_rejects_data_plane() {
    let mut initiator = Assembly::new(initiator_config()).expect("发起方装配层可建");
    assert!(!initiator.is_established());

    let err = initiator
        .seal_frame(FrameType::Data, 1, b"nope")
        .expect_err("会话未就绪必须拒绝封装");
    assert!(
        matches!(err, AssemblyError::SessionNotEstablished),
        "期望 SessionNotEstablished，实际 {err:?}"
    );

    let src: SocketAddr = "127.0.0.1:1".parse().expect("测试地址可解析");
    let frame = Frame::new(FrameType::Data, 1, vec![0u8; 32]);
    let err = initiator
        .receive_frame(src, frame)
        .expect_err("会话未就绪必须拒绝收包");
    assert!(
        matches!(err, AssemblyError::SessionNotEstablished),
        "期望 SessionNotEstablished，实际 {err:?}"
    );
}
