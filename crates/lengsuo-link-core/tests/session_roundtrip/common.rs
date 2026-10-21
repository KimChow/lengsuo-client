// 共享夹具：假密钥材料与会话/握手/封解帧助手。
//
// 本文件由 `tests/session_roundtrip.rs` 用 `include!` 文本并入同一模块；
// `use` 全部写在入口文件。

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
/// 第三方静态公钥（仓外 Python `cryptography` 的 X25519 独立算出）。
const OTHER_PUBLIC: [u8; 32] = [
    0x7b, 0x0d, 0x47, 0xd9, 0x34, 0x27, 0xf8, 0x31, 0x11, 0x60, 0x78, 0x1c, 0x7c, 0x73, 0x3f, 0xd8,
    0x9f, 0x88, 0x97, 0x0a, 0xef, 0x49, 0x0d, 0x8a, 0xa0, 0xee, 0x19, 0xa4, 0xcb, 0x8a, 0x1b, 0x14,
];

/// 两轮握手之间的最小时间间隔（须大于会话层的洪水窗口 20ms）。
const ROUND_GAP: Duration = Duration::from_millis(50);

/// 推进到「下一轮」可用的时刻。
///
/// ⚠️ 为什么必须等：`lengsuo-wireguard` 的握手时间戳来自 `tai64n_now()`
/// （**系统时钟**），纳秒部分被掩到 ~16.78ms 粒度（`subsec_nanos & !0x00ff_ffff`）。
/// 参考实现的重放检查要求「时间戳严格晚于上一次」，所以**两轮握手必须跨过一个
/// TAI64N 刻度**，否则第二轮会被判重放（与参考实现行为一致，不是本卡的缺陷）。
/// 同时还要跨过会话层的**洪水窗口**（20ms，注入的是单调 `Instant`）——两个窗口
/// 是**独立的时钟源**（墙钟 vs 单调钟），必须**都**满足。
fn advance_round(previous: Instant) -> Instant {
    let before = lengsuo_wireguard::handshake::tai64n_now();
    loop {
        std::thread::sleep(Duration::from_millis(2));
        let now = Instant::now();
        let tai_advanced = lengsuo_wireguard::handshake::tai64n_now() != before;
        let monotonic = now
            .checked_duration_since(previous)
            .is_some_and(|gap| gap >= ROUND_GAP);
        if tai_advanced && monotonic {
            return now;
        }
    }
}

/// 构造（发起方, 响应方）一对**未握手**的会话。
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

/// 在**同一对会话对象**上跑完一轮握手。
///
/// `index_base` 是本轮双方 index 的基址：每轮用**不同**的 index（index 与 key
/// epoch 一一对应，复用会让对端把新密钥的包当成旧 epoch 的包）。
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
    assert_eq!(initiation.len(), 148, "initiation 固定 148 字节");
    responder
        .consume_initiation(&initiation, now)
        .expect("initiation 可剥壳");
    let response = responder
        .create_response([seed_base.wrapping_add(1); 32], index_base + 1, now)
        .expect("response 可生成");
    assert_eq!(response.len(), 92, "response 固定 92 字节");
    initiator
        .consume_response(&response, now)
        .expect("response 可消费");
}

/// 封一帧数据并取回线上字节。
fn seal(session: &mut Session, seq: u64, plain: &[u8]) -> Vec<u8> {
    session
        .seal_frame(FrameType::Data, seq, plain)
        .expect("封帧成功")
}

/// 解一帧并取回明文。
fn open(session: &mut Session, wire: &[u8]) -> Vec<u8> {
    session.open_frame(wire).expect("解帧成功").plaintext
}
