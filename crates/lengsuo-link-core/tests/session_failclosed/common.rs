// 共享夹具：假密钥材料、已建立会话对、封帧/篡改助手。
//
// 本文件由 `tests/session_failclosed.rs` 用 `include!` 文本并入同一模块；
// `use` 全部写在入口文件。

/// 发起方静态私钥（测试专用）。
const INITIATOR_STATIC: [u8; 32] = [0x11; 32];
/// 响应方静态私钥（测试专用）。
const RESPONDER_STATIC: [u8; 32] = [0x22; 32];
/// 「另一条链路」发起方的静态私钥（测试专用）。
const OTHER_INITIATOR_STATIC: [u8; 32] = [0x99; 32];
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
/// 「另一条链路」发起方的静态公钥（私钥 = 0x99 × 32；仓外独立算出）。
const OTHER_INITIATOR_PUBLIC: [u8; 32] = [
    0xba, 0x19, 0x38, 0x36, 0xcf, 0xf1, 0xf4, 0xe8, 0x66, 0xc1, 0x39, 0x71, 0x5d, 0x30, 0x64, 0x08,
    0xd2, 0x6a, 0x76, 0xf7, 0x6d, 0x63, 0x8a, 0x39, 0xaf, 0xc1, 0x00, 0x10, 0x84, 0xd2, 0x54, 0x11,
];
/// 明显可辨的「错误密钥」字节模式——用于断言它**不出现在**任何输出里。
const POISON_KEY: [u8; 32] = [0x5A; 32];

/// 构造（发起方, 响应方）一对**已建立**的会话。
fn established_pair() -> (Session, Session) {
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
    let (mut initiator, mut responder) = (initiator, responder);
    let now = Instant::now();
    let initiation = initiator
        .create_initiation([0xA1; 32], 10, now)
        .expect("initiation 可生成");
    responder
        .consume_initiation(&initiation, now)
        .expect("initiation 可剥壳");
    let response = responder
        .create_response([0xB2; 32], 11, now)
        .expect("response 可生成");
    initiator
        .consume_response(&response, now)
        .expect("response 可消费");
    (initiator, responder)
}

/// 封一帧数据并取回线上字节。
fn seal(session: &mut Session, seq: u64, plain: &[u8]) -> Vec<u8> {
    session
        .seal_frame(FrameType::Data, seq, plain)
        .expect("封帧成功")
}

/// 篡改密文末字节（制造 AEAD 认证失败）。
fn corrupt(wire: &[u8]) -> Vec<u8> {
    let mut out = wire.to_vec();
    let last = out.len() - 1;
    out[last] ^= 0x01;
    out
}
