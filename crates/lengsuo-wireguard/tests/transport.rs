//! `transport` 的封装/解封测试：全部使用假密钥与假载荷，不代表任何真实凭据。
//! 只证明本 crate 内部 seal ⇄ `wire::parse` ⇄ open 的自洽与 fail-closed 语义，
//! **不证明与任何真实 WireGuard 对端互通**（握手与密钥协商未实现）。
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use lengsuo_wireguard::replay::Error as ReplayError;
use lengsuo_wireguard::transport::{
    key_len, Decrypted, Error, Receiver, Sender, TransportKey, DEFAULT_MAX_COUNTER, MAX_PACKET_LEN,
    MAX_PAYLOAD_LEN,
};
use lengsuo_wireguard::wire::{parse, Message, TRANSPORT_MIN_LEN};

/// 假会话密钥（固定模式字节，仅测试用）。
const KEY_A: [u8; 32] = [0xA1; 32];
/// 另一把假密钥，用于“错误密钥”测试。
const KEY_B: [u8; 32] = [0xB2; 32];
const RECEIVER_ID: u32 = 0xDE_AD_BE_EF;
/// 非 0xFF 的递增字节串，便于逐字节定位错位。
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|offset| (offset % 233) as u8).collect()
}

fn key_a() -> TransportKey {
    TransportKey::new(&KEY_A).expect("32 字节假密钥")
}

fn sender() -> Sender {
    Sender::new(key_a(), RECEIVER_ID, 0)
}

fn receiver() -> Receiver {
    Receiver::new(key_a(), RECEIVER_ID, DEFAULT_MAX_COUNTER)
}

/// 独立算一遍参考 nonce 布局（4 零 + LE64 计数器）的密文，用于钉住格式。
fn reference_ciphertext(counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    ChaCha20Poly1305::new_from_slice(&KEY_A)
        .expect("假密钥长度已校验")
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("假数据封装不应失败")
}

/// 密钥字节的两种常见泄漏形态：数组 Debug 与 hex。
fn leak_forms(key: &[u8]) -> Vec<String> {
    vec![
        format!("{key:?}"),
        key.iter().map(|byte| format!("{byte:02x}")).collect(),
        key.iter().map(|byte| format!("{byte:02X}")).collect(),
    ]
}

#[test]
fn seal_then_wire_parse_roundtrip_byte_exact() {
    let plaintext = payload(100);
    let packet = sender().seal(&plaintext).expect("legal seal");
    // 头部逐字节：类型 4 LE、接收者 LE、计数器 LE。
    assert_eq!(&packet[..4], &4u32.to_le_bytes());
    assert_eq!(&packet[4..8], &RECEIVER_ID.to_le_bytes());
    assert_eq!(&packet[8..16], &0u64.to_le_bytes());
    assert_eq!(packet.len(), 16 + 100 + 16);

    let Message::Transport(message) = parse(&packet).expect("本仓解析器接受自己封的包")
    else {
        panic!("期望 Transport，实际 {:?}", parse(&packet));
    };
    assert_eq!(message.receiver, RECEIVER_ID);
    assert_eq!(message.counter, 0);
    // 密文正文与独立参考实现逐字节一致：证明 nonce 布局与无 AAD 语义。
    assert_eq!(message.encrypted, reference_ciphertext(0, &plaintext));
    assert!(
        core::ptr::eq(message.encrypted, &packet[16..]),
        "密文应零拷贝借用"
    );

    let decrypted = receiver().open(&packet).expect("legal open");
    assert_eq!(decrypted.plaintext, plaintext);
    assert_eq!(decrypted.counter, 0);
    assert_eq!(decrypted.receiver, RECEIVER_ID);
}

#[test]
fn counter_increments_monotonically_across_seals() {
    let mut sender = sender();
    let mut open = receiver();
    let mut packets = Vec::new();
    for expected in 0..5u64 {
        assert_eq!(sender.next_counter(), expected);
        let packet = sender.seal(&payload(16 + expected as usize)).expect("seal");
        assert_eq!(&packet[8..16], &expected.to_le_bytes());
        packets.push(packet);
    }
    assert_eq!(sender.next_counter(), 5);
    for (expected, packet) in packets.iter().enumerate() {
        let decrypted = open.open(packet).expect("按序解封");
        assert_eq!(decrypted.counter, expected as u64);
    }
    assert_eq!(open.highest(), Some(4));
}

#[test]
fn zero_length_keepalive_is_legal() {
    let mut sender = sender();
    let packet = sender.keepalive().expect("零长载荷 keepalive 合法");
    assert_eq!(packet.len(), TRANSPORT_MIN_LEN, "keepalive = 头部 + 标签");
    let Message::Transport(message) = parse(&packet).expect("结构可解析") else {
        panic!("期望 Transport");
    };
    assert_eq!(message.encrypted.len(), 16);
    let decrypted = receiver().open(&packet).expect("keepalive 解封");
    assert!(decrypted.plaintext.is_empty());
    assert_eq!(decrypted.counter, 0);
    // seal(&[]) 与 keepalive() 等价（同密钥同计数器 => 同报文）。
    let mut explicit = Sender::new(key_a(), RECEIVER_ID, 0);
    let mut again = Sender::new(key_a(), RECEIVER_ID, 0);
    assert_eq!(
        explicit.seal(&[]).expect("explicit empty seal"),
        again.keepalive().expect("keepalive again")
    );
}

#[test]
fn oversized_payload_rejected_before_write_no_half_packet() {
    assert_eq!(MAX_PACKET_LEN, 1420);
    assert_eq!(MAX_PAYLOAD_LEN, 1388);
    let mut sender = sender();
    // 上限内：整包正好 1420 字节。
    let ok = sender
        .seal(&payload(MAX_PAYLOAD_LEN))
        .expect("1420 整包合法");
    assert_eq!(ok.len(), MAX_PACKET_LEN);
    assert_eq!(sender.next_counter(), 1);
    // 超限：写入前拒绝，计数器不消耗、上下文不 poison、不产出半包。
    let error = sender
        .seal(&payload(MAX_PAYLOAD_LEN + 1))
        .expect_err("1389 字节载荷必须拒绝");
    assert_eq!(
        error,
        Error::TooLong {
            actual: MAX_PACKET_LEN + 1,
            limit: MAX_PACKET_LEN
        }
    );
    assert_eq!(sender.next_counter(), 1, "超限不得消耗计数器");
    assert!(!sender.is_poisoned(), "长度拒绝不是密钥失同步");
    assert_eq!(
        receiver().open(&ok).expect("回封回解").plaintext,
        payload(MAX_PAYLOAD_LEN)
    );
    // 解封侧同样拒绝超限整包（先于结构与认证）。
    let mut oversize = ok.clone();
    oversize.extend_from_slice(&[0u8; 8]);
    assert_eq!(
        receiver().open(&oversize).expect_err("超长整包"),
        Error::TooLong {
            actual: MAX_PACKET_LEN + 8,
            limit: MAX_PACKET_LEN
        }
    );
}

#[test]
fn wrong_key_fails_closed_and_poisons() {
    let packet = sender().seal(&payload(64)).expect("seal");
    let mut wrong = Receiver::new(
        TransportKey::new(&KEY_B).expect("假密钥 B"),
        RECEIVER_ID,
        DEFAULT_MAX_COUNTER,
    );
    assert_eq!(
        wrong.open(&packet).expect_err("错误密钥"),
        Error::AuthFailed
    );
    // 永久 poison：即便之后拿到正确密钥的包也不再解密，绝不回退明文。
    assert!(wrong.is_poisoned());
    let good = receiver().open(&packet).expect("正确密钥仍可解");
    assert_eq!(
        wrong
            .open(&receiver_seal_one())
            .expect_err("poison 后拒绝解封"),
        Error::Poisoned
    );
    // poison 后窗口未被污染：认证失败不推进重放窗口。
    assert_eq!(wrong.highest(), None);
    assert_eq!(good.plaintext, payload(64));
}

fn receiver_seal_one() -> Vec<u8> {
    sender().seal(&payload(8)).expect("seal")
}

#[test]
fn tampered_tag_rejected_and_poisons() {
    let mut packet = sender().seal(&payload(48)).expect("seal");
    // 只翻转认证标签的最后一字节（tag = packet 尾部 16 字节）。
    let last = packet.len() - 1;
    packet[last] ^= 0x01;
    let mut open = receiver();
    assert_eq!(open.open(&packet).expect_err("标签篡改"), Error::AuthFailed);
    assert!(open.is_poisoned());
    assert_eq!(
        open.open(&packet).expect_err("poison 后仍拒绝"),
        Error::Poisoned
    );
    // 密文正文篡改同样认证失败（另起上下文）。
    let mut body = sender().seal(&payload(48)).expect("seal");
    body[20] ^= 0xFF;
    assert_eq!(
        receiver().open(&body).expect_err("密文篡改"),
        Error::AuthFailed
    );
}

#[test]
fn replay_and_out_of_order_counters_rejected() {
    // 先封好一串报文，再按任意顺序投递，模拟乱序到达。
    let mut sender = Sender::new(key_a(), RECEIVER_ID, 0);
    let mut packets = Vec::new();
    for _ in 0..6 {
        packets.push(sender.seal(&payload(8)).expect("seal"));
    }
    let mut open = receiver();
    // 乱序窗口内可收：先收 5，再收 3。
    assert_eq!(open.open(&packets[5]).expect("首包起窗").counter, 5);
    assert_eq!(open.open(&packets[3]).expect("窗口内乱序可收").counter, 3);
    // 重复计数器：无论是否乱序都必须拒绝，且不 poison。
    assert_eq!(
        open.open(&packets[3]).expect_err("重复计数器"),
        Error::Replay(ReplayError::Duplicate { counter: 3 })
    );
    assert_eq!(
        open.open(&packets[5]).expect_err("重复最高计数器"),
        Error::Replay(ReplayError::Duplicate { counter: 5 })
    );
    assert!(!open.is_poisoned(), "重放只是丢包");
    // 落在 8192 位窗口之外的旧包：先收到 10000，再投 0。
    let mut far = Sender::new(key_a(), RECEIVER_ID, 10_000);
    let far_packet = far.seal(&payload(8)).expect("high counter seal");
    assert_eq!(
        open.open(&far_packet).expect("跨度重新起窗").counter,
        10_000
    );
    assert_eq!(
        open.open(&packets[0]).expect_err("计数器 0 已在新窗口之外"),
        Error::Replay(ReplayError::TooOld {
            counter: 0,
            highest: 10_000
        })
    );
}

#[test]
fn counter_above_injected_max_rejected_without_poison() {
    let mut sender = Sender::new(key_a(), RECEIVER_ID, 7);
    let packet = sender.seal(&payload(8)).expect("seal");
    let mut limited = Receiver::new(key_a(), RECEIVER_ID, 5);
    assert_eq!(
        limited.open(&packet).expect_err("超过注入上限"),
        Error::Replay(ReplayError::ExceedsMaxCounter {
            counter: 7,
            max_counter: 5
        })
    );
    assert!(!limited.is_poisoned());
    assert_eq!(limited.highest(), None, "拒绝不得改动窗口");
}

#[test]
fn counter_wraparound_is_poisoned_not_reused() {
    let mut sender = Sender::new(key_a(), RECEIVER_ID, u64::MAX - 1);
    let first = sender.seal(&payload(8)).expect("MAX-1 可封");
    assert_eq!(&first[8..16], &(u64::MAX - 1).to_le_bytes());
    let second = sender.seal(&payload(8)).expect("MAX 可封");
    assert_eq!(&second[8..16], &u64::MAX.to_le_bytes());
    // 回绕点之后：永久 poison，绝不重新从 0 计数，也不产出任何报文。
    assert!(sender.is_poisoned());
    assert_eq!(
        sender.seal(&payload(8)).expect_err("计数器用尽后拒绝"),
        Error::CounterExhausted { counter: u64::MAX }
    );
    assert_eq!(
        sender.keepalive().expect_err("keepalive 同样拒绝"),
        Error::CounterExhausted { counter: u64::MAX }
    );
    // 接收侧按共享窗口判定：MAX 之后的 0 落在窗口之外，不会重放成功。
    let mut open = receiver();
    assert_eq!(open.open(&second).expect("MAX 解封").counter, u64::MAX);
    let zero = sender_at(0);
    assert!(matches!(
        open.open(&zero).expect_err("回绕后的 0 必须拒绝"),
        Error::Replay(_)
    ));
}

fn sender_at(counter: u64) -> Vec<u8> {
    Sender::new(key_a(), RECEIVER_ID, counter)
        .seal(&payload(8))
        .expect("seal")
}

#[test]
fn wrong_receiver_and_non_transport_rejected() {
    let packet = sender().seal(&payload(16)).expect("seal");
    let mut other = Receiver::new(key_a(), RECEIVER_ID ^ 1, u64::MAX);
    let error = other.open(&packet).expect_err("接收者标识不匹配");
    assert!(matches!(error, Error::ReceiverMismatch { .. }));
    assert!(!other.is_poisoned(), "误投包不代表本端密钥失同步");
    // 非运输类型：握手三类的长度是固定的，用 148 字节的类型 1 报文测试。
    let mut init = vec![0u8; 148];
    init[..4].copy_from_slice(&1u32.to_le_bytes());
    assert!(matches!(
        receiver().open(&init).expect_err("类型 1 不是运输报文"),
        Error::NotTransport(_)
    ));
    // 结构非法（短于 32 字节）沿用 wire::Error，且明文永不返回。
    assert!(matches!(
        receiver()
            .open(&[4, 0, 0, 0, 0, 0, 0, 0])
            .expect_err("短包"),
        Error::Wire(_)
    ));
}

#[test]
fn key_and_plaintext_never_reach_debug_or_errors() {
    let secret = b"INNER-IP-PACKET-MUST-NOT-BE-LOGGED";
    let packet = sender().seal(secret).expect("seal");
    let mut wrong = Receiver::new(
        TransportKey::new(&KEY_B).expect("假密钥 B"),
        RECEIVER_ID,
        DEFAULT_MAX_COUNTER,
    );
    let open_error = wrong.open(&packet).expect_err("错误密钥");
    let mut long_sender = sender();
    long_sender.seal(&payload(MAX_PAYLOAD_LEN)).expect("ok");
    let too_long = long_sender
        .seal(&payload(MAX_PAYLOAD_LEN + 1))
        .expect_err("超限");
    let key_error = TransportKey::new(&[0xC3; 16]).expect_err("密钥长度不对");
    let wrap = {
        let mut exhausted = Sender::new(key_a(), RECEIVER_ID, u64::MAX);
        exhausted.seal(secret).expect("MAX 封包");
        exhausted.seal(secret).expect_err("用尽")
    };

    let mut rendered = Vec::new();
    // 所有错误路径的 Display 与 Debug。
    for error in [open_error, too_long, key_error, wrap] {
        rendered.push(format!("{error}"));
        rendered.push(format!("{error:?}"));
    }
    // 所有面向日志的结构体 Debug。
    let decrypted: Decrypted = Receiver::new(key_a(), RECEIVER_ID, DEFAULT_MAX_COUNTER)
        .open(&packet)
        .expect("解封");
    rendered.push(format!("{decrypted:?}"));
    rendered.push(format!("{:?}", key_a()));
    rendered.push(format!("{:?}", TransportKey::new(&KEY_B).expect("key b")));
    rendered.push(format!("{:?}", sender()));
    rendered.push(format!("{:?}", receiver()));
    rendered.push(format!(
        "{:?}",
        Decrypted {
            counter: 1,
            receiver: RECEIVER_ID,
            plaintext: secret.to_vec(),
        }
    ));

    let leaks = leak_forms(&KEY_A)
        .into_iter()
        .chain(leak_forms(&KEY_B))
        .chain(leak_forms(&[0xC3; 16]))
        .collect::<Vec<_>>();
    for text in &rendered {
        for leak in &leaks {
            assert!(!text.contains(leak.as_str()), "密钥泄漏到日志：{text}");
        }
        assert!(!text.contains("INNER-IP-PACKET"), "明文泄漏：{text}");
        assert!(
            !text.contains(&format!("{:?}", secret.as_slice())),
            "明文字节泄漏：{text}"
        );
    }
    // 明文长度可以出现，但不得带出内容。
    assert!(rendered
        .iter()
        .any(|text| text.contains("plaintext_len") || text.contains("Decrypted")));
    assert_eq!(key_len(), 32);
}

/// 同步测试用 `tokio::time::timeout` 兜住，防止未来接入异步 I/O 时挂死无人察觉。
#[tokio::test]
async fn seal_open_under_timeout_stays_bounded() {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(|| {
            let mut sender = sender();
            let mut open = receiver();
            let mut checked = 0usize;
            for index in 0..64u64 {
                let packet = sender.seal(&payload(8 + index as usize)).expect("seal");
                let decrypted = open.open(&packet).expect("open");
                assert_eq!(decrypted.counter, index);
                assert_eq!(decrypted.plaintext, payload(8 + index as usize));
                checked += 1;
            }
            checked
        }),
    )
    .await
    .expect("timeout 内完成");
    assert_eq!(result.expect("worker 未 panic"), 64);
}
