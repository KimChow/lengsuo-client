// ② fail-closed 路径：超限、错密钥、篡改、重放、计数器上限与回绕、误投。
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
