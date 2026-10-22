// ① 正常路径：封包 ⇄ 解析 ⇄ 解封的字节级一致性、计数器单调性、零长 keepalive。
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
