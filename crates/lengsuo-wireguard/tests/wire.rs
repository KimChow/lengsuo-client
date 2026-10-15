//! `wire::parse` 的固定字节、截断、保留位、长度、字节序与不泄漏测试。
//! 仅证明头部字段与长度检查，不证明 MAC、解密或任何对端互通。
mod support;
use lengsuo_wireguard::wire::{
    parse, Error, HandshakeKind, HandshakeMessage, Message, TransportMessage, COOKIE_LEN, INIT_LEN,
    RESPONSE_LEN, TRANSPORT_MIN_LEN,
};
use support::*;

/// 假接收者标识（TEST-NET 风格的文档用值，不是真实密钥材料）。
const RECEIVER: u32 = 0xDE_AD_BE_EF;
const COUNTER: u64 = 0x0123_4567_89AB_CDEF;

#[test]
fn init_exact_148_with_little_endian_type() {
    let packet = handshake_packet(1, INIT_LEN);
    assert_eq!(&packet[..4], &[1, 0, 0, 0]);
    assert_eq!(INIT_LEN, 148);
    match parse(&packet) {
        Ok(Message::Init(message)) => {
            assert_eq!(message.kind, HandshakeKind::Init);
            assert_eq!(message.kind.exact_len(), 148);
            // 只返回通过检查的原始借用字节，指针指向同一块内存。
            assert_eq!(message.unverified_bytes(), packet.as_slice());
            assert!(core::ptr::eq(message.unverified_bytes(), packet.as_slice()));
        }
        other => panic!("期望 Init，实际 {other:?}"),
    }
}

#[test]
fn response_exact_92_and_cookie_exact_64() {
    assert_eq!(RESPONSE_LEN, 92);
    assert_eq!(COOKIE_LEN, 64);
    let response = handshake_packet(2, RESPONSE_LEN);
    assert_eq!(&response[..4], &[2, 0, 0, 0]);
    let Message::Response(message) = parse(&response).expect("legal response") else {
        panic!("期望 Response");
    };
    assert_eq!(message.kind, HandshakeKind::Response);
    assert_eq!(message.kind.exact_len(), 92);

    let cookie = handshake_packet(3, COOKIE_LEN);
    assert_eq!(&cookie[..4], &[3, 0, 0, 0]);
    let Message::Cookie(message) = parse(&cookie).expect("legal cookie") else {
        panic!("期望 Cookie");
    };
    assert_eq!(message.kind, HandshakeKind::Cookie);
    assert_eq!(message.kind.exact_len(), 64);
}

#[test]
fn transport_header_fields_are_little_endian() {
    let packet = transport_packet(RECEIVER, COUNTER, 16);
    // 逐字节核对线上字节序，避免实现与断言同时写错。
    assert_eq!(&packet[4..8], &[0xEF, 0xBE, 0xAD, 0xDE]);
    assert_eq!(
        &packet[8..16],
        &[0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]
    );
    let Message::Transport(message) = parse(&packet).expect("legal transport") else {
        panic!("期望 Transport");
    };
    assert_eq!(message.receiver, RECEIVER);
    assert_eq!(message.counter, COUNTER);
    assert_eq!(message.encrypted, &packet[16..]);
    assert_eq!(message.encrypted.len(), 16);
    assert_eq!(parse(&packet).expect("stable").counter(), Some(COUNTER));
    // 大端读法会得到完全不同的值，说明本实现确实按小端解析。
    assert_ne!(
        message.counter,
        u64::from_be_bytes(packet[8..16].try_into().unwrap())
    );
    assert_ne!(
        message.receiver,
        u32::from_be_bytes(packet[4..8].try_into().unwrap())
    );
}

#[test]
fn transport_accepts_min_len_and_larger_payloads() {
    assert_eq!(TRANSPORT_MIN_LEN, 32);
    // 本层不要求整包 16 对齐：16/17/33/1420 等不同密文长度结构上都可解析。
    for cipher_len in [16usize, 17, 32, 33, 48, 1024, 1420] {
        let packet = transport_packet(1, 7, cipher_len);
        let Message::Transport(message) = parse(&packet).expect("transport") else {
            panic!("期望 Transport");
        };
        assert_eq!(message.encrypted, &packet[16..]);
        assert_eq!(message.encrypted.len(), cipher_len);
    }
    // 恰好 32 字节：只有 AEAD 标签、零长度明文，结构上合法。
    let packet = transport_packet(1, 1, 16);
    assert_eq!(packet.len(), 32);
    assert!(parse(&packet).is_ok());
    // 零长度头部（counter=0, receiver=0）同样是合法运输报文。
    let packet = transport_packet(0, 0, 16);
    let Message::Transport(message) = parse(&packet).expect("zero header") else {
        panic!("期望 Transport");
    };
    assert_eq!((message.receiver, message.counter), (0, 0));
    assert_eq!(message.encrypted.len(), 16);
}

#[test]
fn transport_below_32_bytes_is_rejected() {
    // 唯一的运输结构约束：不足 32 字节装不下头部+标签。
    // 40、33、31 等的区别只是是否达下限，本层不对 16 对齐下结论。
    for len in [4usize, 8, 15, 16, 17, 31] {
        let mut packet = vec![0u8; len];
        packet[..4].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(
            parse(&packet),
            Err(Error::TransportTooShort(len)),
            "长度 {len} 必须按过短拒绝"
        );
    }
    // 32 及以上（含非 16 倍数）不因长度被拒绝。
    for len in [32usize, 33, 47, 64] {
        let mut packet = transport_packet(1, 1, 1424);
        packet.truncate(len);
        assert!(parse(&packet).is_ok(), "长度 {len} 结构上应可解析");
    }
    // 33 字节是「本层不验证未解密 padding」的代表用例。
    let packet = transport_packet(1, 1, 17);
    assert_eq!(packet.len(), 33);
    assert!(!packet.len().is_multiple_of(16));
    let Message::Transport(message) = parse(&packet).expect("33-byte transport") else {
        panic!("期望 Transport");
    };
    assert_eq!(message.encrypted.len(), 17);
}

#[test]
fn handshake_rejects_wrong_exact_lengths() {
    for (kind, exact) in [(1u32, INIT_LEN), (2, RESPONSE_LEN), (3, COOKIE_LEN)] {
        for len in [exact - 1, exact + 1, exact + 16, 4] {
            let packet = handshake_packet(kind, len);
            assert_eq!(
                parse(&packet),
                Err(Error::HandshakeLength {
                    kind,
                    actual: len,
                    expected: exact
                }),
                "类型 {kind} 长度 {len} 必须拒绝"
            );
        }
        // 零长度也走同一分支，报告实际长度 0。
        assert_eq!(
            parse(&handshake_packet(kind, 0)),
            Err(Error::Incomplete),
            "类型 {kind} 空输入先缺类型字段"
        );
    }
}

#[test]
fn every_truncation_below_exact_is_rejected() {
    for (kind, exact) in [(1u32, INIT_LEN), (2, RESPONSE_LEN), (3, COOKIE_LEN)] {
        for len in 0..exact {
            let packet = handshake_packet(kind, len);
            let expected = if len < 4 {
                Error::Incomplete
            } else {
                Error::HandshakeLength {
                    kind,
                    actual: len,
                    expected: exact,
                }
            };
            assert_eq!(parse(&packet), Err(expected), "类型 {kind} 长度 {len}");
        }
    }
    // 短于类型字段的输入无法判定种类。
    for len in [0usize, 1, 2, 3] {
        assert_eq!(parse(&vec![4u8; len]), Err(Error::Incomplete));
    }
}

#[test]
fn reserved_high_three_bytes_must_be_zero() {
    // 类型字段 = u32LE，高 3 字节任一非零即拒绝，不猜意图。
    for position in 1..4 {
        for bit in [0x01u8, 0x80, 0xFF] {
            let mut raw = [1u8, 0, 0, 0];
            raw[position] = bit;
            let packet = with_raw_type(handshake_packet(1, INIT_LEN), raw);
            let expected = u32::from_le_bytes(raw);
            assert_eq!(
                parse(&packet),
                Err(Error::ReservedType(expected)),
                "字节 {position}=0x{bit:02X} 必须按保留位拒绝"
            );
        }
    }
    // 运输报文同样先核对保留位，即使长度合法。
    let mut packet = transport_packet(RECEIVER, COUNTER, 16);
    packet[3] = 0x01;
    assert_eq!(parse(&packet), Err(Error::ReservedType(0x0100_0004)));
    // 保留位检查优先于长度检查。
    let short = with_raw_type(handshake_packet(1, 20), [1, 0, 0, 7]);
    assert_eq!(parse(&short), Err(Error::ReservedType(0x0700_0001)));
}

#[test]
fn unknown_types_fail_closed() {
    // 类型字段只有首字节承载类型值（高 3 字节保留为 0），所以可判定的未知类型
    // 是 0 与 5..=255；两者无论长度是否精确都不接受。
    for kind in [0u32, 5, 6, 127, 255] {
        let packet = handshake_packet(kind, INIT_LEN);
        assert_eq!(parse(&packet), Err(Error::UnknownType(kind)));
        let short = handshake_packet(kind, 4);
        assert_eq!(parse(&short), Err(Error::UnknownType(kind)));
    }
    // 运输类型位置的未知值不因长度而放宽。
    let packet = handshake_packet(9, 32);
    assert_eq!(parse(&packet), Err(Error::UnknownType(9)));
    // 需要第二个字节的类型值先被保留位分支拦下，而不是未知类型。
    let packet = with_raw_type(handshake_packet(1, INIT_LEN), [0, 1, 0, 0]);
    assert_eq!(parse(&packet), Err(Error::ReservedType(0x0000_0100)));
    let packet = with_raw_type(handshake_packet(1, INIT_LEN), [0, 0, 0, 0x80]);
    assert_eq!(parse(&packet), Err(Error::ReservedType(0x8000_0000)));
}

#[test]
fn error_display_never_contains_payload_bytes() {
    // 报文体里放一个独特哨兵值，任何错误信息都不得带上它。
    const SENTINEL: u8 = 211;
    let mut packet = vec![SENTINEL; INIT_LEN];
    packet[..4].copy_from_slice(&1u32.to_le_bytes());
    packet.truncate(100);
    let error = parse(&packet).expect_err("长度错误");
    assert!(!error.to_string().contains(&SENTINEL.to_string()));
    let mut packet = vec![SENTINEL; 20];
    packet[..4].copy_from_slice(&4u32.to_le_bytes());
    let error = parse(&packet).expect_err("运输过短");
    assert!(!error.to_string().contains(&SENTINEL.to_string()));
    let error = parse(&[0, 0, 0, 5]).expect_err("未知类型");
    assert!(!error.to_string().contains(&SENTINEL.to_string()));
}

#[test]
fn debug_output_does_not_leak_payload() {
    const SENTINEL: u8 = 211;
    let mut packet = transport_packet(9, 5, 16);
    for byte in packet[16..].iter_mut() {
        *byte = SENTINEL;
    }
    let Message::Transport(message) = parse(&packet).expect("legal transport") else {
        panic!("期望 Transport");
    };
    let rendered = format!("{message:?}");
    assert!(rendered.contains("encrypted_len"), "{rendered}");
    assert!(
        !rendered.contains(&SENTINEL.to_string()),
        "运输 Debug 泄漏密文字节"
    );
    assert!(!rendered.contains("211, 211"));
    assert_eq!(message.receiver, 9);
    assert_eq!(message.counter, 5);

    let mut packet = handshake_packet(1, INIT_LEN);
    for byte in packet[4..].iter_mut() {
        *byte = SENTINEL;
    }
    let Message::Init(message) = parse(&packet).expect("legal init") else {
        panic!("期望 Init");
    };
    let rendered = format!("{message:?}");
    assert!(
        !rendered.contains(&SENTINEL.to_string()),
        "握手 Debug 泄漏原始字节"
    );
    assert!(rendered.contains("len: 148"), "{rendered}");
    // 借用类型保持 `'a`，不复制载荷。
    let borrow: &HandshakeMessage<'_> = &message;
    assert_eq!(borrow.unverified_bytes().len(), INIT_LEN);
    let _: &TransportMessage<'_> = &lengsuo_wireguard::TransportMessage {
        receiver: 0,
        counter: 0,
        encrypted: &[],
    };
}

#[test]
fn parse_does_not_mutate_or_copy_input() {
    let packet = transport_packet(RECEIVER, COUNTER, 32);
    let before = packet.clone();
    let parsed = parse(&packet).expect("legal");
    assert_eq!(packet, before, "解析不得改写输入");
    let Message::Transport(message) = parsed else {
        panic!("期望 Transport");
    };
    // 密文切片与原缓冲区同一地址：零拷贝借用。
    assert!(core::ptr::eq(message.encrypted, &packet[16..]));
}
