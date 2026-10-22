//! 帧编解码 API 的行为契约。
//!
//! 本文件的期望字节**手写**（照契约 §5.2 逐字段推导），
//! ⛔ 不读向量文件、⛔ 不用「编码再解码相等」冒充验收。

use lengsuo_browser_extension::error::FrameError;
use lengsuo_browser_extension::frame::{
    decode, decode_exact, Frame, FRAME_HEADER_LEN, MAX_PAYLOAD_LEN,
};

/// 帧头：len(4, 大端) + type(1) + reserved(3)。
///
/// 手算：len = 1 ⇒ `00 00 00 01`；type = 0 ⇒ `00`；reserved ⇒ `00 00 00`。
const FRAME_LEN1_TYPE0: &[u8] = &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x5a];

/// 帧头：len = 256 ⇒ `00 00 01 00`；type = 3 ⇒ `03`；reserved ⇒ `00 00 00`。
const FRAME_LEN256_TYPE3: &[u8] = &[0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00];

#[test]
fn encode_produces_the_hand_derived_bytes() {
    let frame = Frame::new(0, vec![0x5a]);
    assert_eq!(frame.encode().unwrap(), FRAME_LEN1_TYPE0);
}

#[test]
fn len_is_payload_length_not_total_length() {
    // len = 256 ⇒ 整帧 = 8 + 256 = 264 字节，len 字段本身不参与。
    let frame = Frame::new(3, vec![0x5a; 256]);
    let encoded = frame.encode().unwrap();
    assert_eq!(encoded.len(), FRAME_HEADER_LEN + 256);
    assert_eq!(
        &encoded[..FRAME_HEADER_LEN],
        &FRAME_LEN256_TYPE3[..FRAME_HEADER_LEN]
    );
    assert_eq!(
        u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]),
        256
    );
}

#[test]
fn len_is_big_endian() {
    // 大端 ⇒ 256 写成 00 00 01 00；小端会写成 00 01 00 00。
    let encoded = Frame::new(3, vec![0x5a; 256]).encode().unwrap();
    assert_eq!(encoded[0], 0x00);
    assert_eq!(encoded[1], 0x00);
    assert_eq!(encoded[2], 0x01);
    assert_eq!(encoded[3], 0x00);
}

#[test]
fn reserved_bytes_are_always_zero() {
    let encoded = Frame::new(10, vec![0x01, 0x02]).encode().unwrap();
    assert_eq!(&encoded[5..8], &[0x00, 0x00, 0x00]);
}

#[test]
fn decode_returns_the_number_of_consumed_bytes() {
    let (frame, consumed) = decode(FRAME_LEN1_TYPE0).unwrap();
    assert_eq!(consumed, FRAME_LEN1_TYPE0.len());
    assert_eq!(frame.frame_type, 0);
    assert_eq!(frame.payload, vec![0x5a]);
}

#[test]
fn decode_splits_concatenated_frames() {
    // 粘包：两帧连续排列，decode 只切第一帧并给出已消费长度。
    let mut buffer = Frame::new(1, vec![0xaa]).encode().unwrap();
    buffer.extend(Frame::new(2, vec![0xbb, 0xcc]).encode().unwrap());

    let (first, consumed) = decode(&buffer).unwrap();
    assert_eq!(first.frame_type, 1);
    assert_eq!(first.payload, vec![0xaa]);
    assert_eq!(consumed, FRAME_HEADER_LEN + 1);

    let (second, consumed) = decode(&buffer[consumed..]).unwrap();
    assert_eq!(second.frame_type, 2);
    assert_eq!(second.payload, vec![0xbb, 0xcc]);
    assert_eq!(consumed, FRAME_HEADER_LEN + 2);
}

#[test]
fn decode_exact_rejects_trailing_bytes() {
    let mut buffer = Frame::new(0, vec![]).encode().unwrap();
    buffer.push(0x00);
    match decode_exact(&buffer) {
        Err(FrameError::TrailingBytes { expected, actual }) => {
            assert_eq!(expected, FRAME_HEADER_LEN);
            assert_eq!(actual, FRAME_HEADER_LEN + 1);
        }
        other => panic!("期望 trailing_bytes，实际 {:?}", other),
    }
}

#[test]
fn decode_exact_accepts_exactly_one_frame() {
    let frame = decode_exact(FRAME_LEN1_TYPE0).unwrap();
    assert_eq!(frame.frame_type, 0);
    assert_eq!(frame.payload, vec![0x5a]);
}

#[test]
fn decode_of_empty_buffer_fails() {
    match decode(&[]) {
        Err(FrameError::TruncatedHeader { needed, available }) => {
            assert_eq!(needed, FRAME_HEADER_LEN);
            assert_eq!(available, 0);
        }
        other => panic!("期望 truncated_header，实际 {:?}", other),
    }
}

#[test]
fn encode_rejects_payload_over_the_limit() {
    let frame = Frame::new(0, vec![0u8; MAX_PAYLOAD_LEN + 1]);
    match frame.encode() {
        Err(FrameError::PayloadTooLong { declared, limit }) => {
            assert_eq!(declared, (MAX_PAYLOAD_LEN + 1) as u64);
            assert_eq!(limit, MAX_PAYLOAD_LEN);
        }
        other => panic!("期望 payload_too_long，实际 {:?}", other),
    }
}

#[test]
fn encode_accepts_payload_exactly_at_the_limit() {
    // 上限本身含在内（契约写的是「len > 1 MiB ⇒ 失败」）。
    let frame = Frame::new(0, vec![0u8; MAX_PAYLOAD_LEN]);
    let encoded = frame.encode().unwrap();
    assert_eq!(encoded.len(), FRAME_HEADER_LEN + MAX_PAYLOAD_LEN);
    assert_eq!(
        u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]),
        MAX_PAYLOAD_LEN as u32
    );
}

#[test]
fn encode_rejects_unknown_message_type() {
    match Frame::new(11, vec![]).encode() {
        Err(FrameError::UnknownMessageType { got }) => assert_eq!(got, 11),
        other => panic!("期望 unknown_message_type，实际 {:?}", other),
    }
}

#[test]
fn decode_fails_immediately_when_len_exceeds_the_limit() {
    // 只给 8 字节帧头，声明 len = 1 MiB + 1 ⇒ 立刻失败，
    // ⛔ 不得「等更多数据」，⛔ 不得截断到可用长度。
    let buffer = [0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    match decode(&buffer) {
        Err(FrameError::PayloadTooLong { declared, limit }) => {
            assert_eq!(declared, 1_048_577);
            assert_eq!(limit, MAX_PAYLOAD_LEN);
        }
        other => panic!("期望 payload_too_long，实际 {:?}", other),
    }
}

#[test]
fn decode_fails_when_reserved_is_not_zero() {
    for index in 0..3 {
        let mut buffer = [0u8; FRAME_HEADER_LEN];
        buffer[5 + index] = 1;
        match decode(&buffer) {
            Err(FrameError::ReservedNotZero { got }) => {
                assert_eq!(got[index], 1);
                assert_eq!(got.iter().filter(|b| **b != 0).count(), 1);
            }
            other => panic!("期望 reserved_not_zero，实际 {:?}", other),
        }
    }
}

#[test]
fn decode_fails_on_unknown_message_type() {
    for got in [11u8, 12, 255] {
        let mut buffer = [0u8; FRAME_HEADER_LEN];
        buffer[4] = got;
        match decode(&buffer) {
            Err(FrameError::UnknownMessageType { got: reported }) => assert_eq!(reported, got),
            other => panic!("期望 unknown_message_type，实际 {:?}", other),
        }
    }
}

#[test]
fn decode_fails_when_payload_is_shorter_than_declared() {
    // 声明 len = 4，只有 2 字节载荷 ⇒ 报错，⛔ 不截断、不读越界。
    let buffer = [0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x5a, 0x5a];
    match decode(&buffer) {
        Err(FrameError::TruncatedPayload {
            declared,
            available,
        }) => {
            assert_eq!(declared, 4);
            assert_eq!(available, 2);
        }
        other => panic!("期望 truncated_payload，实际 {:?}", other),
    }
}

#[test]
fn frame_debug_does_not_leak_the_payload() {
    let frame = Frame::new(0, vec![0xde, 0xad, 0xbe, 0xef]);
    let rendered = format!("{:?}", frame);
    assert!(rendered.contains("payload_len"), "Debug 必须给出载荷长度");
    assert!(!rendered.contains("222"), "Debug 绝不能输出载荷字节");
    assert!(!rendered.contains("de"), "Debug 绝不能输出载荷字节");
}
