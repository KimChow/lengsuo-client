//! CONNECT-UDP 响应消息测试。
//!
//! 只覆盖本 crate 的消息层编解码原语：不证明 HTTP/3 层、QUIC 连接、认证 token
//! 或与原生 apernet/hysteria 的双向互通已完成。消息与 padding 均为测试假值。

use lengsuo_hysteria::connect_udp::ConnectUdpResponse;
use lengsuo_hysteria::tcp::{Status, MAX_MESSAGE_LENGTH, MAX_PADDING_LENGTH};
use lengsuo_hysteria::Error;
use std::time::Duration;

/// 参考布局：status + varint(msg_len) + msg + varint(pad_len) + pad。
/// 期望字节由测试自己的长度编码构造，不调用被测编码函数。
fn response_frame(status: Status, message: &[u8], padding: &[u8]) -> Vec<u8> {
    let mut bytes = vec![status.as_byte()];
    bytes.extend_from_slice(&len_bytes(message.len()));
    bytes.extend_from_slice(message);
    bytes.extend_from_slice(&len_bytes(padding.len()));
    bytes.extend_from_slice(padding);
    bytes
}

/// 独立实现的最短长度编码（本仓取值 <= 4096，只需 1/2 字节形式）。
fn len_bytes(value: usize) -> Vec<u8> {
    if value <= 63 {
        vec![value as u8]
    } else {
        vec![((value >> 8) as u8) | 0x40, value as u8]
    }
}

fn response(status: Status, message: &str, padding: &[u8]) -> ConnectUdpResponse {
    ConnectUdpResponse {
        status,
        message: message.to_string(),
        padding: padding.to_vec(),
    }
}

/// ConnectUdpResponse 故意不派生 Debug，失败路径先丢弃成功值再取错误。
fn response_error(input: &[u8]) -> Error {
    match ConnectUdpResponse::decode(input) {
        Ok((_, used)) => panic!("应 fail-closed，但解析出 {used} 字节"),
        Err(error) => error,
    }
}

#[test]
fn fixed_response_bytes() {
    let expected: &[u8] = &[0x01, 0x05, b'r', b'e', b'f', b'u', b's', 0x02, b'p', b'd'];
    assert_eq!(response_frame(Status::Error, b"refus", b"pd"), expected);
    let resp = response(Status::Error, "refus", b"pd");
    assert_eq!(resp.encoded_len().ok(), Some(expected.len()));
    assert_eq!(resp.encode().expect("编码"), expected);
    assert_eq!(
        ConnectUdpResponse::decode(expected).expect("解码"),
        (resp.clone(), expected.len())
    );
    assert_eq!(
        ConnectUdpResponse::decode_exact(expected).expect("定界解码"),
        resp
    );
}

#[tokio::test]
async fn response_roundtrip_both_directions_within_timeout() {
    // 客户端侧放行响应与服务端侧拒绝响应两个方向都做完整往返。
    let work = async {
        for (status, message) in [
            (Status::Ok, ""),
            (Status::Ok, "accepted"),
            (Status::Error, "udp disabled by server"),
        ] {
            let resp = response(status, message, b"pad-pad");
            let bytes = resp.encode().expect("编码");
            let (decoded, used) = ConnectUdpResponse::decode(&bytes).expect("解码");
            assert_eq!(used, bytes.len(), "{status:?} 空消息往返");
            assert_eq!(decoded, resp);
            assert_eq!(decoded.status, status);
            assert_eq!(decoded.message, message);
            assert_eq!(decoded.encode().expect("回环编码"), bytes);
        }
    };
    tokio::time::timeout(Duration::from_millis(2_000), work)
        .await
        .expect("双向往返应在超时内完成");
}

#[tokio::test]
async fn response_tamper_and_truncation_fail_within_timeout() {
    let work = async {
        let intact = response_frame(Status::Ok, b"ok", b"pad");
        // 篡改状态字节。
        let mut tampered = intact.clone();
        tampered[0] = 0x07;
        assert_eq!(
            response_error(&tampered),
            Error::InvalidStatus { byte: 0x07 }
        );
        // 截断 padding 体。
        assert_eq!(
            response_error(&intact[..intact.len() - 1]),
            Error::Truncated {
                need: intact.len(),
                got: intact.len() - 1
            }
        );
        // 长度不一致（外层多声明 1 字节）。
        let mut extra = intact.clone();
        extra.push(b'?');
        assert_eq!(
            ConnectUdpResponse::decode_exact(&extra).expect_err("长度不一致"),
            Error::LengthMismatch {
                declared: extra.len(),
                consumed: intact.len()
            }
        );
    };
    tokio::time::timeout(Duration::from_millis(2_000), work)
        .await
        .expect("错误路径应在超时内 fail-closed");
}

#[test]
fn response_message_may_be_empty() {
    let bytes = response_frame(Status::Ok, b"", b"");
    assert_eq!(bytes, vec![0x00, 0x00, 0x00]);
    let (decoded, used) = ConnectUdpResponse::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded, response(Status::Ok, "", b""));
}

#[test]
fn response_accepts_maximum_lengths() {
    let message = "m".repeat(MAX_MESSAGE_LENGTH as usize);
    let padding = vec![0x2A_u8; MAX_PADDING_LENGTH as usize];
    let resp = response(Status::Error, &message, &padding);
    let bytes = resp.encode().expect("编码");
    assert_eq!(bytes.len(), 1 + 2 + message.len() + 2 + padding.len());
    let (decoded, used) = ConnectUdpResponse::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded, resp);
}

#[test]
fn response_rejects_lengths_above_maximum() {
    let bytes = response_frame(
        Status::Error,
        &vec![b'm'; (MAX_MESSAGE_LENGTH + 1) as usize],
        &[],
    );
    assert_eq!(
        response_error(&bytes),
        Error::TooLong {
            field: "message",
            len: 2049,
            max: MAX_MESSAGE_LENGTH
        }
    );
    let bytes = response_frame(
        Status::Ok,
        b"",
        &vec![0x20; (MAX_PADDING_LENGTH + 1) as usize],
    );
    assert_eq!(
        response_error(&bytes),
        Error::TooLong {
            field: "padding",
            len: 4097,
            max: MAX_PADDING_LENGTH
        }
    );
    assert_eq!(
        response(
            Status::Error,
            &"m".repeat((MAX_MESSAGE_LENGTH + 1) as usize),
            b""
        )
        .encode()
        .expect_err("结构体消息超限"),
        Error::TooLong {
            field: "message",
            len: 2049,
            max: MAX_MESSAGE_LENGTH
        }
    );
}

#[test]
fn every_response_truncation_reports_needed_length() {
    // 帧布局：0 状态，1 消息长度，2..5 消息，5 padding 长度，6..9 padding。
    let bytes = response_frame(Status::Ok, b"yes", b"pad");
    assert_eq!(bytes.len(), 9);
    let expectations: &[(usize, usize)] = &[
        (0, 1), // 状态字节
        (1, 2), // 消息长度字段
        (2, 5), // 消息体
        (4, 5), // 消息最后 1 字节
        (5, 6), // padding 长度字段
        (6, 9), // padding 体
        (8, 9),
    ];
    for (got, need) in expectations {
        assert_eq!(
            response_error(&bytes[..*got]),
            Error::Truncated {
                need: *need,
                got: *got
            },
            "只剩 {got} 字节"
        );
    }
    for got in 0..bytes.len() {
        match response_error(&bytes[..got]) {
            Error::Truncated { need, got: seen } => {
                assert_eq!(seen, got);
                assert!(need > got, "need 应大于可用字节");
            }
            other => panic!("只剩 {got} 字节应报截断，实际 {other:?}"),
        }
    }
    assert_eq!(
        ConnectUdpResponse::decode(&bytes)
            .ok()
            .map(|(_, used)| used),
        Some(9)
    );
    assert_eq!(
        ConnectUdpResponse::decode_exact(&bytes[..8]).expect_err("前缀必截断"),
        Error::Truncated { need: 9, got: 8 }
    );
}

#[test]
fn response_rejects_invalid_status() {
    for byte in [0x02_u8, 0x03, 0x40, 0x44, 0x7F, 0x80, 0xFE, 0xFF] {
        let mut input = vec![byte];
        input.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(
            response_error(&input),
            Error::InvalidStatus { byte },
            "状态 {byte:#04x}"
        );
    }
    assert!(ConnectUdpResponse::decode(&[0x00, 0x00, 0x00]).is_ok());
    assert!(ConnectUdpResponse::decode(&[0x01, 0x00, 0x00]).is_ok());
}

#[test]
fn response_rejects_nul_and_invalid_utf8_in_message() {
    assert_eq!(
        response_error(&response_frame(Status::Ok, b"bad\x00msg", &[])),
        Error::ContainsNul { field: "message" }
    );
    assert_eq!(
        response_error(&response_frame(Status::Ok, &[0x41, 0xFF], &[])),
        Error::InvalidUtf8 { field: "message" }
    );
    assert_eq!(
        response_error(&response_frame(Status::Ok, &[0xF0, 0x9F, 0x92], &[])),
        Error::InvalidUtf8 { field: "message" }
    );
    assert_eq!(
        response(Status::Error, "bad\u{0}msg", b"")
            .encode()
            .expect_err("结构体 NUL"),
        Error::ContainsNul { field: "message" }
    );
    let text = "放行 正常。";
    let bytes = response_frame(Status::Ok, text.as_bytes(), b"");
    let (decoded, used) = ConnectUdpResponse::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded.message, text);
    assert_eq!(decoded.encode().expect("编码"), bytes);
}

#[test]
fn response_accepts_non_shortest_length_fields() {
    // 消息长度 2 写成 4 字节、padding 长度 3 写成 8 字节的非最短形式。
    let mut bytes = vec![Status::Ok.as_byte()];
    bytes.extend_from_slice(&[0x80, 0x00, 0x00, 0x02]);
    bytes.extend_from_slice(b"ok");
    bytes.extend_from_slice(&[0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]);
    bytes.extend_from_slice(b"pad");
    let (decoded, used) = ConnectUdpResponse::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len(), "消耗长度含非最短前缀");
    assert_eq!(decoded, response(Status::Ok, "ok", b"pad"));
    assert_eq!(
        decoded.encode().expect("编码"),
        response_frame(Status::Ok, b"ok", b"pad")
    );
    assert_eq!(
        ConnectUdpResponse::decode_exact(&bytes).expect("定界解码"),
        response(Status::Ok, "ok", b"pad")
    );
}

#[test]
fn response_decode_does_not_swallow_payload() {
    let bytes = response_frame(Status::Ok, b"ok", b"pad");
    let mut stream = bytes.clone();
    stream.extend_from_slice(b"\xAA\xBBfollowing-frames");
    let (decoded, used) = ConnectUdpResponse::decode(&stream).expect("解码");
    assert_eq!(used, bytes.len(), "只消耗帧本身");
    assert_eq!(decoded, response(Status::Ok, "ok", b"pad"));
    assert_eq!(
        &stream[used..],
        b"\xAA\xBBfollowing-frames",
        "帧后字节留给后续 capsule"
    );
}

#[test]
fn response_errors_and_debug_do_not_leak_message_or_padding() {
    let intact = response_frame(Status::Ok, REASON, PAD);
    let variants = [
        intact[..6].to_vec(), // 截断消息体
        {
            let mut bytes = intact.clone();
            bytes[0] = 0x09; // 非法状态
            bytes
        },
        {
            // 消息中注入 NUL：偏移 = 状态 1 + 长度 1 + 消息内第 2 字节。
            let mut bytes = intact.clone();
            bytes[1 + len_bytes(REASON.len()).len() + 2] = 0x00;
            bytes
        },
    ];
    for input in variants {
        let rendered = response_error(&input).to_string();
        assert!(!rendered.contains("private-reason"), "{rendered}");
        assert!(!rendered.contains("sensitive-padding"), "{rendered}");
    }
    let rendered = format!("{:?}", response(Status::Error, "private-reason", PAD));
    assert!(!rendered.contains("private-reason"), "{rendered}");
    assert!(!rendered.contains("sensitive-padding"), "{rendered}");
    assert!(rendered.contains("message_len"), "{rendered}");
}

const REASON: &[u8] = b"private-reason";
const PAD: &[u8] = b"sensitive-padding";
