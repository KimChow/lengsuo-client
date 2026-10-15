//! Hysteria2 TCPResponse 帧测试。
//!
//! 只覆盖本 crate 的帧编解码原语：不证明 QUIC 连接、HTTP/3 伪装认证、
//! UDP 中继或与参考实现的双向互通已完成。
//! 消息与 padding 均为测试专用假值，不含真实凭据。

use lengsuo_hysteria::tcp::{Status, TcpResponse, MAX_MESSAGE_LENGTH, MAX_PADDING_LENGTH};
use lengsuo_hysteria::Error;

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

fn response(status: Status, message: &str, padding: &[u8]) -> TcpResponse {
    TcpResponse {
        status,
        message: message.to_string(),
        padding: padding.to_vec(),
    }
}

/// TcpResponse 故意不派生 Debug，失败路径先丢弃成功值再取错误。
fn response_error(input: &[u8]) -> Error {
    match TcpResponse::decode(input) {
        Ok((_, used)) => panic!("应 fail-closed，但解析出 {used} 字节"),
        Err(error) => error,
    }
}

const REASON: &[u8] = b"private-reason";
const PAD: &[u8] = b"sensitive-padding";

#[test]
fn fixed_response_bytes() {
    // OK + 空消息 + padding "xx"：消息长度 0，padding 长度 2。
    let ok: &[u8] = &[0x00, 0x00, 0x02, b'x', b'x'];
    let ok_struct = response(Status::Ok, "", b"xx");
    let ok_bytes = response_frame(Status::Ok, b"", b"xx");
    assert_eq!(ok_bytes, ok.to_vec());
    assert_eq!(ok_struct.encoded_len().ok(), Some(ok.len()));
    assert_eq!(ok_struct.encode().expect("编码"), ok.to_vec());
    assert_eq!(
        TcpResponse::decode(ok).expect("解码"),
        (ok_struct, ok.len())
    );

    // Error + 21 字节消息 + padding "p"。
    let msg: &[u8] = b"authentication failed";
    let err: &[u8] = &[
        0x01, 0x15, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
        0x6e, 0x20, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x01, 0x70,
    ];
    let err_struct = response(Status::Error, "authentication failed", b"p");
    assert_eq!(response_frame(Status::Error, msg, b"p"), err.to_vec());
    assert_eq!(msg.len(), 21);
    assert_eq!(err.len(), 25);
    assert_eq!(err_struct.encoded_len().ok(), Some(err.len()));
    assert_eq!(err_struct.encode().expect("编码"), err.to_vec());
    assert_eq!(
        TcpResponse::decode(err).expect("解码"),
        (err_struct.clone(), err.len())
    );
    // 状态字节只有 0/1 两种取值。
    assert_eq!(Status::Ok.as_byte(), 0);
    assert_eq!(Status::Error.as_byte(), 1);
}

#[test]
fn response_message_may_be_empty_or_non_ascii() {
    for message in ["", "x", "连接被拒绝。", "ok: 42"] {
        for padding in [&b""[..], &b"pad"[..]] {
            let bytes = response_frame(Status::Ok, message.as_bytes(), padding);
            let (decoded, used) = TcpResponse::decode(&bytes).expect("解码");
            assert_eq!(used, bytes.len());
            assert_eq!(decoded, response(Status::Ok, message, padding));
            assert_eq!(decoded.encode().expect("回环编码"), bytes);
        }
    }
    // 空地址不允许，但空消息允许（与参考实现 "No message is fine" 一致）。
    assert_eq!(
        TcpResponse::decode(&[0x00, 0x00, 0x00])
            .ok()
            .map(|(r, _)| r),
        Some(response(Status::Ok, "", b""))
    );
}

#[test]
fn response_accepts_maximum_lengths() {
    let message = "m".repeat(MAX_MESSAGE_LENGTH as usize);
    let padding = vec![0x7F_u8; MAX_PADDING_LENGTH as usize];
    let expected = response(Status::Error, &message, &padding);
    let bytes = expected.encode().expect("编码");
    assert_eq!(
        bytes.len(),
        1 + 2 + message.len() + 2 + padding.len(),
        "2048/4096 用 2 字节 varint"
    );
    assert_eq!(bytes[1], 0x48, "消息长度 2048 的首字节");
    assert_eq!(bytes[2], 0x00, "消息长度 2048 的次字节");
    assert_eq!(
        &bytes[3 + message.len()..5 + message.len()],
        &[0x50, 0x00],
        "padding 长度 4096"
    );
    let (decoded, used) = TcpResponse::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded, expected);
}

#[test]
fn response_rejects_lengths_above_maximum() {
    assert_eq!(
        response_error(&response_frame(Status::Ok, &vec![b'm'; 2049], &[])),
        Error::TooLong {
            field: "message",
            len: 2049,
            max: MAX_MESSAGE_LENGTH
        }
    );
    assert_eq!(
        response_error(&response_frame(Status::Ok, b"hi", &vec![0x20; 4097])),
        Error::TooLong {
            field: "padding",
            len: 4097,
            max: MAX_PADDING_LENGTH
        }
    );
    // 上限边界合法。
    assert!(
        TcpResponse::decode(&response_frame(Status::Ok, &vec![b'm'; 2048], &[])).is_ok(),
        "2048 应合法"
    );
    assert!(
        TcpResponse::decode(&response_frame(Status::Ok, b"hi", &vec![0x20; 4096])).is_ok(),
        "4096 应合法"
    );
    // 结构体侧同样在写入任何字节前拒绝。
    assert_eq!(
        response(Status::Ok, &"m".repeat(2049), b"")
            .encode()
            .expect_err("结构体消息超限"),
        Error::TooLong {
            field: "message",
            len: 2049,
            max: MAX_MESSAGE_LENGTH
        }
    );
    assert_eq!(
        response(Status::Ok, "", &vec![0x20; 4097])
            .encode()
            .expect_err("结构体 padding 超限"),
        Error::TooLong {
            field: "padding",
            len: 4097,
            max: MAX_PADDING_LENGTH
        }
    );
}

#[test]
fn every_response_truncation_reports_needed_length() {
    // 帧布局：0 状态，1 消息长度，2..15 消息，15 padding 长度，16..19 padding。
    let bytes = response_frame(Status::Ok, b"example.com:4", b"pad");
    assert_eq!(bytes.len(), 19);
    let expectations: &[(usize, usize)] = &[
        (0, 1),   // 状态字节
        (1, 2),   // 消息长度字段
        (2, 15),  // 消息体
        (14, 15), // 消息最后 1 字节
        (15, 16), // padding 长度字段
        (16, 19), // padding 体
        (18, 19),
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
    // 全量扫描：任何真前缀都必须失败，且 need 大于可用字节。
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
        TcpResponse::decode(&bytes).ok().map(|(_, used)| used),
        Some(19),
        "完整帧应成功"
    );
    // 2 字节非最短消息长度字段的前缀：缺尾字节须按 2 字节报需求。
    let mut prefix = vec![0x00, 0x40];
    prefix.extend_from_slice(&[0x05]);
    prefix.extend_from_slice(b"error");
    prefix.extend_from_slice(&[0x00]);
    assert_eq!(
        response_error(&prefix[..1]),
        Error::Truncated { need: 2, got: 1 }
    );
    assert_eq!(
        response_error(&prefix[..2]),
        Error::Truncated { need: 3, got: 2 }
    );
    assert_eq!(
        TcpResponse::decode(&prefix).ok().map(|(_, used)| used),
        Some(prefix.len())
    );
}

#[test]
fn response_rejects_invalid_status() {
    for byte in [0x02_u8, 0x03, 0x40, 0x7F, 0x80, 0xFE, 0xFF] {
        let mut input = vec![byte];
        input.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(
            response_error(&input),
            Error::InvalidStatus { byte },
            "状态 {byte:#04x}"
        );
    }
    // 只有 0x00/0x01 合法。
    assert!(TcpResponse::decode(&[0x00, 0x00, 0x00]).is_ok());
    assert!(TcpResponse::decode(&[0x01, 0x00, 0x00]).is_ok());
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
    // 截断的多字节序列。
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
    // 合法非 ASCII 消息字节回环。
    let message = "HyOK 正常。";
    let bytes = response_frame(Status::Ok, message.as_bytes(), b"");
    let (decoded, used) = TcpResponse::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded.message, message);
    assert_eq!(decoded.encode().expect("编码"), bytes);
}

#[test]
fn response_accepts_non_shortest_length_fields() {
    // 消息长度 5 写成 4 字节、padding 长度 2 写成 8 字节的非最短形式。
    // QUIC 允许非最短解码（quicvarint.Read 同样接受），因此这是合法输入。
    let mut bytes = vec![Status::Error.as_byte()];
    bytes.extend_from_slice(&[0x80, 0x00, 0x00, 0x05]);
    bytes.extend_from_slice(b"error");
    bytes.extend_from_slice(&[0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
    bytes.extend_from_slice(b"ab");
    let (decoded, used) = TcpResponse::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len(), "消耗长度含非最短前缀");
    assert_eq!(decoded, response(Status::Error, "error", b"ab"));
    // 编码侧永远输出最短形式。
    assert_eq!(
        decoded.encode().expect("编码"),
        response_frame(Status::Error, b"error", b"ab")
    );
}

#[test]
fn response_decode_does_not_swallow_payload() {
    let bytes = response_frame(Status::Ok, b"ok", b"pad");
    let mut stream = bytes.clone();
    stream.extend_from_slice(b"\x00\x01\x02stream-body");
    let (decoded, used) = TcpResponse::decode(&stream).expect("解码");
    assert_eq!(used, bytes.len(), "只消耗帧本身");
    assert_eq!(decoded, response(Status::Ok, "ok", b"pad"));
    assert_eq!(
        &stream[used..],
        b"\x00\x01\x02stream-body",
        "帧后字节留给应用载荷"
    );

    // 相邻两帧可依次解析，消耗长度即下一帧起点。
    let second = response_frame(Status::Error, b"deny", b"");
    let mut two = bytes.clone();
    two.extend_from_slice(&second);
    let (first_struct, first_used) = TcpResponse::decode(&two).expect("第一帧");
    assert_eq!(first_used, bytes.len());
    let (second_struct, second_used) = TcpResponse::decode(&two[first_used..]).expect("第二帧");
    assert_eq!(first_used + second_used, two.len(), "两帧首尾相接");
    assert_eq!(first_struct, response(Status::Ok, "ok", b"pad"));
    assert_eq!(second_struct, response(Status::Error, "deny", b""));
}

#[test]
fn response_errors_do_not_leak_message_or_padding() {
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
}
