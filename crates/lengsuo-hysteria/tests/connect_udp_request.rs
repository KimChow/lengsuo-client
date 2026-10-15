//! CONNECT-UDP 请求消息测试。
//!
//! 只覆盖本 crate 的消息层编解码原语：不证明 HTTP/3 Extended CONNECT 协商、
//! QUIC 连接、认证 token、UDP 中继或与原生 apernet/hysteria 的双向互通已完成。
//! 地址与 padding 均为测试专用假值，不含真实凭据。

use lengsuo_hysteria::connect_udp::{ConnectUdpRequest, REQUEST_TYPE_CONNECT_UDP};
use lengsuo_hysteria::tcp::{MAX_ADDRESS_LENGTH, MAX_PADDING_LENGTH};
use lengsuo_hysteria::varint::MAX_VALUE;
use lengsuo_hysteria::Error;
use std::time::Duration;

/// `0x402` 的规范最短编码。
const TYPE_BYTES: [u8; 2] = [0x44, 0x02];

/// 独立实现的长度编码（本仓取值 <= 4096，只需 1/2 字节形式），
/// 避免用被测代码构造期望字节。
fn len_bytes(value: usize) -> Vec<u8> {
    if value <= 63 {
        vec![value as u8]
    } else {
        vec![((value >> 8) as u8) | 0x40, value as u8]
    }
}

/// 独立实现 QUIC varint 解码，只用于推导测试期望值。
fn prefix_value(prefix: &[u8]) -> u64 {
    match prefix.len() {
        4 => u64::from(u32::from_be_bytes(prefix.try_into().expect("4 字节"))) & 0x3FFF_FFFF,
        8 => u64::from_be_bytes(prefix.try_into().expect("8 字节")) & 0x3FFF_FFFF_FFFF_FFFF,
        other => unreachable!("测试只用 4/8 字节前缀，收到 {other}"),
    }
}

/// 参考布局：type + varint(addr_len) + addr + varint(pad_len) + pad。
fn frame(addr: &[u8], padding: &[u8]) -> Vec<u8> {
    let mut bytes = TYPE_BYTES.to_vec();
    bytes.extend_from_slice(&len_bytes(addr.len()));
    bytes.extend_from_slice(addr);
    bytes.extend_from_slice(&len_bytes(padding.len()));
    bytes.extend_from_slice(padding);
    bytes
}

fn request(address: &str, padding: &[u8]) -> ConnectUdpRequest {
    ConnectUdpRequest {
        address: address.to_string(),
        padding: padding.to_vec(),
    }
}

/// ConnectUdpRequest 故意不派生 Debug，失败路径先丢弃成功值再取错误。
fn request_error(input: &[u8]) -> Error {
    match ConnectUdpRequest::decode(input) {
        Ok((_, used)) => panic!("应 fail-closed，但解析出 {used} 字节"),
        Err(error) => error,
    }
}

#[test]
fn fixed_request_bytes() {
    let expected: &[u8] = &[
        0x44, 0x02, 0x0F, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', b':',
        b'4', b'4', b'3', 0x03, b'p', b'a', b'd',
    ];
    assert_eq!(REQUEST_TYPE_CONNECT_UDP, 0x402);
    assert_eq!(frame(b"example.com:443", b"pad"), expected.to_vec());

    let req = request("example.com:443", b"pad");
    assert_eq!(req.encoded_len().ok(), Some(expected.len()));
    assert_eq!(req.encode().expect("编码"), expected.to_vec());
    assert_eq!(
        ConnectUdpRequest::decode(expected).expect("解码"),
        (req.clone(), expected.len())
    );
}

#[tokio::test]
async fn request_roundtrip_within_timeout() {
    // 纯字节层的编码/解码往返；用超时兜住任何 pathological 输入导致的停滞。
    let work = async {
        let req = request("udp.example.test:53", b"abcdefgh");
        let bytes = req.encode().expect("编码");
        let (decoded, used) = ConnectUdpRequest::decode(&bytes).expect("解码");
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, req);
        assert_eq!(decoded.encode().expect("回环编码"), bytes);
        assert_eq!(decoded.padding.len(), 8);
        bytes
    };
    let bytes = tokio::time::timeout(Duration::from_millis(2_000), work)
        .await
        .expect("往返应在超时内完成");
    assert_eq!(bytes.len(), 2 + 1 + 19 + 1 + 8);
}

#[tokio::test]
async fn request_decode_of_adversarial_input_fails_within_timeout() {
    // 篡改与超长声明都必须立刻返回错误，不得挂起或 panic。
    let work = async {
        let mut tampered = frame(b"target.example:7000", b"pad");
        tampered[1] = 0x03; // 类型字节改成 0x403
        assert_eq!(
            request_error(&tampered),
            Error::InvalidFrameType { value: 0x403 }
        );

        let mut declared = frame(b"h", &[]);
        declared.truncate(2 + len_bytes(1).len() + 1);
        declared.extend_from_slice(&len_bytes(MAX_PADDING_LENGTH as usize));
        assert_eq!(
            request_error(&declared),
            Error::Truncated {
                need: declared.len() + MAX_PADDING_LENGTH as usize,
                got: declared.len()
            }
        );
    };
    tokio::time::timeout(Duration::from_millis(2_000), work)
        .await
        .expect("错误路径应在超时内 fail-closed");
}

#[test]
fn request_padding_may_be_empty() {
    let bytes = frame(b"1.1.1.1:53", b"");
    assert_eq!(
        bytes,
        vec![0x44, 0x02, 0x0A, b'1', b'.', b'1', b'.', b'1', b'.', b'1', b':', b'5', b'3', 0x00]
    );
    let (decoded, used) = ConnectUdpRequest::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded.address, "1.1.1.1:53");
    assert!(decoded.padding.is_empty());
    assert_eq!(decoded.encode().expect("回环编码"), bytes);
}

#[test]
fn request_accepts_maximum_lengths() {
    let address = "a".repeat(MAX_ADDRESS_LENGTH as usize);
    let padding = vec![0x7F_u8; MAX_PADDING_LENGTH as usize];
    let req = request(&address, &padding);
    let bytes = req.encode().expect("编码");
    assert_eq!(
        bytes.len(),
        2 + 2 + address.len() + 2 + padding.len(),
        "2048/4096 用 2 字节 varint"
    );
    assert_eq!(&bytes[2..4], &[0x48, 0x00], "地址长度 2048");
    assert_eq!(
        &bytes[4 + address.len()..6 + address.len()],
        &[0x50, 0x00],
        "padding 长度 4096"
    );
    let (decoded, used) = ConnectUdpRequest::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded, req);
    assert_eq!(
        ConnectUdpRequest::decode_exact(&bytes).expect("定界解码"),
        req
    );
}

#[test]
fn request_rejects_lengths_above_maximum() {
    let bytes = frame(&vec![b'a'; (MAX_ADDRESS_LENGTH + 1) as usize], b"");
    assert_eq!(
        request_error(&bytes),
        Error::TooLong {
            field: "address",
            len: 2049,
            max: MAX_ADDRESS_LENGTH
        }
    );
    assert!(
        ConnectUdpRequest::decode(&frame(&vec![b'a'; MAX_ADDRESS_LENGTH as usize], b"")).is_ok(),
        "2048 应合法"
    );

    let bytes = frame(b"h", &vec![0x20; (MAX_PADDING_LENGTH + 1) as usize]);
    assert_eq!(
        request_error(&bytes),
        Error::TooLong {
            field: "padding",
            len: 4097,
            max: MAX_PADDING_LENGTH
        }
    );
    assert!(
        ConnectUdpRequest::decode(&frame(b"h", &vec![0x20; MAX_PADDING_LENGTH as usize])).is_ok(),
        "4096 应合法"
    );
}

#[test]
fn every_request_truncation_reports_needed_length() {
    // 帧布局：0..2 类型，2 地址长度，3..18 地址，18 padding 长度，19..22 padding。
    let bytes = frame(b"example.com:443", b"pad");
    assert_eq!(bytes.len(), 22);
    let expectations: &[(usize, usize)] = &[
        (0, 1),   // 类型首字节
        (1, 2),   // 类型第 2 字节
        (2, 3),   // 地址长度字段
        (3, 18),  // 地址体
        (17, 18), // 地址最后 1 字节
        (18, 19), // padding 长度字段
        (19, 22), // padding 体
        (21, 22),
    ];
    for (got, need) in expectations {
        assert_eq!(
            request_error(&bytes[..*got]),
            Error::Truncated {
                need: *need,
                got: *got
            },
            "只剩 {got} 字节"
        );
    }
    // 全量扫描：任何真前缀都必须失败，且 need 大于可用字节。
    for got in 0..bytes.len() {
        match request_error(&bytes[..got]) {
            Error::Truncated { need, got: seen } => {
                assert_eq!(seen, got);
                assert!(need > got, "need 应大于可用字节");
            }
            other => panic!("只剩 {got} 字节应报截断，实际 {other:?}"),
        }
    }
    assert_eq!(
        ConnectUdpRequest::decode(&bytes).ok().map(|(_, used)| used),
        Some(22),
        "完整帧应成功"
    );
    // 定界版本同样按截断拒绝。
    assert_eq!(
        ConnectUdpRequest::decode_exact(&bytes[..21]).expect_err("前缀必截断"),
        Error::Truncated { need: 22, got: 21 }
    );
}

#[test]
fn request_rejects_wrong_request_type() {
    for (value, prefix) in [
        (0_u64, &[0x00][..]),
        (1, &[0x01]),
        (0x400, &[0x44, 0x00]),
        (0x401, &[0x44, 0x01]), // TCPRequest 类型不得当 CONNECT-UDP 接受
        (0x403, &[0x44, 0x03]),
        (2049, &[0x48, 0x01]),
        (MAX_VALUE, &[0xFF; 8]),
    ] {
        let mut input = prefix.to_vec();
        input.extend_from_slice(&[0x01, b'a', 0x00]);
        assert_eq!(
            request_error(&input),
            Error::InvalidFrameType { value },
            "类型 {value:#x}"
        );
    }
    // 非最短写法的 0x402 仍是合法类型前缀（QUIC 允许非最短解码）。
    for prefix in [
        [0x80, 0x00, 0x04, 0x02].as_slice(),
        [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02].as_slice(),
    ] {
        let mut input = prefix.to_vec();
        input.extend_from_slice(&[0x01, b'a', 0x01, b'p']);
        let (decoded, used) = ConnectUdpRequest::decode(&input).expect("解码");
        assert_eq!(used, input.len(), "非最短类型前缀 {prefix:02x?}");
        assert_eq!(decoded, request("a", b"p"));
    }
}

#[test]
fn request_rejects_empty_address() {
    let mut bytes = TYPE_BYTES.to_vec();
    bytes.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(
        request_error(&bytes),
        Error::EmptyField { field: "address" }
    );

    let (decoded, used) = ConnectUdpRequest::decode(&frame(b"z", b"")).expect("1 字节地址合法");
    assert_eq!((decoded.address.as_str(), used), ("z", 5));

    assert_eq!(
        request("", b"pad").encode().expect_err("空地址"),
        Error::EmptyField { field: "address" }
    );
}

#[test]
fn request_rejects_nul_and_invalid_utf8_in_address() {
    assert_eq!(
        request_error(&frame(b"evil\x00host:1", b"")),
        Error::ContainsNul { field: "address" }
    );
    assert_eq!(
        request_error(&frame(&[0x61, 0x62, 0xFF], b"")),
        Error::InvalidUtf8 { field: "address" }
    );
    assert_eq!(
        request_error(&frame(&[0xE4, 0xB8], b"")),
        Error::InvalidUtf8 { field: "address" }
    );
    let idn = "例え.jp:8080";
    let bytes = frame(idn.as_bytes(), b"");
    let (decoded, used) = ConnectUdpRequest::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len());
    assert_eq!(decoded.address, idn);
    assert_eq!(decoded.encode().expect("编码"), bytes);

    assert_eq!(
        request("bad\u{0}host", b"")
            .encode()
            .expect_err("结构体 NUL"),
        Error::ContainsNul { field: "address" }
    );
}

#[test]
fn request_accepts_non_shortest_length_fields() {
    // 地址长度 15 写成 2 字节、padding 长度 3 写成 4 字节的非最短形式。
    let mut bytes = TYPE_BYTES.to_vec();
    bytes.extend_from_slice(&[0x40, 0x0F]);
    bytes.extend_from_slice(b"example.com:443");
    bytes.extend_from_slice(&[0x80, 0x00, 0x00, 0x03]);
    bytes.extend_from_slice(b"pad");
    let (decoded, used) = ConnectUdpRequest::decode(&bytes).expect("解码");
    assert_eq!(used, bytes.len(), "消耗长度含非最短前缀");
    assert_eq!(decoded, request("example.com:443", b"pad"));
    // 编码侧永远输出最短形式。
    assert_eq!(
        decoded.encode().expect("编码"),
        frame(b"example.com:443", b"pad")
    );
    // 定界版本同样接受非最短声明。
    assert_eq!(
        ConnectUdpRequest::decode_exact(&bytes).expect("定界解码"),
        request("example.com:443", b"pad")
    );
}

#[test]
fn request_decode_does_not_swallow_payload() {
    let bytes = frame(b"example.com:443", b"pad");
    let mut stream = bytes.clone();
    stream.extend_from_slice(b"\x00\x01later-datagram-body");
    let (decoded, used) = ConnectUdpRequest::decode(&stream).expect("解码");
    assert_eq!(used, bytes.len(), "只消耗帧本身");
    assert_eq!(decoded.address, "example.com:443");
    assert_eq!(
        &stream[used..],
        b"\x00\x01later-datagram-body",
        "帧后字节留给应用载荷"
    );

    // 相邻两帧可依次解析，消耗长度即下一帧起点。
    let second = frame(b"b:2", b"q");
    let mut two = bytes.clone();
    two.extend_from_slice(&second);
    let (first, first_used) = ConnectUdpRequest::decode(&two).expect("第一帧");
    assert_eq!(first_used, bytes.len());
    let (second_struct, second_used) =
        ConnectUdpRequest::decode(&two[first_used..]).expect("第二帧");
    assert_eq!(first_used + second_used, two.len(), "两帧首尾相接");
    assert_eq!(first, request("example.com:443", b"pad"));
    assert_eq!(second_struct, request("b:2", b"q"));
}

#[test]
fn request_decode_exact_rejects_length_mismatch() {
    // 外层声明的长度比消息实际长度多 1 字节：必须拒绝，不能吞掉尾部。
    let mut extra = frame(b"example.com:443", b"pad");
    extra.push(b'!');
    assert_eq!(
        ConnectUdpRequest::decode_exact(&extra).expect_err("长度不一致"),
        Error::LengthMismatch {
            declared: extra.len(),
            consumed: extra.len() - 1
        }
    );
    // 多出一整个后续帧同样拒绝。
    let mut two = frame(b"a:1", b"");
    two.extend_from_slice(&frame(b"b:2", b""));
    assert_eq!(
        ConnectUdpRequest::decode_exact(&two).expect_err("两帧concatenate"),
        Error::LengthMismatch {
            declared: two.len(),
            consumed: frame(b"a:1", b"").len()
        }
    );
    // 精确等长才通过。
    assert_eq!(
        ConnectUdpRequest::decode_exact(&frame(b"a:1", b"")).expect("定界解码"),
        request("a:1", b"")
    );
}

#[test]
fn request_encode_rejects_invalid_struct_fields() {
    let too_long = "a".repeat((MAX_ADDRESS_LENGTH + 1) as usize);
    assert_eq!(
        request(&too_long, b"").encode().expect_err("地址超限"),
        Error::TooLong {
            field: "address",
            len: 2049,
            max: MAX_ADDRESS_LENGTH
        }
    );
    assert_eq!(
        request("a:1", &vec![0x20; 4097])
            .encode()
            .expect_err("padding 超限"),
        Error::TooLong {
            field: "padding",
            len: 4097,
            max: MAX_PADDING_LENGTH
        }
    );
    // encoded_len 与 encode 判定一致。
    let req = request("a:1", b"xyz");
    assert_eq!(
        req.encoded_len().ok(),
        Some(req.encode().expect("编码").len())
    );
}

#[test]
fn request_rejects_oversized_length_fields_without_panicking() {
    for prefix in [
        [0x80, 0xFF, 0xFF, 0xFF].as_slice(),
        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF].as_slice(),
    ] {
        let mut bytes = TYPE_BYTES.to_vec();
        bytes.extend_from_slice(prefix);
        let len = prefix_value(prefix);
        assert_eq!(
            request_error(&bytes),
            Error::TooLong {
                field: "address",
                len,
                max: MAX_ADDRESS_LENGTH
            },
            "地址长度前缀 {prefix:02x?}"
        );

        let mut bytes = frame(b"a", &[]);
        bytes.truncate(2 + len_bytes(1).len() + 1);
        bytes.extend_from_slice(prefix);
        assert_eq!(
            request_error(&bytes),
            Error::TooLong {
                field: "padding",
                len,
                max: MAX_PADDING_LENGTH
            },
            "padding 长度前缀 {prefix:02x?}"
        );
    }
}

#[test]
fn request_errors_and_debug_do_not_leak_address_or_padding() {
    let secret = frame(b"private-target:1", b"sensitive-padding");
    let variants = [
        {
            let mut bytes = secret.clone();
            bytes[1] = 0x03; // 篡改类型字节
            bytes
        },
        secret[..10].to_vec(), // 截断地址体
        {
            let mut bytes = secret.clone();
            bytes[5] = 0x00; // 地址中注入 NUL
            bytes
        },
    ];
    for input in variants {
        let rendered = request_error(&input).to_string();
        assert!(!rendered.contains("private-target"), "{rendered}");
        assert!(!rendered.contains("sensitive-padding"), "{rendered}");
    }
    // Debug 只报长度。
    let rendered = format!("{:?}", request("private-target:1", b"sensitive-padding"));
    assert!(!rendered.contains("private-target"), "{rendered}");
    assert!(!rendered.contains("sensitive-padding"), "{rendered}");
    assert!(rendered.contains("address_len"), "{rendered}");
}
