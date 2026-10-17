//! Hysteria2 UDP 报文（`UDPMessage`）字节级参考向量测试。
//!
//! 黄金字节由本机 Python `struct.pack` 独立生成（布局：BE32 sessionID +
//! BE16 packetID + u8 fragID + u8 fragCount + QUIC varint 地址长 + 地址原字节
//! 以及 data），不是从本 crate 的编码结果回填；参考实现为 apernet/hysteria 完整
//! commit `ca8fbd874fd6ca82413948de6dc5924405e103e1`，
//! `core/internal/protocol/proxy.go` 第 151-225 行的 `Serialize` / `ParseUDPMessage`。
//!
//! 只覆盖消息 codec 本身：不涉及 QUIC、HTTP/3、datagram 中继或分片重组。
//! 本文件只证明与 Go 字节布局在构造样本上一致，不证明与原生服务端的真实互通。

use lengsuo_hysteria::udp::{UdpMessage, MAX_ADDRESS_LENGTH};
use lengsuo_hysteria::Error;

/// 头部 8 字节：session 0x11223344、packet 0x5566、fragID 1、fragCount 3。
const HEADER: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x03];

/// 地址 `198.51.100.7:23456`（18 字节，TEST-NET 假地址）+ 数据 `udp!`。
const ADDRESS: &[u8] = b"198.51.100.7:23456";
const DATA: &[u8] = b"udp!";

/// Python: struct.pack(">IHBB",0x11223344,0x5566,1,3)+varint(18)+addr+b"udp!"
const REF_MESSAGE: [u8; 31] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x03, 0x12, 0x31, 0x39, 0x38, 0x2E, 0x35, 0x31, 0x2E,
    0x31, 0x30, 0x30, 0x2E, 0x37, 0x3A, 0x32, 0x33, 0x34, 0x35, 0x36, 0x75, 0x64, 0x70, 0x21,
];

/// 同上，但地址长度用 2 字节非最短 varint（`0x40 0x12`），quicvarint.Read 接受。
const REF_NONMIN2: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x03, 0x40, 0x12, 0x31, 0x39, 0x38, 0x2E, 0x35, 0x31,
    0x2E, 0x31, 0x30, 0x30, 0x2E, 0x37, 0x3A, 0x32, 0x33, 0x34, 0x35, 0x36, 0x75, 0x64, 0x70, 0x21,
];

/// 同上，地址长度用 4 字节非最短 varint（`0x80 0x00 0x00 0x12`）。
const REF_NONMIN4: [u8; 34] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x03, 0x80, 0x00, 0x00, 0x12, 0x31, 0x39, 0x38, 0x2E,
    0x35, 0x31, 0x2E, 0x31, 0x30, 0x30, 0x2E, 0x37, 0x3A, 0x32, 0x33, 0x34, 0x35, 0x36, 0x75, 0x64,
    0x70, 0x21,
];

/// 地址含非法 UTF-8 与 NUL 的原字节（Go 只当字节切片）：0xFF 0x00 0x80 0x3A，数据 0x00。
const NONUTF8_MESSAGE: [u8; 14] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0xFF, 0x00, 0x80, 0x3A, 0x00,
];

/// 地址长度 varint 为 0（Go: "invalid address length"）。
const EMPTY_ADDRESS: [u8; 14] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x03, 0x00, 0x41, 0x75, 0x64, 0x70, 0x21,
];

/// 地址长度用 2 字节非最短 varint 表达 0，同样必须拒绝。
const EMPTY_ADDRESS_NONMIN: [u8; 15] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x03, 0x40, 0x00, 0x41, 0x75, 0x64, 0x70, 0x21,
];

/// 声明地址长度 2049（> MaxMessageLength 2048），varint `0x48 0x01`。
const ADDR_TOO_LONG: [u8; 10] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x03, 0x48, 0x01];

/// 地址长度 varint 只给 1/3/5 字节，不足以完成该前缀。
const TRUNC_VARINT2: [u8; 9] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x03, 0x40];
const TRUNC_VARINT4: [u8; 11] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x03, 0x80, 0x00, 0x00,
];
const TRUNC_VARINT8: [u8; 13] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x03, 0xC0, 0x00, 0x00, 0x00, 0x00,
];

fn reference_message<'a>() -> UdpMessage<'a> {
    UdpMessage {
        session_id: 0x1122_3344,
        packet_id: 0x5566,
        fragment_id: 1,
        fragment_count: 3,
        address: ADDRESS,
        data: DATA,
    }
}

fn message<'a>(address: &'a [u8], data: &'a [u8]) -> UdpMessage<'a> {
    UdpMessage {
        session_id: 0,
        packet_id: 0,
        fragment_id: 0,
        fragment_count: 1,
        address,
        data,
    }
}

/// 由头部 + varint 地址长 + 地址 + 数据拼一条最小 varint 消息。
fn build(addr_len: u64, address: &[u8], data: &[u8]) -> Vec<u8> {
    let mut bytes = HEADER.to_vec();
    lengsuo_hysteria::varint::append(addr_len, &mut bytes).expect("varint 写入");
    bytes.extend_from_slice(address);
    bytes.extend_from_slice(data);
    bytes
}

#[test]
fn decodes_python_reference_fields() {
    let parsed = UdpMessage::decode(&REF_MESSAGE).expect("参考样本必须可解");
    assert_eq!(parsed.session_id, 0x1122_3344);
    assert_eq!(parsed.packet_id, 0x5566);
    assert_eq!(parsed.fragment_id, 1);
    assert_eq!(parsed.fragment_count, 3);
    assert_eq!(parsed.address, ADDRESS);
    assert_eq!(parsed.data, DATA);
}

#[test]
fn encode_matches_python_reference_bytes() {
    let encoded = reference_message().encode().expect("编码成功");
    assert_eq!(encoded, REF_MESSAGE.to_vec());
    assert_eq!(encoded.len(), REF_MESSAGE.len());
    assert_eq!(
        reference_message().encoded_len().expect("长度一致"),
        REF_MESSAGE.len()
    );
}

#[test]
fn accepts_non_minimal_varint_forms() {
    for sample in [&REF_NONMIN2 as &[u8], &REF_NONMIN4] {
        let parsed = UdpMessage::decode(sample).expect("非最短 varint 必须接受");
        assert_eq!(parsed.session_id, 0x1122_3344);
        assert_eq!(parsed.packet_id, 0x5566);
        assert_eq!(parsed.fragment_id, 1);
        assert_eq!(parsed.fragment_count, 3);
        assert_eq!(parsed.address, ADDRESS);
        assert_eq!(parsed.data, DATA);
        // 编码侧永远输出最短形式，不复制非最短前缀。
        assert_eq!(parsed.encode().expect("重编码"), REF_MESSAGE.to_vec());
    }
}

#[test]
fn keeps_raw_non_utf8_address_bytes_and_nul() {
    let parsed = UdpMessage::decode(&NONUTF8_MESSAGE).expect("地址按原字节处理");
    assert_eq!(parsed.address, &[0xFF, 0x00, 0x80, 0x3A]);
    assert_eq!(parsed.data, &[0x00]);
    assert_eq!(parsed.session_id, 0);
    assert_eq!(parsed.fragment_count, 1);
    assert_eq!(parsed.encode().expect("回合编码"), NONUTF8_MESSAGE.to_vec());
    // 不做 UTF-8 转换：非法序列仍保持原字节数。
    assert!(std::str::from_utf8(parsed.address).is_err());
}

#[test]
fn decode_borrows_input_without_copying() {
    let parsed = UdpMessage::decode(&REF_MESSAGE).expect("解码成功");
    assert_eq!(
        parsed.address.as_ptr(),
        REF_MESSAGE[9..27].as_ptr(),
        "地址必须借用输入缓冲"
    );
    assert_eq!(parsed.data.as_ptr(), REF_MESSAGE[27..].as_ptr());
}

#[test]
fn header_truncation_reports_eight_bytes_needed() {
    for got in 0..HEADER.len() {
        let error = UdpMessage::decode(&REF_MESSAGE[..got]).expect_err("头部不足必须失败");
        assert_eq!(error, Error::Truncated { need: 8, got }, "{got} 字节时");
    }
    // 恰好 8 字节：地址长度 varint 缺失。
    assert_eq!(
        UdpMessage::decode(&HEADER).expect_err("无 varint 必须失败"),
        Error::Truncated { need: 9, got: 8 }
    );
}

#[test]
fn varint_truncation_reports_absolute_need() {
    assert_eq!(
        UdpMessage::decode(&TRUNC_VARINT2).expect_err("2 字节 varint 不足"),
        Error::Truncated { need: 10, got: 9 }
    );
    assert_eq!(
        UdpMessage::decode(&TRUNC_VARINT4).expect_err("4 字节 varint 不足"),
        Error::Truncated { need: 12, got: 11 }
    );
    assert_eq!(
        UdpMessage::decode(&TRUNC_VARINT8).expect_err("8 字节 varint 不足"),
        Error::Truncated { need: 16, got: 13 }
    );
}

#[test]
fn rejects_empty_address_like_go_parser() {
    assert_eq!(
        UdpMessage::decode(&EMPTY_ADDRESS).expect_err("空地址非法"),
        Error::EmptyField { field: "address" }
    );
    assert_eq!(
        UdpMessage::decode(&EMPTY_ADDRESS_NONMIN).expect_err("非最短 0 同样非法"),
        Error::EmptyField { field: "address" }
    );
    assert_eq!(
        message(b"", DATA).encode().expect_err("编码也拒绝空地址"),
        Error::EmptyField { field: "address" }
    );
}

#[test]
fn rejects_address_length_above_max_on_both_paths() {
    assert_eq!(
        UdpMessage::decode(&ADDR_TOO_LONG).expect_err("2049 > 上限"),
        Error::TooLong {
            field: "address",
            len: 2049,
            max: MAX_ADDRESS_LENGTH
        }
    );
    let long = vec![b'a'; (MAX_ADDRESS_LENGTH + 1) as usize];
    let mut oversized = message(&long, DATA);
    oversized.session_id = 1;
    assert_eq!(
        oversized.encode().expect_err("编码拒绝超长地址"),
        Error::TooLong {
            field: "address",
            len: 2049,
            max: MAX_ADDRESS_LENGTH
        }
    );
    assert_eq!(
        oversized.encoded_len().expect_err("长度计算同样拒绝"),
        Error::TooLong {
            field: "address",
            len: 2049,
            max: MAX_ADDRESS_LENGTH
        }
    );
}

#[test]
fn accepts_address_length_exactly_at_max() {
    let long = vec![b'a'; MAX_ADDRESS_LENGTH as usize];
    let bytes = build(MAX_ADDRESS_LENGTH, &long, DATA);
    let parsed = UdpMessage::decode(&bytes).expect("2048 字节地址可解");
    assert_eq!(parsed.address.len(), MAX_ADDRESS_LENGTH as usize);
    assert_eq!(parsed.data, DATA);
    assert_eq!(parsed.encode().expect("重编码"), bytes);
}

#[test]
fn requires_at_least_one_data_byte() {
    // 地址完整、零数据字节：Go 用 `len(bs) <= lAddr` 拒绝。
    let addr_only = build(ADDRESS.len() as u64, ADDRESS, b"");
    assert_eq!(addr_only.len(), 27);
    assert_eq!(
        UdpMessage::decode(&addr_only).expect_err("无数据字节必须失败"),
        Error::Truncated { need: 28, got: 27 }
    );
    // 地址本体被截断：同一条规则，need 指向地址末端 + 1 个数据字节。
    assert_eq!(
        UdpMessage::decode(&REF_MESSAGE[..20]).expect_err("地址不足"),
        Error::Truncated { need: 28, got: 20 }
    );
}

#[test]
fn encode_rejects_empty_data() {
    assert_eq!(
        message(ADDRESS, b"").encode().expect_err("空数据非法"),
        Error::EmptyField { field: "data" }
    );
    assert_eq!(
        message(ADDRESS, b"").encoded_len().expect_err("空数据非法"),
        Error::EmptyField { field: "data" }
    );
}

#[test]
fn fragment_fields_are_not_restricted_by_codec() {
    // 重组层负责 fragID/fragCount 语义；codec 只透传 0..=255。
    for (id, count) in [(0_u8, 0_u8), (255, 0), (255, 255), (9, 2)] {
        let mut msg = message(ADDRESS, DATA);
        msg.fragment_id = id;
        msg.fragment_count = count;
        let bytes = msg.encode().expect("任意 frag 字段可编码");
        let parsed = UdpMessage::decode(&bytes).expect("任意 frag 字段可解码");
        assert_eq!(parsed.fragment_id, id);
        assert_eq!(parsed.fragment_count, count);
    }
}

#[test]
fn id_fields_accept_full_range() {
    let mut msg = message(ADDRESS, DATA);
    msg.session_id = u32::MAX;
    msg.packet_id = u16::MAX;
    let bytes = msg.encode().expect("全 1 id 可编码");
    // 头字段是固定宽度大端整数，不是 varint：0xFF 前缀字节不影响解析。
    assert_eq!(
        &bytes[..8],
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01]
    );
    let parsed = UdpMessage::decode(&bytes).expect("解码");
    assert_eq!(parsed.session_id, u32::MAX);
    assert_eq!(parsed.packet_id, u16::MAX);
    assert_eq!(parsed.address, ADDRESS);
}

#[test]
fn data_field_is_greedy_rest_of_message() {
    let extra = [0xDE, 0xAD, 0xBE, 0xEF];
    let mut bytes = REF_MESSAGE.to_vec();
    bytes.extend_from_slice(&extra);
    let parsed = UdpMessage::decode(&bytes).expect("尾部字节属于数据");
    let mut expected = DATA.to_vec();
    expected.extend_from_slice(&extra);
    assert_eq!(parsed.data, expected);
    assert_eq!(parsed.encode().expect("回合"), bytes);
}

#[test]
fn minimal_varint_widths_across_boundaries() {
    // 地址长度 63/64/16383 边界决定 varint 宽度（上限 2048 内可达 63/64）。
    for (len, varint_bytes) in [(1_usize, 1_usize), (63, 1), (64, 2), (2048, 2)] {
        let address = vec![b'b'; len];
        let msg = message(&address, DATA);
        assert_eq!(
            msg.encoded_len().expect("长度"),
            8 + varint_bytes + len + DATA.len(),
            "地址长度 {len}"
        );
        let bytes = msg.encode().expect("编码");
        assert_eq!(UdpMessage::decode(&bytes).expect("解码").address, address);
    }
}

#[test]
fn debug_output_omits_payload_bytes() {
    let dbg = format!("{:?}", reference_message());
    assert!(dbg.contains("18"), "应输出现有长度元数据：{dbg}");
    assert!(!dbg.contains("198.51.100.7"), "不得输出地址内容");
    assert!(!dbg.contains("udp"), "不得输出数据内容");
    assert!(dbg.contains("4291962692") || dbg.contains("0x11223344") || dbg.contains("session_id"));
}

#[test]
fn roundtrip_is_byte_identical_for_minimal_messages() {
    let samples = [
        build(1, b".", b"\x00"),
        build(ADDRESS.len() as u64, ADDRESS, b"single byte payload"),
        NONUTF8_MESSAGE.to_vec(),
    ];
    for sample in &samples {
        let parsed = UdpMessage::decode(sample).expect("样本可解");
        assert_eq!(&parsed.encode().expect("编码"), sample, "{sample:?}");
    }
}
