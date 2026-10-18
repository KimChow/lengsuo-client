//! Hysteria2 `UDPMessage` 黄金向量：由参考 Go 代码 `proxy.go` 的 `UDPMessage.Serialize`
//! （commit `ca8fbd874fd6ca82413948de6dc5924405e103e1`，第 151-225 行）逐字抄录实现
//! 实跑生成，非 Python 自造样本。
//!
//! 验证方式：对每个参考输出字节串，断言
//! 1. `UdpMessage::decode(参考字节)` 还原出与 Go 完全一致的字段；
//! 2. 由这些字段重新 `encode()` 逐字节等于参考输出（Rust<->Go 字节对等）。
//!
//! 覆盖 IPv4 / IPv6 / 域名三类地址，以及地址长度 63/64/2048 边界（varint 宽度切换）。
//! 不覆盖 QUIC、HTTP/3、中继、分片重组；不宣称与 apernet/hysteria 真实服务互通。

use lengsuo_hysteria::udp::UdpMessage;

/// 参考 Serialize 输出（Go 实跑）：session 0x11223344, packet 0x5566, fragID 1,
/// fragCount 3, 地址 "198.51.100.7:23456" (18B), data "udp!" (4B)。长度 31。
const GO_IPV4: &[u8] = &[
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x03, 0x12, 0x31, 0x39, 0x38, 0x2e, 0x35, 0x31, 0x2e,
    0x31, 0x30, 0x30, 0x2e, 0x37, 0x3a, 0x32, 0x33, 0x34, 0x35, 0x36, 0x75, 0x64, 0x70, 0x21,
];

/// 地址 "[2001:db8::1]:443" (17B), data "hello" (5B)。长度 31。
const GO_IPV6: &[u8] = &[
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x01, 0x03, 0x11, 0x5b, 0x32, 0x30, 0x30, 0x31, 0x3a, 0x64,
    0x62, 0x38, 0x3a, 0x3a, 0x31, 0x5d, 0x3a, 0x34, 0x34, 0x33, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
];

/// 地址 "example.com:53" (14B), data "query" (5B)。长度 28。
const GO_DOMAIN: &[u8] = &[
    0x0a, 0x0b, 0x0c, 0x0d, 0x12, 0x34, 0x00, 0x01, 0x0e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x2e, 0x63, 0x6f, 0x6d, 0x3a, 0x35, 0x33, 0x71, 0x75, 0x65, 0x72, 0x79,
];

/// session u32::MAX, packet u16::MAX, fragID 255, fragCount 255,
/// 地址 "1.2.3.4:5" (9B), data "z" (1B)。长度 19。
const GO_FULL_IDS: &[u8] = &[
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x09, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34,
    0x3a, 0x35, 0x7a,
];

/// 地址含非法 UTF-8 与 NUL 原字节 (0xFF 0x00 0x80 0x3A), data 0x00。长度 14。
const GO_NONUTF8: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0xff, 0x00, 0x80, 0x3a, 0x00,
];

#[allow(clippy::too_many_arguments)]
fn check(name: &str, go: &[u8], sid: u32, pid: u16, fid: u8, fcnt: u8, addr: &[u8], data: &[u8]) {
    let parsed = UdpMessage::decode(go).expect(name);
    assert_eq!(parsed.session_id, sid, "{name}: session_id");
    assert_eq!(parsed.packet_id, pid, "{name}: packet_id");
    assert_eq!(parsed.fragment_id, fid, "{name}: fragment_id");
    assert_eq!(parsed.fragment_count, fcnt, "{name}: fragment_count");
    assert_eq!(parsed.address, addr, "{name}: address");
    assert_eq!(parsed.data, data, "{name}: data");
    let rebuilt = UdpMessage {
        session_id: sid,
        packet_id: pid,
        fragment_id: fid,
        fragment_count: fcnt,
        address: addr,
        data,
    }
    .encode()
    .expect(name);
    assert_eq!(
        rebuilt,
        go.to_vec(),
        "{name}: encode byte-parity with Go reference"
    );
}

#[test]
fn go_reference_ipv4_vector() {
    check(
        "ipv4",
        GO_IPV4,
        0x1122_3344,
        0x5566,
        1,
        3,
        b"198.51.100.7:23456",
        b"udp!",
    );
}

#[test]
fn go_reference_ipv6_vector() {
    check(
        "ipv6",
        GO_IPV6,
        0x1122_3344,
        0x5566,
        1,
        3,
        b"[2001:db8::1]:443",
        b"hello",
    );
}

#[test]
fn go_reference_domain_vector() {
    check(
        "domain",
        GO_DOMAIN,
        0x0A0B_0C0D,
        0x1234,
        0,
        1,
        b"example.com:53",
        b"query",
    );
}

#[test]
fn go_reference_full_range_ids_vector() {
    check(
        "full_ids",
        GO_FULL_IDS,
        u32::MAX,
        u16::MAX,
        255,
        255,
        b"1.2.3.4:5",
        b"z",
    );
}

#[test]
fn go_reference_nonutf8_address_vector() {
    check(
        "nonutf8",
        GO_NONUTF8,
        0,
        0,
        0,
        1,
        &[0xFF, 0x00, 0x80, 0x3A],
        &[0x00],
    );
}

#[test]
fn go_reference_address_length_boundaries() {
    // 地址长度 63/64/2048：varint 宽度 1->2 切换，与参考 Serialize 长度一致。
    for (len, expected_total) in [(63_usize, 73_usize), (64, 75), (2048, 2059)] {
        let address = vec![0u8; len];
        let msg = UdpMessage {
            session_id: 1,
            packet_id: 1,
            fragment_id: 0,
            fragment_count: 1,
            address: &address,
            data: b"d",
        };
        let encoded = msg.encode().expect("encode");
        assert_eq!(encoded.len(), expected_total, "addr len {len} total");
        let parsed = UdpMessage::decode(&encoded).expect("decode");
        assert_eq!(parsed.address.len(), len);
        assert_eq!(parsed.data, b"d");
    }
}
