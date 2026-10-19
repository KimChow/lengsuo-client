//! UDP-over-TCP v2 编解码测试：纯内存、逐字节对照参考线格式。
//! 基线 anytls-go fd6167a 的 `cmd/server/inbound_tcp.go`、`outbound_tcp.go`
//! 与 sing v0.5.1 `common/uot`（`ReadRequest`/`AddrParser`/`Conn.ReadFrom`）。
//! 本文件不涉及套接字；真实互通见 `tests/interop_udp.rs`（默认 `#[ignore]`）。
use lengsuo_anytls::stream::{
    is_udp_over_tcp_request, socks::SocksAddr, version_from_magic, Address, AddressFamily,
    Association, Datagram, StreamError, UdpAssociations, UdpVersion, UotRequest, MAGIC_ADDRESS_V1,
    MAGIC_ADDRESS_V2,
};

/// 参考 `uot.AddrParser` 的家族字节，**不是** SOCKS5 的 ATYP。
/// 这是最容易写错的一处，单独锁死。
#[test]
fn address_family_bytes_follow_uot_not_socks5() {
    assert_eq!(AddressFamily::Ipv4.to_byte(), 0x00);
    assert_eq!(AddressFamily::Ipv6.to_byte(), 0x01);
    assert_eq!(AddressFamily::Fqdn.to_byte(), 0x02);
    assert_eq!(AddressFamily::from_byte(0x00), Some(AddressFamily::Ipv4));
    assert_eq!(AddressFamily::from_byte(0x01), Some(AddressFamily::Ipv6));
    assert_eq!(AddressFamily::from_byte(0x02), Some(AddressFamily::Fqdn));
    assert_eq!(
        AddressFamily::from_byte(0x03),
        None,
        "SOCKS 的域名类型在此非法"
    );
    assert_eq!(
        AddressFamily::from_byte(0x04),
        None,
        "SOCKS 的 v6 类型在此非法"
    );
}

#[test]
fn uot_address_roundtrips_all_three_families() {
    let cases = [
        Address::Ipv4([127, 0, 0, 1], 53),
        Address::Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443),
        Address::Fqdn("example.com".into(), 8080),
    ];
    for address in cases {
        let encoded = address.encode().expect("可编码");
        let (decoded, consumed) = Address::decode(&encoded).expect("可解码");
        assert_eq!(decoded, address);
        assert_eq!(consumed, encoded.len());
    }
}

#[test]
fn uot_address_wire_bytes_are_exact() {
    let ipv4 = Address::Ipv4([1, 2, 3, 4], 0x1234).encode().unwrap();
    assert_eq!(ipv4, vec![0x00, 1, 2, 3, 4, 0x12, 0x34]);
    let fqdn = Address::Fqdn("a.b".into(), 7).encode().unwrap();
    assert_eq!(fqdn, vec![0x02, 3, b'a', b'.', b'b', 0x00, 0x07]);
}

#[test]
fn uot_address_rejects_empty_and_oversized_domains() {
    assert_eq!(
        Address::Fqdn(String::new(), 1).encode(),
        Err(StreamError::InvalidAddress)
    );
    assert_eq!(
        Address::Fqdn("x".repeat(256), 1).encode(),
        Err(StreamError::InvalidAddress)
    );
    // 零长域名在解码时也必须拒绝，避免消费 0 字节造成死循环。
    assert_eq!(
        Address::decode(&[0x02, 0, 0, 0]),
        Err(StreamError::InvalidAddress)
    );
}

#[test]
fn socks_address_uses_socks5_atyp_for_the_stream_header() {
    // 普通流首字节的目的地址是 SOCKS5 风格，与 UoT 报文的家族字节不同。
    let fqdn = SocksAddr::Fqdn(MAGIC_ADDRESS_V2.into(), 0)
        .encode()
        .unwrap();
    assert_eq!(fqdn[0], 0x03, "SOCKS5 域名类型");
    let (decoded, consumed) = SocksAddr::decode(&fqdn).unwrap();
    assert_eq!(decoded, SocksAddr::Fqdn(MAGIC_ADDRESS_V2.into(), 0));
    assert_eq!(consumed, fqdn.len());
    assert_eq!(
        SocksAddr::Ipv4([10, 0, 0, 1], 80).encode().unwrap(),
        vec![0x01, 10, 0, 0, 1, 0, 80]
    );
    assert_eq!(
        SocksAddr::Ipv6([0; 16], 1).encode().unwrap()[0],
        0x04,
        "SOCKS5 v6 类型"
    );
}

/// 参考 `uot.ReadRequest` 的字节：`isConnect(1B) | 地址 | 端口`。
/// 期望值取自 Go 侧 `uot.EncodeRequest` 的真实十六进制输出：
/// `isConnect=true, 127.0.0.1:53` → `01017f0000010035`（注意家族字节是 SOCKS5 的 0x01）。
#[test]
fn uot_request_header_matches_reference_bytes_from_go() {
    let request = UotRequest {
        is_connect: true,
        destination: SocksAddr::Ipv4([127, 0, 0, 1], 53),
    };
    let encoded = request.encode().unwrap();
    assert_eq!(
        encoded,
        vec![0x01, 0x01, 127, 0, 0, 1, 0, 53],
        "Go 输出 01017f0000010035"
    );
    let (decoded, consumed) = UotRequest::decode(&encoded).unwrap();
    assert_eq!(decoded, request);
    assert_eq!(consumed, encoded.len());

    let non_connect = UotRequest {
        is_connect: false,
        destination: SocksAddr::Fqdn("dns.example".into(), 1),
    };
    let encoded = non_connect.encode().unwrap();
    assert_eq!(
        encoded,
        vec![
            0x00, 0x03, 0x0b, b'd', b'n', b's', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
            1
        ],
        "Go 输出 00030b646e732e6578616d706c650001"
    );
    assert_eq!(UotRequest::decode(&encoded).unwrap().0, non_connect);
}

/// 请求头用 SOCKS5 ATYP，报文地址用 UoT 家族字节——两者必须能同时正确解码，
/// 且同一地址在两处的首字节不同。
#[test]
fn request_and_datagram_use_different_address_families() {
    let request = UotRequest {
        is_connect: false,
        destination: SocksAddr::Ipv4([1, 2, 3, 4], 5),
    };
    let datagram = Datagram {
        address: Some(Address::Ipv4([1, 2, 3, 4], 5)),
        payload: vec![],
    };
    assert_eq!(request.encode().unwrap()[1], 0x01, "SOCKS5 IPv4");
    assert_eq!(datagram.encode(false).unwrap()[0], 0x00, "UoT IPv4");
}

#[test]
fn uot_request_rejects_non_boolean_is_connect() {
    assert_eq!(
        UotRequest::decode(&[0x02, 0x01, 1, 2, 3, 4, 0, 53]),
        Err(StreamError::InvalidRequest("isConnect 非 0/1"))
    );
}

/// 参考 `Conn.ReadFrom`/`WriteTo` 的报文：`[地址] | 长度(2B BE) | 载荷`。
/// 注意：**没有** `isize` 前缀，长度只覆盖载荷。
#[test]
fn datagram_wire_bytes_are_exact_in_connect_mode() {
    let datagram = Datagram {
        address: None,
        payload: b"ping".to_vec(),
    };
    let encoded = datagram.encode(true).unwrap();
    assert_eq!(encoded, vec![0x00, 0x04, b'p', b'i', b'n', b'g']);
    let (decoded, consumed) = Datagram::decode(&encoded, true).unwrap();
    assert_eq!(decoded, datagram);
    assert_eq!(consumed, encoded.len());
}

#[test]
fn datagram_wire_bytes_are_exact_in_non_connect_mode() {
    let datagram = Datagram {
        address: Some(Address::Ipv4([8, 8, 8, 8], 53)),
        payload: b"ab".to_vec(),
    };
    let encoded = datagram.encode(false).unwrap();
    assert_eq!(
        encoded,
        vec![0x00, 8, 8, 8, 8, 0, 53, 0x00, 0x02, b'a', b'b']
    );
    let (decoded, consumed) = Datagram::decode(&encoded, false).unwrap();
    assert_eq!(decoded, datagram);
    assert_eq!(consumed, encoded.len());
}

#[test]
fn datagram_mode_mismatch_is_rejected_in_both_directions() {
    let with_address = Datagram {
        address: Some(Address::Fqdn("a.example".into(), 9)),
        payload: vec![],
    };
    assert_eq!(
        with_address.encode(true),
        Err(StreamError::UnexpectedAddress),
        "connect 模式不得携带地址"
    );
    let without_address = Datagram {
        address: None,
        payload: vec![],
    };
    assert_eq!(
        without_address.encode(false),
        Err(StreamError::MissingAddress),
        "非 connect 模式必须携带地址"
    );
}

/// 零长载荷是合法的 UDP 空报文，必须能与「截断」区分开。
#[test]
fn zero_length_payload_is_a_valid_empty_datagram() {
    let datagram = Datagram {
        address: Some(Address::Ipv4([127, 0, 0, 1], 9)),
        payload: vec![],
    };
    let encoded = datagram.encode(false).unwrap();
    let (decoded, consumed) = Datagram::decode(&encoded, false).unwrap();
    assert_eq!(decoded, datagram);
    assert_eq!(consumed, 7 + 2);
}

#[test]
fn truncated_datagrams_report_incomplete_not_silent_success() {
    let encoded = Datagram {
        address: Some(Address::Fqdn("host.test".into(), 53)),
        payload: b"payload".to_vec(),
    }
    .encode(false)
    .unwrap();
    for cut in 0..encoded.len() {
        assert_eq!(
            Datagram::decode(&encoded[..cut], false),
            Err(StreamError::Incomplete),
            "截断到 {cut} 字节必须报不完整"
        );
    }
    assert!(Datagram::decode(&encoded, false).is_ok());
}

#[test]
fn oversized_payload_is_rejected_before_encoding() {
    let datagram = Datagram {
        address: None,
        payload: vec![0u8; u16::MAX as usize + 1],
    };
    assert_eq!(datagram.encode(true), Err(StreamError::Oversized));
}

/// 多个报文首尾相接时逐个消费，偏移必须精确推进。
#[test]
fn consecutive_datagrams_are_consumed_exactly() {
    let association = Association::new(
        UdpVersion::V2,
        UotRequest {
            is_connect: false,
            destination: SocksAddr::Ipv4([0, 0, 0, 0], 0),
        },
    );
    let mut wire = Vec::new();
    let payloads: Vec<Vec<u8>> = vec![b"a".to_vec(), vec![], b"ccc".to_vec()];
    for payload in &payloads {
        wire.extend_from_slice(
            &Datagram {
                address: Some(Address::Ipv4([10, 1, 2, 3], 1000)),
                payload: payload.clone(),
            }
            .encode(false)
            .unwrap(),
        );
    }
    let mut offset = 0;
    for expected in &payloads {
        let (datagram, consumed) = association.decode_datagram(&wire[offset..]).unwrap();
        assert_eq!(&datagram.payload, expected);
        assert_eq!(datagram.address, Some(Address::Ipv4([10, 1, 2, 3], 1000)));
        offset += consumed;
    }
    assert_eq!(offset, wire.len(), "必须恰好消费完，无残留也无越界");
}

#[test]
fn association_connect_mode_omits_address_on_every_datagram() {
    let association = Association::new(
        UdpVersion::V2,
        UotRequest {
            is_connect: true,
            destination: SocksAddr::Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2], 5353),
        },
    );
    assert!(!association.carries_address());
    let encoded = association
        .encode_datagram(&Datagram {
            address: None,
            payload: b"x".to_vec(),
        })
        .unwrap();
    assert_eq!(
        encoded,
        vec![0x00, 0x01, b'x'],
        "connect 模式只有长度与载荷"
    );
    assert_eq!(association.request.destination.port(), 5353);
}

/// 参考 `inbound_tcp.go` 的 `strings.Contains(destination, "udp-over-tcp.arpa")`。
#[test]
fn magic_address_detection_matches_reference_contains_rule() {
    assert!(is_udp_over_tcp_request(MAGIC_ADDRESS_V2));
    assert!(is_udp_over_tcp_request(MAGIC_ADDRESS_V1));
    assert!(is_udp_over_tcp_request("prefix.sp.v2.udp-over-tcp.arpa"));
    assert!(is_udp_over_tcp_request("udp-over-tcp.arpa"));
    assert!(!is_udp_over_tcp_request("example.com"));
    assert!(!is_udp_over_tcp_request(""));
    // 参考用 Contains，大小写敏感；此处保持同一行为。
    assert!(!is_udp_over_tcp_request("SP.V2.UDP-OVER-TCP.ARPA"));
}

#[test]
fn magic_address_selects_the_protocol_version_like_reference() {
    assert_eq!(version_from_magic(MAGIC_ADDRESS_V2), UdpVersion::V2);
    assert_eq!(version_from_magic(MAGIC_ADDRESS_V1), UdpVersion::V1);
    // 参考 `RequestDestination` 对未知魔法域 default 落到 LegacyVersion。
    assert_eq!(version_from_magic("sp.udp-over-tcp.arpa"), UdpVersion::V1);
    assert_eq!(UdpVersion::V2.to_byte(), 2);
    assert_eq!(UdpVersion::from_byte(1), Some(UdpVersion::V1));
    assert_eq!(UdpVersion::from_byte(3), None);
    assert_eq!(UdpVersion::V2.magic_address(), MAGIC_ADDRESS_V2);
}

#[test]
fn associations_reject_zero_duplicate_and_unknown_stream_ids() {
    let mut associations = UdpAssociations::new();
    assert!(associations.is_empty());
    let association = Association::new(
        UdpVersion::V2,
        UotRequest {
            is_connect: true,
            destination: SocksAddr::Ipv4([127, 0, 0, 1], 53),
        },
    );
    assert_eq!(
        associations.insert(0, association.clone()),
        Err(StreamError::InvalidId("UDP 关联流编号为零"))
    );
    associations.insert(5, association.clone()).expect("登记");
    assert_eq!(associations.len(), 1);
    assert_eq!(
        associations.insert(5, association),
        Err(StreamError::DuplicateAssociation(5))
    );
    assert_eq!(
        associations.remove(6),
        Err(StreamError::UnknownAssociation(6))
    );
    assert!(associations.remove(5).expect("移除").request.is_connect);
    assert!(associations.is_empty());
}
