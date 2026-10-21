//! 回归护栏：datagram 模式 mismatch 判据不得被本卡的篡改用例破坏。
//!
//! 审计 `docs/audit-all1.md` §3 记录 AnyTLS 篡改格原先「仅 datagram mode
//! mismatch」——即当时唯一的篡改证据就是本模块这组判据。
//! 本卡补齐其余四类篡改后，**必须**保留这组既有判据（任务书第 6 条）。
//!
//! 判据位置：`src/stream.rs:295-309`（`Datagram::encode` 的模式一致性检查）
//! 与 `src/stream.rs:312-320`（`Datagram::decode` 按模式决定是否带地址）。
//! 参考 anytls-go 用 sing 的 `common/uot`：请求头 `isConnect` 决定后续报文
//! 是否携带地址（`cmd/server/outbound_tcp.go:37-52` 的 `uot.ReadRequest`
//! 与 `uot.NewConn`）。
#![allow(dead_code)]

use lengsuo_anytls::socks::SocksAddr;
use lengsuo_anytls::stream::{Address, Association, Datagram, StreamError, UdpVersion, UotRequest};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(2);

/// connect 模式不得携带地址；非 connect 模式必须携带地址。两个方向都要拒。
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

/// 模式一致时编码必须成功，且解码后逐字节还原（判据本身仍有效）。
#[test]
fn datagram_mode_consistent_round_trip_still_works() {
    let connect = Datagram {
        address: None,
        payload: b"ping".to_vec(),
    };
    let encoded = connect.encode(true).expect("connect 模式应可编码");
    let (decoded, consumed) = Datagram::decode(&encoded, true).expect("connect 模式应可解码");
    assert_eq!(decoded, connect);
    assert_eq!(consumed, encoded.len());

    let non_connect = Datagram {
        address: Some(Address::Ipv4([8, 8, 8, 8], 53)),
        payload: b"ab".to_vec(),
    };
    let encoded = non_connect.encode(false).expect("非 connect 模式应可编码");
    let (decoded, consumed) = Datagram::decode(&encoded, false).expect("非 connect 模式应可解码");
    assert_eq!(decoded, non_connect);
    assert_eq!(consumed, encoded.len());
}

/// **模式是会话级协商属性**：关联（`Association`）始终用协商好的模式编解码，
/// 因此产品路径上不可能出现模式错配。
///
/// ⚠️ 口径边界（**如实记录**）：`Datagram::decode(bytes, is_connect)` 这个
/// **低层自由函数**本身**不**校验模式——给错模式会静默错位解析出别的载荷。
/// 这**不是**本仓的缺陷：模式在会话建立时协商一次，参考 anytls-go 用 sing 的
/// `common/uot` 也是同一做法（`cmd/server/outbound_tcp.go:37-52`：
/// `uot.ReadRequest` 读一次请求头，`uot.NewConn(conn, *request)` 之后按该
/// 模式解析所有报文，**不做逐报文的模式校验**）。
/// 本仓多一层 `Association`（`src/stream.rs:341-365`）把协商模式固化在会话对象上，
/// 属**更严**：产品路径根本拿不到「错模式」这个输入。
///
/// 该边界在 `docs/anytls-tamper.md` 的「帧层判据边界」条里如实登记。
#[test]
fn datagram_association_always_uses_its_negotiated_mode() {
    // 非 connect 关联：报文带地址。
    let association = Association::new(
        UdpVersion::V2,
        UotRequest {
            is_connect: false,
            destination: SocksAddr::Ipv4([8, 8, 8, 8], 53),
        },
    );
    assert!(association.carries_address(), "非 connect 关联应携带地址");
    let datagram = Datagram {
        address: Some(Address::Ipv4([1, 2, 3, 4], 5)),
        payload: b"ping".to_vec(),
    };
    let encoded = association
        .encode_datagram(&datagram)
        .expect("非 connect 关联应可编码带地址报文");
    let (decoded, consumed) = association
        .decode_datagram(&encoded)
        .expect("非 connect 关联应可解码");
    assert_eq!(decoded, datagram, "协商模式下逐字节还原");
    assert_eq!(consumed, encoded.len());
    // 同一关联里，connect 模式的报文（无地址）必须被编码侧拒绝。
    let no_address = Datagram {
        address: None,
        payload: b"ping".to_vec(),
    };
    assert_eq!(
        association.encode_datagram(&no_address),
        Err(StreamError::MissingAddress),
        "关联的协商模式不得被单条报文改写"
    );

    // connect 关联：报文不带地址。
    let association = Association::new(
        UdpVersion::V2,
        UotRequest {
            is_connect: true,
            destination: SocksAddr::Ipv4([8, 8, 8, 8], 53),
        },
    );
    assert!(!association.carries_address(), "connect 关联不应携带地址");
    let datagram = Datagram {
        address: None,
        payload: b"ping".to_vec(),
    };
    let encoded = association
        .encode_datagram(&datagram)
        .expect("connect 关联应可编码无地址报文");
    let (decoded, consumed) = association
        .decode_datagram(&encoded)
        .expect("connect 关联应可解码");
    assert_eq!(decoded, datagram, "协商模式下逐字节还原");
    assert_eq!(consumed, encoded.len());
    // 同一关联里，非 connect 模式的报文（带地址）必须被编码侧拒绝。
    let with_address = Datagram {
        address: Some(Address::Ipv4([1, 2, 3, 4], 5)),
        payload: b"ping".to_vec(),
    };
    assert_eq!(
        association.encode_datagram(&with_address),
        Err(StreamError::UnexpectedAddress),
        "关联的协商模式不得被单条报文改写"
    );
}

/// UoT 请求头的 `is_connect` 非 0/1 必须被拒绝（防止静默产生歧义字节）。
#[test]
fn uot_request_rejects_non_boolean_is_connect() {
    assert_eq!(
        UotRequest::decode(&[0x02, 0x01, 1, 2, 3, 4, 0, 53]),
        Err(StreamError::InvalidRequest("isConnect 非 0/1"))
    );
}

/// 请求头与报文的地址家族字节不同（两套编码），本仓必须各走各的映射。
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
    assert_eq!(
        request.encode().expect("请求头应可编码")[1],
        0x01,
        "SOCKS5 IPv4"
    );
    assert_eq!(
        datagram.encode(false).expect("报文应可编码")[0],
        0x00,
        "UoT IPv4"
    );
}
