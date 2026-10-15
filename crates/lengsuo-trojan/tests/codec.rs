//! Trojan 请求编解码测试：SHA224 已知向量、固定头部字节、地址类型、命令、
//! 每处截断、错误密码、坏 CRLF、非法地址与载荷保留。
//! 密码为测试专用假凭据，不代表任何真实凭据。

use lengsuo_trojan::codec::{self, Command, Error, Request};
use lengsuo_trojan::{Credential, TargetAddr};

/// 测试假密码。
const PASSWORD: &str = "Trojan-Test-Passwd";
/// 该密码的 SHA224 小写十六进制（56 字符）。
const HASH: &str = "3d387b62cd9fb6e83d84928a27b8247b12bd968d4b5f894f4edb18a3";

fn credential() -> Credential {
    Credential::new(PASSWORD)
}

/// 头部 = 哈希 + CRLF + 命令 + SOCKS 地址 + CRLF。
fn header(command: u8, address: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::from(HASH.as_bytes());
    bytes.extend_from_slice(b"\r\n");
    bytes.push(command);
    bytes.extend_from_slice(address);
    bytes.extend_from_slice(b"\r\n");
    bytes
}

fn ipv4_target() -> TargetAddr {
    TargetAddr::V4([203, 0, 113, 7], 443)
}

fn ipv4_tcp() -> Request {
    Request {
        command: Command::Tcp,
        target: ipv4_target(),
    }
}

#[test]
fn sha224_known_vectors() {
    // 已知向量取自 RFC 4634 与独立实现（Python hashlib），核对外加十六进制格式。
    assert_eq!(
        Credential::new("").as_hex(),
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    );
    assert_eq!(
        Credential::new("abc").as_hex(),
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
    );
    let cred = credential();
    assert_eq!(cred.as_hex(), HASH);
    assert_eq!(cred.as_bytes(), HASH.as_bytes());
    assert_eq!(cred.as_bytes().len(), 56);
    assert!(cred.verify(HASH.as_bytes()));
    assert!(!cred.verify(HASH.to_uppercase().as_bytes()));
    assert!(!cred.verify(&HASH.as_bytes()[..55]));
}

#[test]
fn credential_never_prints_secret() {
    let text = format!("{:?}", credential());
    assert!(!text.contains(HASH), "Debug 不得包含密码哈希");
    assert!(!text.contains(PASSWORD), "Debug 不得包含密码");
    assert!(text.contains("redacted"));
}

#[test]
fn fixed_tcp_ipv4_header_bytes() {
    let encoded = codec::encode(&ipv4_tcp(), &credential()).expect("可编码");
    assert_eq!(
        encoded,
        header(1, &[0x01, 203, 0, 113, 7, 1, 187]),
        "固定字节头部"
    );
    assert_eq!(encoded.len(), 68);
    assert_eq!(ipv4_tcp().header_len(), encoded.len());
    assert_eq!(
        codec::decode(&encoded, &credential()).expect("可解码"),
        (ipv4_tcp(), 68)
    );
}

#[test]
fn udp_domain_and_tcp_ipv6_fixed_bytes() {
    let udp = Request {
        command: Command::Udp,
        target: TargetAddr::Domain("example.com".into(), 8443),
    };
    let encoded = codec::encode(&udp, &credential()).expect("可编码");
    let mut address = vec![0x03, 11];
    address.extend_from_slice(b"example.com");
    address.extend_from_slice(&8443u16.to_be_bytes());
    assert_eq!(encoded, header(3, &address));
    assert_eq!(encoded.len(), 76);
    assert_eq!(
        codec::decode(&encoded, &credential()).expect("可解码"),
        (udp, 76)
    );

    let v6 = Request {
        command: Command::Tcp,
        target: TargetAddr::V6(
            [
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                0x2e, 0x2f,
            ],
            8080,
        ),
    };
    let encoded = codec::encode(&v6, &credential()).expect("可编码");
    let mut address = vec![0x04];
    address.extend((0x20u8..=0x2f).take(16));
    address.extend_from_slice(&8080u16.to_be_bytes());
    assert_eq!(encoded, header(1, &address));
    assert_eq!(encoded.len(), 80);
    assert_eq!(
        codec::decode(&encoded, &credential()).expect("可解码"),
        (v6, 80)
    );
}

#[test]
fn every_truncation_reports_need_and_got() {
    let requests = [
        ipv4_tcp(),
        Request {
            command: Command::Udp,
            target: TargetAddr::Domain("a.test".into(), 53),
        },
        Request {
            command: Command::Tcp,
            target: TargetAddr::V6([0x20; 16], 1),
        },
    ];
    for req in requests {
        let bytes = codec::encode(&req, &credential()).expect("可编码");
        for end in 0..bytes.len() {
            let err = codec::decode(&bytes[..end], &credential()).expect_err("截断 {end} 必须失败");
            match err {
                Error::Truncated { need, got } => {
                    assert_eq!(got, end, "截断位置 {end}");
                    assert!(need > got, "need {need} 必须大于 got {got}");
                    assert!(need <= bytes.len(), "need 不得超过完整头部长度");
                    if end < 56 {
                        assert_eq!(need, 56, "哈希段截断统一报 56");
                    }
                }
                other => panic!("截断位置 {end} 得到意外错误 {other:?}"),
            }
        }
        assert_eq!(
            codec::decode(&bytes, &credential()).expect("完整头部必须成功"),
            (req.clone(), bytes.len())
        );
    }
    // 空输入也按哈希段截断报告。
    assert!(matches!(
        codec::decode(&[], &credential()),
        Err(Error::Truncated { need: 56, got: 0 })
    ));
}

#[test]
fn wrong_password_fails_authentication() {
    let bytes = codec::encode(&ipv4_tcp(), &credential()).expect("可编码");
    let other = Credential::new("other-password");
    assert!(
        matches!(codec::decode(&bytes, &other), Err(Error::Authentication)),
        "错误密码必须 fail-closed"
    );
    // 篡改单个哈希字符仍判为认证失败，而不是格式错误。
    let mut tampered = bytes.clone();
    tampered[10] = if tampered[10] == b'a' { b'b' } else { b'a' };
    assert!(matches!(
        codec::decode(&tampered, &credential()),
        Err(Error::Authentication)
    ));
    // 截短到不足 56 字节且哈希前缀正确时是截断，不是认证成功后的格式错误。
    assert!(matches!(
        codec::decode(&bytes[..30], &credential()),
        Err(Error::Truncated { .. })
    ));
}

#[test]
fn bad_crlf_is_reported_separately() {
    let base = codec::encode(&ipv4_tcp(), &credential()).expect("可编码");
    // 两处 CRLF 分别位于偏移 56 与 66，且都必须是 \r\n 两个字节。
    for offset in [56usize, 66usize] {
        // (行内字节位置, 替换值)：只使用真正改变原字节的取值。
        for (index, replacement) in [(0usize, b'x'), (0usize, 0u8), (1usize, b'x'), (1usize, 0u8)] {
            let mut broken = base.clone();
            broken[offset + index] = replacement;
            let err = codec::decode(&broken, &credential())
                .expect_err("坏 CRLF 必须失败，替换值 {replacement:#04x}");
            assert!(
                matches!(err, Error::InvalidCrlf { offset: o } if o == offset),
                "偏移 {offset} 第 {index} 字节替换为 {replacement:#04x}，得到 {err:?}"
            );
            assert_eq!(format!("{err}"), format!("偏移 {offset} 处缺少 CRLF"));
        }
        // 只有 LF 没有 CR（换行错位一格）同样拒绝，不容忍宽松分隔符。
        let mut lf_only = base.clone();
        lf_only[offset] = b'x';
        lf_only[offset + 1] = b'\n';
        let err = codec::decode(&lf_only, &credential()).expect_err("缺少 CR 的分隔符必须失败");
        assert!(
            matches!(err, Error::InvalidCrlf { offset: o } if o == offset),
            "得到 {err:?}"
        );
    }
}

#[test]
fn invalid_command_and_address_rejected() {
    let base = codec::encode(&ipv4_tcp(), &credential()).expect("可编码");
    for byte in [0x00u8, 0x02, 0x04, 0x05, 0xff] {
        let mut broken = base.clone();
        broken[58] = byte;
        assert!(
            matches!(codec::decode(&broken, &credential()), Err(Error::InvalidCommand(v)) if v == byte),
            "命令字节 {byte:#04x}"
        );
    }
    for byte in [0x00u8, 0x02, 0x05, 0x99] {
        let mut broken = base.clone();
        broken[59] = byte;
        let err = codec::decode(&broken, &credential()).expect_err("非法 ATYP 必须失败");
        assert!(
            matches!(&err, Error::Address(ss_core::Error::InvalidAddressType(v)) if *v == byte),
            "ATYP {byte:#04x} 得到 {err:?}"
        );
    }
    // 域名长度 0 与含 NUL 的域名都必须拒绝。
    let mut broken = base.clone();
    broken[59] = 0x03;
    broken[60] = 0;
    let err = codec::decode(&broken, &credential()).expect_err("空域名必须失败");
    assert!(
        matches!(&err, Error::Address(ss_core::Error::InvalidLength(0))),
        "得到 {err:?}"
    );

    let nul = header(1, &[vec![0x03, 3, b'a', 0, b'b'], vec![7, 0]].concat());
    let err = codec::decode(&nul, &credential()).expect_err("NUL 域名必须失败");
    assert!(matches!(err, Error::Address(_)), "得到 {err:?}");
}

#[test]
fn empty_and_oversize_domains_rejected_on_encode() {
    for host in [String::new(), "x".repeat(256), "a\0b".into()] {
        let req = Request {
            command: Command::Tcp,
            target: TargetAddr::Domain(host, 80),
        };
        let err = codec::encode(&req, &credential()).expect_err("非法域名必须拒绝编码");
        assert!(matches!(err, Error::Address(_)), "得到 {err:?}");
    }

    // 最大合法域名（255 字节）仍然通过。
    let longest = Request {
        command: Command::Udp,
        target: TargetAddr::Domain("l".repeat(255), 65535),
    };
    let encoded = codec::encode(&longest, &credential()).expect("255 字节域名合法");
    assert_eq!(encoded.len(), 56 + 2 + 1 + (1 + 1 + 255 + 2) + 2);
    assert_eq!(
        codec::decode(&encoded, &credential()).expect("可解码"),
        (longest, encoded.len())
    );
}

#[test]
fn header_consumption_keeps_application_payload() {
    let req = ipv4_tcp();
    let payload = b"GET /index HTTP/1.1\r\n\r\nbody";
    let mut stream = codec::encode(&req, &credential()).expect("可编码");
    let header_len = stream.len();
    stream.extend_from_slice(payload);

    let (decoded, used) = codec::decode(&stream, &credential()).expect("可解码");
    assert_eq!(decoded, req);
    assert_eq!(used, header_len, "只消耗头部字节");
    assert_eq!(&stream[used..], payload, "应用载荷必须原样保留");

    // 头部之后紧跟的第二个头部不能被当作载荷的一部分解析。
    let mut second = codec::encode(
        &Request {
            command: Command::Udp,
            target: TargetAddr::Domain("dns.test".into(), 53),
        },
        &credential(),
    )
    .expect("可编码");
    second.extend_from_slice(b"dns-payload");
    let mut multi = stream.clone();
    multi.extend_from_slice(&second);
    let (first, used) = codec::decode(&multi, &credential()).expect("可解码");
    assert_eq!(first, req);
    assert_eq!(
        &multi[used..],
        [payload.as_slice(), second.as_ref()].concat()
    );
}

#[test]
fn roundtrip_covers_every_command_and_address() {
    let cred = Credential::new("password123");
    assert_eq!(
        cred.as_hex(),
        "3d45597256050bb1e93bd9c10aee4c8716f8774f5a48c995bf0cf860"
    );
    let targets = [
        TargetAddr::V4([127, 0, 0, 1], 1),
        TargetAddr::V6([0; 16], 65535),
        TargetAddr::Domain("sub.domain.example".into(), 8080),
    ];
    for command in [Command::Tcp, Command::Udp] {
        for target in targets.iter().cloned() {
            let req = Request { command, target };
            let encoded = codec::encode(&req, &cred).expect("可编码");
            let (decoded, used) = codec::decode(&encoded, &cred).expect("可解码");
            assert_eq!(decoded, req);
            assert_eq!(used, encoded.len());
            assert_eq!(used, req.header_len());
        }
    }
}
