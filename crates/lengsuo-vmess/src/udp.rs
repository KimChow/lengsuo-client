//! UDP 数据报的 SOCKS5 UDP 请求头编解码（对照 Xray 固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。
//!
//! 参考事实（逐条给出出处，避免「等价方案」）：
//!
//! 1. `proxy/socks/protocol.go:324-347` `DecodeUDPPacket`：一个数据报**只解析一封**
//!    SOCKS5 UDP 头（`RSV(2) | FRAG(1) | ATYP | ADDR | PORT`），解析完地址后
//!    **剩余字节即载荷**（`proxy/socks/server.go:238-249` 判 `payload.IsEmpty()`
//!    后把剩余字节原样转发）。⇒ 本模块**不循环**解析多封头：第二封头的字节
//!    属于**载荷**，不是新的地址。
//! 2. `proxy/socks/protocol.go:334-336`：`FRAG != 0` ⇒ 拒绝
//!    （`discarding fragmented payload.`），**不分片重组**；本层同语义 fail-closed。
//! 3. `proxy/socks/protocol.go:325-327`：长度 < 5 ⇒ 拒绝（`insufficient length of
//!    packet.`）；地址段不足由 `ReadAddressPort` 报错（`failed to read UDP header`）。
//! 4. 地址段用 SOCKS 自己的 addrParser（`proxy/socks/protocol.go:36-40`）：
//!    `ATYP 0x01=IPv4 / 0x04=IPv6 / 0x03=域名`，**端口在地址之后**
//!    （`common/protocol/address.go:113-134` `portLastAddressParser`）。
//!    ⛔ **不是** VMess 请求头用的 `PortThenAddress()`
//!    （`proxy/vmess/encoding/encoding.go:12-16`：端口在前、ATYP 1/2/3）。
//! 5. `proxy/socks/protocol.go:349-363` `EncodeUDPPacket`：`{0,0,0}` + 地址段 +
//!    数据；数据装不下时**丢包**（`b.Clear()`），本层改为显式错误
//!    （[`FrameError::PacketTooLarge`]），偏差点记入 `docs/vmess-status.md`。
//! 6. `proxy/socks/protocol.go:369-384` `UDPReader.ReadMultiBuffer`：**一个数据报
//!    一次读取、只解一封头**。本层 [`read_udp_packet`] 同语义：**单次读**取一个
//!    数据报，**不**把多份数据报拼成一份（`read_to_end` 会把两个数据报连成一个
//!    「报文」，那正是「一报多封头」的来源）。
//! 7. **VMess 线路上没有这一层**：`proxy/vmess/encoding/server.go:212-217` 只从
//!    请求头解析**一个**目标地址（`PortThenAddress`），请求体逐帧解密后**原样**
//!    转发（`proxy/vmess/inbound/inbound.go:281-296`）⇒ VMess 的 UDP 载荷是
//!    **裸数据报**。本模块是 SOCKS5 侧的 UDP 关联头，**不得**用来包裹 VMess 载荷。

use std::io::{Read, Write};

use ss_core::target::TargetAddr;

use crate::muxframe::FrameError;

/// 单条 UDP 报文载荷上限：`buf.Size`(8192) 减去 SOCKS5 UDP 头的最大开销
/// （RSV 2 + FRAG 1 + ATYP 1 + 域名长度 1 + 域名 255 + 端口 2 = 262）。
pub const MAX_UDP_PAYLOAD: usize = 8192 - 6 - 256;

/// SOCKS5 UDP 请求头固定前缀长度（RSV 2 + FRAG 1）。
pub const UDP_HEADER_PREFIX_LEN: usize = 3;

/// SOCKS5 地址族字节：IPv4（`proxy/socks/protocol.go:37`）。
const ATYP_IPV4: u8 = 0x01;
/// SOCKS5 地址族字节：域名（`proxy/socks/protocol.go:39`）。
const ATYP_DOMAIN: u8 = 0x03;
/// SOCKS5 地址族字节：IPv6（`proxy/socks/protocol.go:38`）。
const ATYP_IPV6: u8 = 0x04;

/// 端口段字节数（BE16）。
const PORT_LEN: usize = 2;

/// 一次读取的缓冲上限：单个 UDP 数据报的理论上限（IPv6 理论最大 65507 字节），
/// 取 65536 保证不静默截断；超限由 [`decode_udp_packet`] 的载荷上限判据拒绝。
const MAX_DATAGRAM_READ: usize = 65536;

/// 空读重试上限（参考 `common/buf/reader.go:12` 的 `for i := 0; i < 64; i++`）。
const MAX_EMPTY_READS: usize = 64;

/// 一条 UDP 关联报文：目标地址 + 载荷。
///
/// 语义对齐 `socks.DecodeUDPPacket` 返回的 `RequestHeader + data`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket {
    pub target: TargetAddr,
    pub payload: Vec<u8>,
}

/// 解码一条 SOCKS5 UDP 请求报文（`DecodeUDPPacket` 逐段对齐）。
///
/// 判据顺序与参考一致：
/// 1. 长度 < 5 → 拒（`proxy/socks/protocol.go:325-327`）；
/// 2. `FRAG != 0` → 拒（`proxy/socks/protocol.go:334-336`）；
/// 3. 地址段解析失败 → 拒（`proxy/socks/protocol.go:340-343`）。
///
/// **只解析一封头**：解析完第一封的地址后，剩余字节**全部是载荷**
/// （参考 `proxy/socks/server.go:246-271` 把剩余字节原样转发）。数据报里若还
/// 跟着第二封 SOCKS5 头，它的字节落在载荷里，**不会**被当成新的目标地址。
pub fn decode_udp_packet(bytes: &[u8]) -> Result<UdpPacket, FrameError> {
    if bytes.len() < 5 {
        return Err(FrameError::Address);
    }
    // packet[0]/[1] 是保留位，参考不校验；packet[2] 是分片号，必须为 0。
    if bytes[2] != 0 {
        return Err(FrameError::Address);
    }
    let (target, used) = decode_socks5_address(&bytes[UDP_HEADER_PREFIX_LEN..])?;
    let payload = bytes[UDP_HEADER_PREFIX_LEN + used..].to_vec();
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(FrameError::PacketTooLarge {
            size: u16::try_from(payload.len()).unwrap_or(u16::MAX),
        });
    }
    Ok(UdpPacket { target, payload })
}

/// 编码一条 SOCKS5 UDP 请求报文（`EncodeUDPPacket` 逐段对齐）。
///
/// 参考在缓冲区不足时返回空包（静默丢包）；本层改为显式错误
/// （[`FrameError::PacketTooLarge`]），偏差点记入 `docs/vmess-status.md`。
pub fn encode_udp_packet(packet: &UdpPacket) -> Result<Vec<u8>, FrameError> {
    if packet.payload.len() > MAX_UDP_PAYLOAD {
        return Err(FrameError::PacketTooLarge {
            size: u16::try_from(packet.payload.len()).unwrap_or(u16::MAX),
        });
    }
    let mut out = Vec::with_capacity(UDP_HEADER_PREFIX_LEN + 19 + packet.payload.len());
    out.extend_from_slice(&[0, 0, 0]); // RSV|x2 + FRAG=0
    encode_socks5_address(&mut out, &packet.target)?;
    out.extend_from_slice(&packet.payload);
    Ok(out)
}

/// 从流里读**一条** UDP 关联报文。
///
/// 参考 `proxy/socks/protocol.go:369-384` `UDPReader.ReadMultiBuffer` +
/// `common/buf/reader.go:10-25` `readOneUDP`：**一次读出一个**数据报并只解一封头
/// （参考在读到非空内容时立刻返回，最多重试 64 次空读）。
///
/// ⛔ 不用 `read_to_end`：那会把多份数据报首尾相接成一份「报文」，后一份的
/// SOCKS5 头就被当成前一封头的**残余载荷**——这正是「一报多封头」的来源。
/// 本函数只做**一次** `read`，因此传入的 reader 必须是「一次读 = 一个数据报」的
/// 来源（如 UDP socket）。字节流来源请自行按数据报边界切分后再调用
/// [`decode_udp_packet`]。
pub fn read_udp_packet<R: Read>(reader: &mut R) -> Result<UdpPacket, FrameError> {
    let mut buf = vec![0u8; MAX_DATAGRAM_READ];
    for _ in 0..MAX_EMPTY_READS {
        let read = reader
            .read(&mut buf)
            .map_err(|error| FrameError::Io(format!("{:?}", error.kind())))?;
        if read > 0 {
            buf.truncate(read);
            return decode_udp_packet(&buf);
        }
    }
    Err(FrameError::Io(
        "reader returns too many empty payloads".to_string(),
    ))
}

/// 把一条 UDP 关联报文写到流里（整包写出，由调用方决定外层分帧）。
pub fn write_udp_packet<W: Write>(writer: &mut W, packet: &UdpPacket) -> Result<(), FrameError> {
    let wire = encode_udp_packet(packet)?;
    writer
        .write_all(&wire)
        .map_err(|error| FrameError::Io(format!("{:?}", error.kind())))
}

/// SOCKS5 地址段读端（`common/protocol/address.go:113-134` `portLastAddressParser`）：
/// `ATYP(1) | ADDR | PORT(2)`；返回地址与消耗字节数。
///
/// 与参考的差异（有意偏离，记入 `docs/vmess-status.md`）：
/// - 域名字符集不加严（参考 `common/protocol/address.go:159-166,219-221` 要求
///   `[0-9a-zA-Z-._]`；与既有偏离 V-M1 同源：`TargetAddr` 是 ss-core 共享类型）。
///   ⛔ 参考的域名长度 0 会把长度字节并进域名串（`BytesFrom(-0)`），
///   得到 `"\x00"` 并被字符集校验拒（实测 `invalid domain name: `）；
///   本层直接在长度 0 时拒，**可观测结果一致**（都是拒绝）。
fn decode_socks5_address(bytes: &[u8]) -> Result<(TargetAddr, usize), FrameError> {
    let atyp = *bytes.first().ok_or(FrameError::Address)?;
    match atyp {
        ATYP_IPV4 => {
            let need = 1 + 4 + PORT_LEN;
            if bytes.len() < need {
                return Err(FrameError::Address);
            }
            let ip: [u8; 4] = bytes[1..5].try_into().expect("4 字节");
            let port = read_port(&bytes[5..7]);
            Ok((TargetAddr::V4(ip, port), need))
        }
        ATYP_DOMAIN => {
            if bytes.len() < 2 {
                return Err(FrameError::Address);
            }
            let domain_len = usize::from(bytes[1]);
            if domain_len == 0 {
                return Err(FrameError::Address);
            }
            let need = 1 + 1 + domain_len + PORT_LEN;
            if bytes.len() < need {
                return Err(FrameError::Address);
            }
            let host =
                std::str::from_utf8(&bytes[2..2 + domain_len]).map_err(|_| FrameError::Address)?;
            if host.contains('\0') {
                return Err(FrameError::Address);
            }
            let port = read_port(&bytes[2 + domain_len..2 + domain_len + PORT_LEN]);
            // 参考 `common/protocol/address.go:213-218`：`maybeIPPrefix`（首字节是
            // `[` 或数字）时用 `net.ParseAddress` 解析，成 IP 就返回 IP 地址。
            if let Some(ip) = parse_ip_literal(host) {
                return Ok((with_port(ip, port), need));
            }
            Ok((TargetAddr::Domain(host.to_string(), port), need))
        }
        ATYP_IPV6 => {
            let need = 1 + 16 + PORT_LEN;
            if bytes.len() < need {
                return Err(FrameError::Address);
            }
            let ip: [u8; 16] = bytes[1..17].try_into().expect("16 字节");
            let port = read_port(&bytes[17..19]);
            Ok((TargetAddr::V6(ip, port), need))
        }
        _ => Err(FrameError::Address),
    }
}

/// IP 字面量 → IP 地址（对齐 `common/net/address.go:79-96` `ParseAddress` +
/// `common/net/address.go:101-108` `IPAddress`）。
///
/// 参考语义：先剥 `[...]` 方括号；首尾非字母数字时去空白；再按 IP 解析。
/// IPv4-mapped 的 IPv6（`::ffff:a.b.c.d`）折回 IPv4（`IPAddress` 的 v4 分支）。
/// 返回的地址**不带端口**（端口由调用方用 [`with_port`] 补上）。
fn parse_ip_literal(host: &str) -> Option<TargetAddr> {
    // `maybeIPPrefix`：参考只在首字节是 `[` 或数字时才尝试 IP 解析。
    let first = host.as_bytes().first().copied()?;
    if first != b'[' && !first.is_ascii_digit() {
        return None;
    }
    // 剥方括号（`ParseAddress`）。
    let trimmed = if host.len() >= 2 && host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    };
    // 首尾非字母数字时去空白（`ParseAddress`）。
    let cleaned = if trimmed
        .as_bytes()
        .first()
        .is_some_and(|b| !b.is_ascii_alphanumeric())
        || trimmed
            .as_bytes()
            .last()
            .is_some_and(|b| !b.is_ascii_alphanumeric())
    {
        trimmed.trim()
    } else {
        trimmed
    };
    let ip: std::net::IpAddr = cleaned.parse().ok()?;
    Some(match ip {
        std::net::IpAddr::V4(v4) => TargetAddr::V4(v4.octets(), 0),
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => TargetAddr::V4(v4.octets(), 0),
            None => TargetAddr::V6(v6.octets(), 0),
        },
    })
}

/// 给不含端口的 IP 地址补上端口（参考 `net.Address` + `net.Port` 是分开的，
/// 本仓 [`TargetAddr`] 把两者合在一起）。
fn with_port(addr: TargetAddr, port: u16) -> TargetAddr {
    match addr {
        TargetAddr::V4(ip, _) => TargetAddr::V4(ip, port),
        TargetAddr::V6(ip, _) => TargetAddr::V6(ip, port),
        TargetAddr::Domain(host, _) => TargetAddr::Domain(host, port),
    }
}

/// SOCKS5 地址段写端（`common/protocol/address.go:228-259` `writeAddress`）：
/// `ATYP(1) | ADDR | PORT(2)`。
fn encode_socks5_address(out: &mut Vec<u8>, addr: &TargetAddr) -> Result<(), FrameError> {
    match addr {
        TargetAddr::V4(ip, port) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(ip);
            out.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::V6(ip, port) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(ip);
            out.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Domain(host, port) => {
            // 参考 `common/protocol/headers.go:93-95` `isDomainTooLong`（> 256 拒）
            // 与 `common/protocol/address.go:244-246`（写长度前缀）。
            if host.is_empty() || host.len() > u8::MAX as usize || host.contains('\0') {
                return Err(FrameError::Address);
            }
            out.push(ATYP_DOMAIN);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

fn read_port(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV6_LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    #[test]
    fn udp_packet_roundtrip_ipv4_and_domain() {
        for target in [
            TargetAddr::V4([127, 0, 0, 1], 53),
            TargetAddr::Domain("dns.example.invalid".to_string(), 5353),
            TargetAddr::V6(IPV6_LOOPBACK, 123),
        ] {
            let packet = UdpPacket {
                target,
                payload: b"query-bytes".to_vec(),
            };
            let wire = encode_udp_packet(&packet).expect("可编码");
            assert_eq!(wire[0], 0);
            assert_eq!(wire[1], 0);
            assert_eq!(wire[2], 0, "FRAG 必须为 0");
            let back = decode_udp_packet(&wire).expect("可解码");
            assert_eq!(back, packet);
        }
    }

    #[test]
    fn address_layout_is_socks5_atyp_first_port_last() {
        // 参考 `proxy/socks/protocol.go:36-40` + `common/protocol/address.go:113-134`：
        // ATYP 在前、端口在后；ATYP 1=IPv4 / 3=域名 / 4=IPv6。
        let packet = UdpPacket {
            target: TargetAddr::V4([127, 0, 0, 1], 53),
            payload: b"x".to_vec(),
        };
        let wire = encode_udp_packet(&packet).expect("可编码");
        assert_eq!(wire[3], ATYP_IPV4);
        assert_eq!(&wire[4..8], &[127, 0, 0, 1]);
        assert_eq!(&wire[8..10], &[0x00, 0x35], "端口在地址之后");

        let domain = UdpPacket {
            target: TargetAddr::Domain("a.b".to_string(), 53),
            payload: b"x".to_vec(),
        };
        let wire = encode_udp_packet(&domain).expect("可编码");
        assert_eq!(wire[3], ATYP_DOMAIN);
        assert_eq!(wire[4], 3);
        assert_eq!(&wire[5..8], b"a.b");
        assert_eq!(&wire[8..10], &[0x00, 0x35]);
    }

    #[test]
    fn fragmented_packet_is_rejected_like_reference() {
        // FRAG != 0：参考 `discarding fragmented payload`。
        let mut wire = vec![0u8, 0, 1];
        wire.extend_from_slice(
            &encode_udp_packet(&UdpPacket {
                target: TargetAddr::V4([127, 0, 0, 1], 1),
                payload: b"x".to_vec(),
            })
            .expect("可编码")[3..],
        );
        assert!(decode_udp_packet(&wire).is_err());
    }

    #[test]
    fn short_and_oversized_packets_are_rejected() {
        assert!(decode_udp_packet(&[0, 0, 0]).is_err(), "<5 字节必须拒");
        let huge = UdpPacket {
            target: TargetAddr::V4([127, 0, 0, 1], 1),
            payload: vec![0u8; MAX_UDP_PAYLOAD + 1],
        };
        assert!(encode_udp_packet(&huge).is_err(), "超过 buf.Size 必须拒");
    }

    #[test]
    fn empty_payload_is_allowed() {
        let packet = UdpPacket {
            target: TargetAddr::V4([10, 0, 0, 1], 0),
            payload: Vec::new(),
        };
        let wire = encode_udp_packet(&packet).expect("可编码");
        assert_eq!(wire.len(), 3 + 7);
        assert_eq!(decode_udp_packet(&wire).expect("可解码"), packet);
    }

    #[test]
    fn read_write_helpers_match() {
        let packet = UdpPacket {
            target: TargetAddr::Domain("a.b".to_string(), 9),
            payload: b"z".to_vec(),
        };
        let mut wire = Vec::new();
        write_udp_packet(&mut wire, &packet).expect("可写");
        let back = read_udp_packet(&mut &wire[..]).expect("可读");
        assert_eq!(back, packet);
    }
}
