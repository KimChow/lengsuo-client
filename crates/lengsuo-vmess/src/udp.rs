//! VMess UDP 转发（`RequestCommand_UDP`）报文封装（对照固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。
//!
//! 参考事实（逐条给出出处，避免「等价方案」）：
//!
//! 1. `proxy/vmess/outbound/outbound.go:87-92`：目标网络为 UDP 时命令字节取
//!    `RequestCommandUDP`（=2，见本 crate [`crate::consts::CMD_UDP`]），
//!    请求头里写的就是**真实目标地址**。除 `v1.mux.cool` 外没有额外的
//!    "association" 握手——`RequestCommand_UDP` 自身即关联语义。
//! 2. `proxy/vmess/inbound/inbound.go:254`：入站只对 `RequestCommandMux`
//!    跳过访问日志，其余命令（含 UDP）走同一条 `dispatcher.Dispatch`。
//!    UDP 的目标解析/回程地址在 dispatcher 层，vmess 层不做任何
//!    SOCKS5 式的 `RSV|FRAG|ATYP|ADDR|PORT` 头。
//! 3. `proxy/vmess/encoding/{server,client}.go` 的请求/响应体加解密与命令字节
//!    无关：UDP 与 TCP 共用同一套 chunk 流分帧（`common/crypto/auth.go`）。
//!    UDP 的「报文边界」由**上层传输**保留——本仓在与「Xray 的 UDP 关联」互通时
//!    使用 SOCKS5 UDP 请求格式 `RSV(2)=0 | FRAG(1)=0 | ATYP | ADDR | PORT |
//!    DATA`（`proxy/socks/protocol.go:324-363` 的 `DecodeUDPPacket`/
//!    `EncodeUDPPacket` 逐字对齐），该格式**在 VMess 载荷内部**，不改变 VMess
//!    线格式。这既避免了自创方案，也与 `v1.mux.cool:666`（XUDP）路径外的
//!    传统 UDP 关联一致。
//! 4. `DecodeUDPPacket` 的 FRAG != 0 判据是**拒绝**（`discarding fragmented
//!    payload`），不是分片重组；本层同语义 fail-closed。
//!
//! 「超 MTU 分片」在参考里由 IP 层负责，vmess 层只发出不超过
//! `buf.Size`(8192) 的单个数据帧；本层用 [`MAX_UDP_PAYLOAD`] 表达该上限，
//! 超限即拒（不静默截断）。

use std::io::{Read, Write};

use ss_core::target::TargetAddr;

use crate::muxframe::{decode_address_port, encode_address_port, FrameError};

/// 单条 UDP 报文载荷上限：`buf.Size`(8192) 减去 SOCKS5 UDP 头的最小开销
/// （3 字节 RSV+FRAG + 1 字节 ATYP + 2 字节端口 + 最长地址 1+255）。
pub const MAX_UDP_PAYLOAD: usize = 8192 - 6 - 256;

/// SOCKS5 UDP 请求头固定部分长度（RSV 2 + FRAG 1）。
pub const UDP_HEADER_PREFIX_LEN: usize = 3;

/// 一条 UDP 关联报文：目标地址 + 载荷。
///
/// 语义对齐 `socks.DecodeUDPPacket` 返回的 `RequestHeader + data`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket {
    pub target: TargetAddr,
    pub payload: Vec<u8>,
}

/// 解码一条 SOCKS5 UDP 请求报文（`DecodeUDPPacket` 逐行对齐）。
///
/// 判据顺序与参考一致：不足 5 字节 → 拒；`FRAG != 0` → 拒；随后解析地址。
pub fn decode_udp_packet(bytes: &[u8]) -> Result<UdpPacket, FrameError> {
    if bytes.len() < 5 {
        return Err(FrameError::Address);
    }
    // packet[0]/[1] 是保留位，参考不校验；packet[2] 是分片号，必须为 0。
    if bytes[2] != 0 {
        return Err(FrameError::Address);
    }
    let (target, used) = decode_address_port(&bytes[UDP_HEADER_PREFIX_LEN..])?;
    let payload = bytes[UDP_HEADER_PREFIX_LEN + used..].to_vec();
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(FrameError::PacketTooLarge {
            size: u16::try_from(payload.len()).unwrap_or(u16::MAX),
        });
    }
    Ok(UdpPacket { target, payload })
}

/// 编码一条 SOCKS5 UDP 请求报文（`EncodeUDPPacket` 逐行对齐）。
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
    encode_address_port(&mut out, &packet.target)?;
    out.extend_from_slice(&packet.payload);
    Ok(out)
}

/// 从流里读一条 UDP 关联报文（长度前缀由调用方的 chunk 层给出，这里是**整包**）。
pub fn read_udp_packet<R: Read>(reader: &mut R) -> Result<UdpPacket, FrameError> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|error| FrameError::Io(format!("{:?}", error.kind())))?;
    decode_udp_packet(&buf)
}

/// 把一条 UDP 关联报文写到流里（整包写出，由调用方决定外层分帧）。
pub fn write_udp_packet<W: Write>(writer: &mut W, packet: &UdpPacket) -> Result<(), FrameError> {
    let wire = encode_udp_packet(packet)?;
    writer
        .write_all(&wire)
        .map_err(|error| FrameError::Io(format!("{:?}", error.kind())))
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
