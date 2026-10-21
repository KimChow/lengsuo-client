//! Mux 帧的地址段编解码（`protocol.PortThenAddress`）。
//!
//! 线格式：`Port(BE16) | Type(1|2|3) | ADDR`——端口**在前**，与
//! SOCKS5 的 `ATYP | ADDR | Port` 相反，不可复用后者。

use ss_core::target::TargetAddr;

use super::error::FrameError;

/// 地址段写端（`protocol.PortThenAddress`）：`Port(BE16) | Type(1) | ADDR`。
pub fn encode_address_port(out: &mut Vec<u8>, addr: &TargetAddr) -> Result<(), FrameError> {
    let (port, kind, bytes) = split_addr(addr);
    out.extend_from_slice(&port.to_be_bytes());
    out.push(kind);
    out.extend_from_slice(&bytes);
    Ok(())
}

/// 地址段读端；返回地址与消耗字节数。
pub fn decode_address_port(bytes: &[u8]) -> Result<(TargetAddr, usize), FrameError> {
    if bytes.len() < 3 {
        return Err(FrameError::Address);
    }
    let port = u16::from_be_bytes([bytes[0], bytes[1]]);
    match bytes[2] {
        1 => {
            if bytes.len() < 7 {
                return Err(FrameError::Address);
            }
            let ip: [u8; 4] = bytes[3..7].try_into().expect("4 字节");
            Ok((TargetAddr::V4(ip, port), 7))
        }
        2 => {
            let domain_len = usize::from(bytes[3]);
            if domain_len == 0 || bytes.len() < 4 + domain_len {
                return Err(FrameError::Address);
            }
            let host =
                std::str::from_utf8(&bytes[4..4 + domain_len]).map_err(|_| FrameError::Address)?;
            if host.contains('\0') {
                return Err(FrameError::Address);
            }
            Ok((TargetAddr::Domain(host.to_string(), port), 4 + domain_len))
        }
        3 => {
            if bytes.len() < 19 {
                return Err(FrameError::Address);
            }
            let ip: [u8; 16] = bytes[3..19].try_into().expect("16 字节");
            Ok((TargetAddr::V6(ip, port), 19))
        }
        _ => Err(FrameError::Address),
    }
}

fn split_addr(addr: &TargetAddr) -> (u16, u8, Vec<u8>) {
    match addr {
        TargetAddr::V4(ip, port) => (*port, 1, ip.to_vec()),
        TargetAddr::V6(ip, port) => (*port, 3, ip.to_vec()),
        TargetAddr::Domain(host, port) => {
            let mut bytes = Vec::with_capacity(1 + host.len());
            bytes.push(host.len() as u8);
            bytes.extend_from_slice(host.as_bytes());
            (*port, 2, bytes)
        }
    }
}
