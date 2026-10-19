//! SOCKS5 风格地址（`ATYP | 地址 | 端口`）编解码。
//! 基线 anytls-go fd6167a 依赖的 sing v0.5.1 `M.SocksaddrSerializer`。
//!
//! 本类型用于 anytls **普通流首字节**的目的地址，也是 UDP-over-TCP 请求头里的
//! 目的地址载体（魔法域 `sp.v2.udp-over-tcp.arpa` 就出现在这里）。
//! 注意它与 [`crate::stream::Address`] 的家族字节**不同**：此处是 SOCKS5 的
//! `0x01`=IPv4、`0x04`=IPv6、`0x03`=域名；UoT 报文内的地址用的是另一套映射。
//! 两处混用会造成真实互通中的整体错位，已对 Go 侧逐字节核对。
use crate::stream::StreamError;

/// SOCKS5 地址类型（ATYP）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Atyp {
    Ipv4 = 0x01,
    Fqdn = 0x03,
    Ipv6 = 0x04,
}

impl Atyp {
    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0x01 => Self::Ipv4,
            0x03 => Self::Fqdn,
            0x04 => Self::Ipv6,
            _ => return None,
        })
    }
}

/// 域名长度上限：SOCKS5 用 1 字节长度前缀。
const MAX_DOMAIN_BYTES: usize = 255;

/// SOCKS5 地址；`Fqdn` 含魔法域，是 UDP-over-TCP 请求的载体。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksAddr {
    Ipv4([u8; 4], u16),
    Fqdn(String, u16),
    Ipv6([u8; 16], u16),
}

impl SocksAddr {
    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4(_, port) | Self::Fqdn(_, port) | Self::Ipv6(_, port) => *port,
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Ipv4(raw, _) => format!("{}.{}.{}.{}", raw[0], raw[1], raw[2], raw[3]),
            Self::Ipv6(raw, _) => std::net::Ipv6Addr::from(*raw).to_string(),
            Self::Fqdn(name, _) => name.clone(),
        }
    }

    /// 编码为 SOCKS5 地址：`ATYP | 地址 | 端口(2B BE)`。
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        let mut bytes = Vec::new();
        match self {
            Self::Ipv4(raw, port) => {
                bytes.push(Atyp::Ipv4 as u8);
                bytes.extend_from_slice(raw);
                bytes.extend_from_slice(&port.to_be_bytes());
            }
            Self::Ipv6(raw, port) => {
                bytes.push(Atyp::Ipv6 as u8);
                bytes.extend_from_slice(raw);
                bytes.extend_from_slice(&port.to_be_bytes());
            }
            Self::Fqdn(name, port) => {
                let raw = name.as_bytes();
                if raw.is_empty() || raw.len() > MAX_DOMAIN_BYTES {
                    return Err(StreamError::InvalidAddress);
                }
                bytes.push(Atyp::Fqdn as u8);
                bytes.push(raw.len() as u8);
                bytes.extend_from_slice(raw);
                bytes.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(bytes)
    }

    /// 解析 SOCKS5 地址；返回 `(SocksAddr, 已消费字节数)`。
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), StreamError> {
        let atyp = Atyp::from_byte(*bytes.first().ok_or(StreamError::Incomplete)?)
            .ok_or(StreamError::InvalidAddress)?;
        match atyp {
            Atyp::Ipv4 => {
                let raw = bytes.get(1..5).ok_or(StreamError::Incomplete)?;
                let port = read_port(bytes, 5)?;
                Ok((Self::Ipv4(raw.try_into().expect("固定长度"), port), 7))
            }
            Atyp::Ipv6 => {
                let raw = bytes.get(1..17).ok_or(StreamError::Incomplete)?;
                let port = read_port(bytes, 17)?;
                Ok((Self::Ipv6(raw.try_into().expect("固定长度"), port), 19))
            }
            Atyp::Fqdn => {
                let length = *bytes.get(1).ok_or(StreamError::Incomplete)? as usize;
                if length == 0 {
                    return Err(StreamError::InvalidAddress);
                }
                let raw = bytes.get(2..2 + length).ok_or(StreamError::Incomplete)?;
                let name = std::str::from_utf8(raw).map_err(|_| StreamError::InvalidAddress)?;
                let port = read_port(bytes, 2 + length)?;
                Ok((Self::Fqdn(name.to_owned(), port), 4 + length))
            }
        }
    }
}

fn read_port(bytes: &[u8], offset: usize) -> Result<u16, StreamError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(StreamError::Incomplete)?;
    Ok(u16::from_be_bytes(raw.try_into().expect("固定长度")))
}
