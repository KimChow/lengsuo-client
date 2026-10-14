//! 目标地址（SOCKS5 地址格式，Shadowsocks 复用）。
//!
//! 布局：ATYP(1) + ADDR + PORT(2, big-endian)
//! ATYP: 0x01 IPv4 / 0x03 域名(1 字节长度 + 数据) / 0x04 IPv6

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    V4([u8; 4], u16),
    V6([u8; 16], u16),
    Domain(String, u16),
}

impl TargetAddr {
    /// 序列化为 SOCKS5 地址格式（ATYP + ADDR + PORT）。
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            TargetAddr::V4(ip, port) => {
                buf.push(0x01);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            TargetAddr::Domain(host, port) => {
                buf.push(0x03);
                buf.push(host.len() as u8);
                buf.extend_from_slice(host.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            TargetAddr::V6(ip, port) => {
                buf.push(0x04);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    /// 编码后的字节长度（预分配用）。
    pub fn encoded_len(&self) -> usize {
        1 + match self {
            TargetAddr::V4(..) => 4,
            TargetAddr::V6(..) => 16,
            TargetAddr::Domain(host, _) => 1 + host.len(),
        } + 2
    }

    /// 从字节流头部解析一个目标地址，返回（地址, 消耗字节数）。
    pub fn decode(buf: &[u8]) -> Result<(TargetAddr, usize)> {
        if buf.is_empty() {
            return Err(Error::TooShort { need: 1, got: 0 });
        }
        match buf[0] {
            0x01 => {
                const NEED: usize = 1 + 4 + 2;
                if buf.len() < NEED {
                    return Err(Error::TooShort {
                        need: NEED,
                        got: buf.len(),
                    });
                }
                let ip = [buf[1], buf[2], buf[3], buf[4]];
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok((TargetAddr::V4(ip, port), NEED))
            }
            0x03 => {
                if buf.len() < 2 {
                    return Err(Error::TooShort {
                        need: 2,
                        got: buf.len(),
                    });
                }
                let host_len = buf[1] as usize;
                let need = 2 + host_len + 2;
                if buf.len() < need {
                    return Err(Error::TooShort {
                        need,
                        got: buf.len(),
                    });
                }
                let host = std::str::from_utf8(&buf[2..2 + host_len])
                    .map_err(|_| Error::InvalidLength(host_len))?
                    .to_string();
                let port = u16::from_be_bytes([buf[2 + host_len], buf[3 + host_len]]);
                Ok((TargetAddr::Domain(host, port), need))
            }
            0x04 => {
                const NEED: usize = 1 + 16 + 2;
                if buf.len() < NEED {
                    return Err(Error::TooShort {
                        need: NEED,
                        got: buf.len(),
                    });
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[1..17]);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok((TargetAddr::V6(ip, port), NEED))
            }
            other => Err(Error::InvalidAddressType(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_roundtrip() {
        let t = TargetAddr::V4([8, 8, 8, 8], 443);
        let mut buf = Vec::with_capacity(t.encoded_len());
        t.encode_into(&mut buf);
        assert_eq!(buf.len(), t.encoded_len());
        let (decoded, used) = TargetAddr::decode(&buf).unwrap();
        assert_eq!(used, buf.len());
        assert_eq!(decoded, t);
    }

    #[test]
    fn domain_roundtrip() {
        let t = TargetAddr::Domain("example.com".into(), 8080);
        let mut buf = Vec::with_capacity(t.encoded_len());
        t.encode_into(&mut buf);
        let (decoded, used) = TargetAddr::decode(&buf).unwrap();
        assert_eq!(used, buf.len());
        assert_eq!(decoded, t);
    }

    #[test]
    fn v6_roundtrip() {
        let t = TargetAddr::V6([0x20; 16], 80);
        let mut buf = Vec::with_capacity(t.encoded_len());
        t.encode_into(&mut buf);
        let (decoded, used) = TargetAddr::decode(&buf).unwrap();
        assert_eq!(used, buf.len());
        assert_eq!(decoded, t);
    }

    #[test]
    fn invalid_atyp_rejected() {
        let err = TargetAddr::decode(&[0x99, 0, 0]).unwrap_err();
        assert!(matches!(err, Error::InvalidAddressType(0x99)));
    }

    #[test]
    fn truncated_input_reports_need() {
        let err = TargetAddr::decode(&[0x01, 8, 8]).unwrap_err();
        assert!(matches!(err, Error::TooShort { need: 7, got: 3 }));
    }
}
