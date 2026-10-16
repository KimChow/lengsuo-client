//! SIP022 TCP 固定头编解码（§3.1.3 两种方向布局），严格按字段宽度 big-endian。
//!
//! 请求：`type(1B=0) | timestamp(u64be) | length(u16be)`——length 是**变长头明文长度**。
//! 响应：`type(1B=1) | timestamp(u64be) | request_salt(16/32B) | length(u16be)`——
//! 该 chunk 同时充当**第一个 length chunk**，length 是紧随其后的**载荷 chunk 明文长度**。
//!
//! 这里只做字段编解码与自洽校验，不判时间窗（需要注入时钟，留给接收侧）。
//! 不含 `Debug`：时间戳与 salt 不得进入日志。
use super::{
    Direction, LENGTH_FIELD_LEN, MAX_CHUNK_PAYLOAD, MAX_PADDING_LEN, PADDING_FIELD_LEN,
    REQUEST_FIXED_HEADER_LEN, RESPONSE_HEADER_HEAD_LEN, TIMESTAMP_LEN, TYPE_REQUEST, TYPE_RESPONSE,
};
use crate::Error;

/// 固定头字段。响应方向必须携带 request salt，请求方向必须为空。
pub struct FixedHeader {
    /// type 字节（0=请求，1=响应）。
    pub kind: u8,
    /// u64be Unix 时间戳。
    pub timestamp: u64,
    /// 响应方向原样回传的请求 salt；请求方向必须为空。
    pub request_salt: Vec<u8>,
    /// 该方向的 length 字段（含义见 [`Direction::length_describes`]）。
    pub length: u16,
}

impl FixedHeader {
    /// 请求固定头：length = 变长头明文长度。
    pub fn request(timestamp: u64, var_len: u16) -> Self {
        Self {
            kind: TYPE_REQUEST,
            timestamp,
            request_salt: Vec::new(),
            length: var_len,
        }
    }

    /// 响应固定头：length = 紧随其后的载荷 chunk 明文长度（0 表示该方向已收尾）。
    pub fn response(timestamp: u64, request_salt: &[u8], payload_len: u16) -> Self {
        Self {
            kind: TYPE_RESPONSE,
            timestamp,
            request_salt: request_salt.to_vec(),
            length: payload_len,
        }
    }

    /// 编码为固定头明文。请求必须无 salt、长 11 字节；响应 salt 必须等于套件 salt 长度。
    pub fn encode(&self, direction: Direction, salt_len: usize) -> Result<Vec<u8>, Error> {
        match direction {
            Direction::Request => {
                if !self.request_salt.is_empty() {
                    return Err(Error::Direction);
                }
                let mut bytes = Vec::with_capacity(REQUEST_FIXED_HEADER_LEN);
                bytes.push(self.kind);
                bytes.extend_from_slice(&self.timestamp.to_be_bytes());
                bytes.extend_from_slice(&self.length.to_be_bytes());
                Ok(bytes)
            }
            Direction::Response => {
                if self.request_salt.len() != salt_len {
                    return Err(Error::KeyLength);
                }
                let mut bytes =
                    Vec::with_capacity(RESPONSE_HEADER_HEAD_LEN + salt_len + LENGTH_FIELD_LEN);
                bytes.push(self.kind);
                bytes.extend_from_slice(&self.timestamp.to_be_bytes());
                bytes.extend_from_slice(&self.request_salt);
                bytes.extend_from_slice(&self.length.to_be_bytes());
                Ok(bytes)
            }
        }
    }

    /// 解析固定头明文。长度与方向由调用方核对（AEAD 输出切片宽度即长度信号）。
    pub fn decode(direction: Direction, salt_len: usize, bytes: &[u8]) -> Result<Self, Error> {
        if direction.carries_request_salt() {
            let tail = RESPONSE_HEADER_HEAD_LEN + salt_len + LENGTH_FIELD_LEN;
            if bytes.len() != tail {
                return Err(Error::Length);
            }
            let start = RESPONSE_HEADER_HEAD_LEN;
            return Ok(Self {
                kind: bytes[0],
                timestamp: read_timestamp(&bytes[1..start])?,
                request_salt: bytes[start..start + salt_len].to_vec(),
                length: read_length(&bytes[start + salt_len..tail])?,
            });
        }
        if bytes.len() != REQUEST_FIXED_HEADER_LEN {
            return Err(Error::Length);
        }
        Ok(Self {
            kind: bytes[0],
            timestamp: read_timestamp(&bytes[1..1 + TIMESTAMP_LEN])?,
            request_salt: Vec::new(),
            length: read_length(&bytes[1 + TIMESTAMP_LEN..])?,
        })
    }

    /// 声明字段自洽性：type 与方向一致、salt 有无与方向一致、length 在本方向可成帧范围内、
    /// 填充上限不被引用越界。不判时间窗。
    pub fn validate(&self, direction: Direction) -> Result<(), Error> {
        if self.kind != direction.header_type() {
            return Err(Error::Direction);
        }
        if self.request_salt.is_empty() == direction.carries_request_salt() {
            return Err(Error::Direction);
        }
        if direction.has_variable_header() {
            // 变长头至少要有 ATYP+IPv4+port 再加 padding 字段，且不得超出可成帧范围。
            let min = ss_core::target::TargetAddr::decode(&[0x01, 0, 0, 0, 0, 0, 0])
                .map(|(_, used)| used + PADDING_FIELD_LEN)
                .map_err(|_| Error::Length)?;
            if usize::from(self.length) < min || usize::from(self.length) > MAX_CHUNK_PAYLOAD {
                return Err(Error::HeaderPadding);
            }
        }
        // 响应方向的 length 是载荷 chunk 明文长：u16 全域皆合法（0 是收尾信号）。
        Ok(())
    }

    /// 填充声明不得超出 SIP022 `MaxPaddingLength`（接收侧在变长头内核对具体字节数）。
    pub fn check_padding_decl(padding: u16) -> Result<(), Error> {
        if padding > MAX_PADDING_LEN {
            return Err(Error::HeaderPadding);
        }
        Ok(())
    }
}

fn read_timestamp(bytes: &[u8]) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| Error::Length)?,
    ))
}

fn read_length(bytes: &[u8]) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(
        bytes.try_into().map_err(|_| Error::Length)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_header_is_eleven_bytes_big_endian() {
        let header = FixedHeader::request(0x0102_0304_0506_0708, 42);
        let bytes = header
            .encode(Direction::Request, 16)
            .expect("请求固定头可编码");
        assert_eq!(bytes.len(), REQUEST_FIXED_HEADER_LEN);
        assert_eq!(bytes[0], TYPE_REQUEST);
        assert_eq!(&bytes[1..9], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&bytes[9..11], &[0, 42]);
        let decoded = FixedHeader::decode(Direction::Request, 16, &bytes).expect("可解码");
        assert_eq!(decoded.kind, TYPE_REQUEST);
        assert_eq!(decoded.timestamp, 0x0102_0304_0506_0708);
        assert_eq!(decoded.length, 42);
        assert!(decoded.request_salt.is_empty());
        assert!(decoded.validate(Direction::Request).is_ok());
    }

    #[test]
    fn response_header_carries_full_request_salt() {
        for salt_len in [16usize, 32usize] {
            let salt = vec![0xA7u8; salt_len];
            let header = FixedHeader::response(1_700_000_000, &salt, 5);
            let bytes = header
                .encode(Direction::Response, salt_len)
                .expect("响应固定头可编码");
            // 27 / 43 字节：type+timestamp+salt+length。
            assert_eq!(bytes.len(), salt_len + 11);
            assert_eq!(bytes[0], TYPE_RESPONSE);
            assert_eq!(&bytes[9..9 + salt_len], salt.as_slice());
            assert_eq!(&bytes[bytes.len() - 2..], &[0, 5]);
            let decoded =
                FixedHeader::decode(Direction::Response, salt_len, &bytes).expect("可解码");
            assert_eq!(decoded.request_salt, salt);
            assert_eq!(decoded.length, 5);
            assert!(decoded.validate(Direction::Response).is_ok());
        }
    }

    #[test]
    fn wrong_salt_shape_or_length_is_rejected_before_any_io() {
        // 请求方向不得携带 salt。
        let stray = FixedHeader {
            kind: TYPE_REQUEST,
            timestamp: 1,
            request_salt: vec![0x55; 16],
            length: 9,
        };
        assert!(matches!(
            stray.encode(Direction::Request, 16),
            Err(Error::Direction)
        ));
        // 响应 salt 必须正好等于套件 salt 长度。
        assert!(matches!(
            FixedHeader::response(1, &[0x55; 8], 5).encode(Direction::Response, 16),
            Err(Error::KeyLength)
        ));
        // 解码长度不符（少一字节 / 多一字节）必须是 Length，不回退明文。
        assert!(matches!(
            FixedHeader::decode(Direction::Request, 16, &[0; REQUEST_FIXED_HEADER_LEN - 1]),
            Err(Error::Length)
        ));
        assert!(matches!(
            FixedHeader::decode(Direction::Response, 16, &[1; 26]),
            Err(Error::Length)
        ));
        assert!(matches!(
            FixedHeader::decode(Direction::Response, 32, &[1; 44]),
            Err(Error::Length)
        ));
    }

    #[test]
    fn validate_ties_type_and_declared_length_to_direction() {
        // type 与方向不符。
        let mut header = FixedHeader::request(1, 9);
        header.kind = TYPE_RESPONSE;
        assert!(matches!(
            header.validate(Direction::Request),
            Err(Error::Direction)
        ));
        // 方向正确但 salt 缺失（响应必须携带关联 salt）。
        let missing = FixedHeader {
            kind: TYPE_RESPONSE,
            timestamp: 1,
            request_salt: Vec::new(),
            length: 5,
        };
        assert!(matches!(
            missing.validate(Direction::Response),
            Err(Error::Direction)
        ));
        // 变长头声明过短（连 ATYP+IPv4+port+padding 字段都放不下）。
        assert!(matches!(
            FixedHeader::request(1, 8).validate(Direction::Request),
            Err(Error::HeaderPadding)
        ));
        // 变长头声明超过单 chunk 可成帧上限。
        assert!(matches!(
            FixedHeader::request(1, (MAX_CHUNK_PAYLOAD + 1) as u16).validate(Direction::Request),
            Err(Error::HeaderPadding)
        ));
        assert!(FixedHeader::request(1, 9)
            .validate(Direction::Request)
            .is_ok());
        // 0 是响应方向的合法收尾信号。
        assert!(FixedHeader::response(1, &[0x55; 16], 0)
            .validate(Direction::Response)
            .is_ok());
        assert!(FixedHeader::check_padding_decl(MAX_PADDING_LEN).is_ok());
        assert!(matches!(
            FixedHeader::check_padding_decl(MAX_PADDING_LEN + 1),
            Err(Error::HeaderPadding)
        ));
    }
}
