//! SIP022 TCP 会话双向编解码原语：salt + 固定长度头 + 变长头 + 载荷 chunk。
//!
//! 共享类型与线格式常量在此；发送侧见 [`send`]，接收侧见 [`receive`]。
//! 本模块只做编解码与单条流的会话状态，不含服务器、中继或多用户路由。
//!
//! 与 SIP022 §3.1.3 原生固定头（`type|timestamp|length`）相比，本实现在固定头里
//! 额外放入 8 字节会话标识，并把响应流的关联字段定义为“请求会话标识”而非请求
//! salt；变长头内保留原生 `padding length` 字段以便与固定头声明交叉校验。
//! 因此**与 Xray TCP 的线格式互通未经验证**（详见 `docs/ss2022-status.md`）。
use ss_core::crypto::{CipherSuite, TAG_LEN};

use crate::{
    crypto::{Key, Method},
    Error,
};

pub mod receive;
pub mod send;

pub use receive::{Opened, Reader, SessionReplay};
pub use send::Writer;

/// 请求流固定头 type（客户端→服务端）。
pub const TYPE_REQUEST: u8 = 0x01;
/// 响应流固定头 type（服务端→客户端）。
pub const TYPE_RESPONSE: u8 = 0x00;
/// 固定头明文长度：type(1) + 会话标识(8) + 时间戳(8) + 变长头声明长(2) + 填充声明长(2)。
pub const FIXED_HEADER_LEN: usize = 21;
/// 固定头线上长度（明文 + 认证标签）。
pub const FIXED_HEADER_WIRE_LEN: usize = FIXED_HEADER_LEN + TAG_LEN;
/// 变长头内部填充长度字段宽度（u16be，原生 SIP022 字段）。
pub const PADDING_FIELD_LEN: usize = 2;
/// 响应流变长头的关联字段长度：请求会话标识（u64be）。
pub const RESPONSE_ASSOCIATION_LEN: usize = 8;
/// 变长头明文声明长上限（地址块最长 256 字节，另加填充与首批载荷）。
pub const MAX_VAR_HEADER_LEN: u16 = 1200;
/// 填充声明长上限（SIP022 `MaxPaddingLength = 900`，`MinPaddingLength = 0`）。
pub const MAX_PADDING_LEN: u16 = 900;
/// 时间戳允许偏差秒数（SIP022：超过 30 秒必须按重放处理）。
pub const TIMESTAMP_WINDOW_SECS: u64 = 30;

/// 流方向：决定固定头 type 与变长头关联块布局。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// 客户端→服务端：变长头关联块为 SOCKS5 目标地址。
    Request,
    /// 服务端→客户端：变长头关联块为请求会话标识 8 字节。
    Response,
}

impl Direction {
    /// 该方向的固定头 type 字节。
    pub fn header_type(self) -> u8 {
        match self {
            Self::Request => TYPE_REQUEST,
            Self::Response => TYPE_RESPONSE,
        }
    }

    /// 对端方向（响应流绑定到请求流时使用）。
    pub fn peer(self) -> Self {
        match self {
            Self::Request => Self::Response,
            Self::Response => Self::Request,
        }
    }

    /// 变长头关联块长度：请求为可变（SOCKS5 目标地址），响应固定 8 字节（请求会话标识）。
    pub fn fixed_association_len(self) -> Option<usize> {
        match self {
            Self::Request => None,
            Self::Response => Some(RESPONSE_ASSOCIATION_LEN),
        }
    }
}

/// 期望的 salt 长度：SIP022 规定 salt 与 PSK 等长，两个方向一致。
pub fn salt_len(key: &Key) -> usize {
    key.method().key_len()
}

/// 套件到 `ss_core` AEAD 的映射（本 crate 只有两个 AES-GCM 套件）。
pub(crate) fn suite(method: Method) -> CipherSuite {
    match method {
        Method::Aes128 => CipherSuite::Aes128Gcm,
        Method::Aes256 => CipherSuite::Aes256Gcm,
    }
}

pub(crate) fn random_bytes(length: usize) -> Result<Vec<u8>, Error> {
    let mut buffer = vec![0; length];
    getrandom::getrandom(&mut buffer).map_err(|_| Error::Entropy)?;
    Ok(buffer)
}

/// ss-core 错误到本 crate 错误的唯一映射点；映射后仍由调用方决定是否 poison。
pub(crate) fn map_core(error: ss_core::Error) -> Error {
    match error {
        ss_core::Error::TooShort { .. } | ss_core::Error::InvalidLength(_) => Error::Length,
        ss_core::Error::AuthFailed => Error::Authentication,
        ss_core::Error::SealFailed => Error::Seal,
        ss_core::Error::InvalidKeyLength => Error::KeyLength,
        ss_core::Error::Io(io) => Error::Io(io),
        other => Error::Address(other),
    }
}

/// 一条流的开场标识：随机 salt 与会话标识。
/// salt 长度必须等于套件密钥长度（aes-128-gcm 16 字节，aes-256-gcm 32 字节）。
pub struct Opening {
    salt: Vec<u8>,
    session_id: u64,
}

impl Opening {
    /// 用系统随机数生成 salt 与会话标识。
    pub fn random(key: &Key) -> Result<Self, Error> {
        let salt = random_bytes(key.method().key_len())?;
        let session_id =
            u64::from_be_bytes(random_bytes(8)?.try_into().map_err(|_| Error::Entropy)?);
        Ok(Self { salt, session_id })
    }
    /// 显式注入 salt 与会话标识（测试与确定性场景）。
    pub fn injected(salt: &[u8], session_id: u64) -> Self {
        Self {
            salt: salt.to_vec(),
            session_id,
        }
    }
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
    pub fn session_id(&self) -> u64 {
        self.session_id
    }
    pub(crate) fn check_salt(&self, key: &Key) -> Result<(), Error> {
        if self.salt.len() == key.method().key_len() {
            Ok(())
        } else {
            Err(Error::KeyLength)
        }
    }
}

/// 固定长度头字段。线上明文布局（全部 big-endian）：
/// `type(1) | session_id(8) | timestamp(8) | var_len(2) | padding(2)`。
/// 不含 Debug，避免会话标识与时间戳进入日志。
pub struct Header {
    pub kind: u8,
    pub session_id: u64,
    pub timestamp: u64,
    pub var_len: u16,
    pub padding: u16,
}

impl Header {
    pub(crate) fn encode(&self) -> [u8; FIXED_HEADER_LEN] {
        let mut bytes = [0; FIXED_HEADER_LEN];
        bytes[0] = self.kind;
        bytes[1..9].copy_from_slice(&self.session_id.to_be_bytes());
        bytes[9..17].copy_from_slice(&self.timestamp.to_be_bytes());
        bytes[17..19].copy_from_slice(&self.var_len.to_be_bytes());
        bytes[19..21].copy_from_slice(&self.padding.to_be_bytes());
        bytes
    }

    /// 解析固定头明文。调用方已核对长度（AEAD 输出切片），故下标无攻击者可控失败。
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != FIXED_HEADER_LEN {
            return Err(Error::Length);
        }
        Ok(Self {
            kind: bytes[0],
            session_id: u64::from_be_bytes(bytes[1..9].try_into().expect("已核对长度")),
            timestamp: u64::from_be_bytes(bytes[9..17].try_into().expect("已核对长度")),
            var_len: u16::from_be_bytes(bytes[17..19].try_into().expect("已核对长度")),
            padding: u16::from_be_bytes(bytes[19..21].try_into().expect("已核对长度")),
        })
    }

    /// 声明字段自洽性：type 合法、填充不超上限、声明长不小于填充长。
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.kind != TYPE_REQUEST && self.kind != TYPE_RESPONSE {
            return Err(Error::Direction);
        }
        if self.padding > MAX_PADDING_LEN {
            return Err(Error::HeaderPadding);
        }
        if self.var_len < self.padding || self.var_len > MAX_VAR_HEADER_LEN {
            return Err(Error::HeaderPadding);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Method;

    #[test]
    fn header_roundtrip_is_big_endian() {
        let header = Header {
            kind: TYPE_REQUEST,
            session_id: 0x0102_0304_0506_0708,
            timestamp: 1_700_000_000,
            var_len: 42,
            padding: 7,
        };
        let bytes = header.encode();
        assert_eq!(bytes[0], TYPE_REQUEST);
        assert_eq!(&bytes[1..9], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&bytes[17..19], &[0, 42]);
        assert_eq!(&bytes[19..21], &[0, 7]);
        let decoded = Header::decode(&bytes).unwrap();
        assert_eq!(decoded.kind, TYPE_REQUEST);
        assert_eq!(decoded.session_id, 0x0102_0304_0506_0708);
        assert_eq!(decoded.timestamp, 1_700_000_000);
        assert_eq!(decoded.var_len, 42);
        assert_eq!(decoded.padding, 7);
    }

    #[test]
    fn bad_type_or_padding_declaration_is_rejected() {
        assert!(matches!(
            Header::decode(&[0; FIXED_HEADER_LEN - 1]),
            Err(Error::Length)
        ));
        assert!(matches!(
            Header::decode(&[0; FIXED_HEADER_LEN + 1]),
            Err(Error::Length)
        ));
        let mut header = Header {
            kind: 0x02,
            session_id: 1,
            timestamp: 1,
            var_len: 8,
            padding: 0,
        };
        assert!(matches!(header.validate(), Err(Error::Direction)));
        header.kind = TYPE_RESPONSE;
        header.padding = MAX_PADDING_LEN + 1;
        assert!(matches!(header.validate(), Err(Error::HeaderPadding)));
        header.padding = 9;
        header.var_len = 8;
        assert!(matches!(header.validate(), Err(Error::HeaderPadding)));
        header.padding = 0;
        header.var_len = MAX_VAR_HEADER_LEN + 1;
        assert!(matches!(header.validate(), Err(Error::HeaderPadding)));
        header.var_len = 8;
        assert!(header.validate().is_ok());
    }

    #[test]
    fn salt_length_must_match_suite_and_direction_type_is_distinct() {
        let key = Key::new(Method::Aes256, &[0x22; 32]).unwrap();
        assert!(matches!(
            Opening::injected(&[0; 16], 1).check_salt(&key),
            Err(Error::KeyLength)
        ));
        assert!(Opening::injected(&[0; 32], 1).check_salt(&key).is_ok());
        assert_eq!(Direction::Request.header_type(), TYPE_REQUEST);
        assert_eq!(Direction::Response.header_type(), TYPE_RESPONSE);
        assert_eq!(Direction::Request.peer(), Direction::Response);
        assert_eq!(salt_len(&key), 32);
    }

    #[test]
    fn core_errors_map_without_losing_failure_kind() {
        assert!(matches!(
            map_core(ss_core::Error::TooShort { need: 1, got: 0 }),
            Error::Length
        ));
        assert!(matches!(
            map_core(ss_core::Error::AuthFailed),
            Error::Authentication
        ));
        assert!(matches!(map_core(ss_core::Error::SealFailed), Error::Seal));
    }
}
