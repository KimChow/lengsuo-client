//! SIP022 TCP 会话双向编解码原语：salt + 固定头 [+ 变长头] + 载荷 chunk。
//!
//! 共享类型、线格式常量与固定头编解码在此；发送侧见 [`send`]，接收侧见 [`receive`]。
//! 本模块只做编解码与单条流的会话状态，不含服务器、中继或多用户路由。
//!
//! 固定头严格按 SIP022 §3.1.3 的两种方向布局（base64 假 PSK，仅测试与配置使用）：
//! - 请求 = `type(1B=0) | timestamp(u64be) | length(u16be)`，共 **11 字节**；length 指
//!   **变长头**明文长。变长头 = `ATYP+地址+port(u16be) | padding_len(u16be) | padding |
//!   首批载荷`，是紧随其后的第 2 个独立 chunk。
//! - 响应 = `type(1B=1) | timestamp(u64be) | request_salt(16/32B) | length(u16be)`，
//!   共 **27/43 字节**；该 chunk 同时充当**第一个 length chunk**，length 指紧随其后的
//!   载荷 chunk 明文长，响应没有变长头。
//!
//! TCP 流内没有会话标识字段：响应流靠原样回传的请求 salt 归属。u96le nonce 计数器
//! 跨整条流连续——请求方向固定头 = 0、变长头 = 1、之后逐帧递增；响应方向固定头 = 0、
//! 首批载荷 = 1、之后逐帧递增。
use ss_core::crypto::{CipherSuite, TAG_LEN};

use crate::{
    crypto::{Key, Method},
    Error,
};

pub mod header;
pub mod receive;
pub use header::FixedHeader;
pub mod send;

pub use receive::{Association, Opened, Reader, SessionReplay};
pub use send::Writer;

/// 请求流固定头 type（客户端→服务端，SIP022 `HeaderTypeClientStream`）。
pub const TYPE_REQUEST: u8 = 0x00;
/// 响应流固定头 type（服务端→客户端，SIP022 `HeaderTypeServerStream`）。
pub const TYPE_RESPONSE: u8 = 0x01;
/// 请求固定头明文长度：type(1) + timestamp(8) + length(2) = 11 字节。
pub const REQUEST_FIXED_HEADER_LEN: usize = 1 + TIMESTAMP_LEN + LENGTH_FIELD_LEN;
/// 固定头 length 字段宽度（u16be）。
pub const LENGTH_FIELD_LEN: usize = 2;
/// 变长头内 padding 长度字段宽度（u16be，SIP022 原生字段）。
pub const PADDING_FIELD_LEN: usize = 2;
/// 时间戳字段宽度（u64be）。
pub const TIMESTAMP_LEN: usize = 8;
/// 响应固定头中 request salt 之前的字节数：type(1) + timestamp(8)。
pub const RESPONSE_HEADER_HEAD_LEN: usize = 1 + TIMESTAMP_LEN;
/// 变长头明文声明长上限（SIP022 该字段是 u16be，满值即协议上限）。
pub const MAX_VAR_HEADER_LEN: u16 = u16::MAX;
/// 单个 chunk 载荷上限，直接取 `ss_core::chunk`，不在本 crate 另立策略：发送侧超过它
/// 无法成帧，接收侧声明超过它也不可能读到，一律拒绝。
pub const MAX_CHUNK_PAYLOAD: usize = ss_core::chunk::MAX_CHUNK_PAYLOAD;
/// 填充声明长上限（SIP022 `MaxPaddingLength = 900`，`MinPaddingLength = 0`）。
pub const MAX_PADDING_LEN: u16 = 900;
/// 时间戳允许偏差秒数（SIP022：超过 30 秒必须按重放处理）。
pub const TIMESTAMP_WINDOW_SECS: u64 = 30;

/// salt 长度：SIP022 §2.2 规定 salt 与 PSK 等长，两个方向一致。
pub fn salt_len(key: &Key) -> usize {
    key.method().key_len()
}

/// 该方向固定头明文字节数：请求 11；响应 `9 + salt_len + 2` = 27（salt 16）/ 43（salt 32）。
pub fn fixed_header_len(direction: Direction, salt_len: usize) -> usize {
    match direction {
        Direction::Request => REQUEST_FIXED_HEADER_LEN,
        Direction::Response => RESPONSE_HEADER_HEAD_LEN + salt_len + LENGTH_FIELD_LEN,
    }
}

/// 该方向固定头线上长度（明文 + 认证标签）。
pub fn fixed_header_wire_len(direction: Direction, salt_len: usize) -> usize {
    fixed_header_len(direction, salt_len) + TAG_LEN
}

/// 流方向：决定固定头 type、是否回传请求 salt、以及是否存在变长头 chunk。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// 客户端→服务端：11 字节固定头声明变长头长，随后一个变长头 chunk。
    Request,
    /// 服务端→客户端：固定头原样回传请求 salt，其后直接是载荷 chunk。
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

    /// 对端方向（响应流归属回请求流时使用）。
    pub fn peer(self) -> Self {
        match self {
            Self::Request => Self::Response,
            Self::Response => Self::Request,
        }
    }

    /// 该方向固定头是否携带 request salt（只有响应携带）。
    pub fn carries_request_salt(self) -> bool {
        self == Self::Response
    }

    /// 该方向是否有独立的变长头 chunk（§3.1.2：响应开场只有固定头 chunk）。
    pub fn has_variable_header(self) -> bool {
        self == Self::Request
    }
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

/// 请求流开场标识：只有随机 salt（SIP022 TCP 固定头没有会话标识字段）。
/// salt 长度必须等于套件密钥长度（aes-128-gcm 16 字节，aes-256-gcm 32 字节）。
pub struct Opening {
    salt: Vec<u8>,
}

impl Opening {
    /// 用系统随机数生成 salt。
    pub fn random(key: &Key) -> Result<Self, Error> {
        Ok(Self {
            salt: random_bytes(key.method().key_len())?,
        })
    }
    /// 显式注入 salt（测试与确定性场景）。
    pub fn injected(salt: &[u8]) -> Self {
        Self {
            salt: salt.to_vec(),
        }
    }
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
    pub(crate) fn check_salt(&self, key: &Key) -> Result<(), Error> {
        if self.salt.len() == key.method().key_len() {
            Ok(())
        } else {
            Err(Error::KeyLength)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Method;

    #[test]
    fn fixed_header_lengths_match_spec_per_direction() {
        // §3.1.3：请求 11 字节；响应 27（salt 16）/ 43（salt 32）。
        assert_eq!(fixed_header_len(Direction::Request, 16), 11);
        assert_eq!(fixed_header_len(Direction::Request, 32), 11);
        assert_eq!(fixed_header_len(Direction::Response, 16), 27);
        assert_eq!(fixed_header_len(Direction::Response, 32), 43);
        // 线上长度 = 明文 + 16 字节标签（§3.1.2 表格 11B+16B / 27B 或 43B+16B）。
        assert_eq!(fixed_header_wire_len(Direction::Request, 16), 27);
        assert_eq!(fixed_header_wire_len(Direction::Response, 16), 43);
        assert_eq!(fixed_header_wire_len(Direction::Response, 32), 59);
        assert_eq!(REQUEST_FIXED_HEADER_LEN, 11);
    }

    #[test]
    fn direction_semantics_follow_spec() {
        assert_eq!(Direction::Request.header_type(), TYPE_REQUEST);
        assert_eq!(Direction::Response.header_type(), TYPE_RESPONSE);
        assert_eq!(Direction::Request.peer(), Direction::Response);
        assert!(!Direction::Request.carries_request_salt());
        assert!(Direction::Response.carries_request_salt());
        assert!(Direction::Request.has_variable_header());
        assert!(!Direction::Response.has_variable_header());
    }

    #[test]
    fn salt_length_must_match_suite_key() {
        let key = Key::new(Method::Aes256, &[0x22; 32]).unwrap();
        assert!(matches!(
            Opening::injected(&[0; 16]).check_salt(&key),
            Err(Error::KeyLength)
        ));
        assert!(Opening::injected(&[0; 32]).check_salt(&key).is_ok());
        assert_eq!(salt_len(&key), 32);
        assert_eq!(
            salt_len(&Key::new(Method::Aes128, &[0x11; 16]).unwrap()),
            16
        );
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
