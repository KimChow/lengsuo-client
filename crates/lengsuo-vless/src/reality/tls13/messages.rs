//! TLS 1.3 握手消息的构造与解析（RFC 8446 §4）。
//!
//! 参考实现对应 `xtls/reality` 的 `handshake_messages.go`
//! （`clientHelloMsg.unmarshal` / `serverHelloMsg.unmarshal`）与
//! `handshake_server_tls13.go`（服务端构造 ServerHello）。
//!
//! 本模块只覆盖 REALITY 需要的那部分：
//!
//! * 客户端构造 ClientHello（TLS 1.3 + `x25519` key_share + SNI）。
//! * 解析 ClientHello 里的 SNI 与 X25519 key_share（服务端用）。
//! * 解析 ServerHello（客户端用）。
//!
//! **不实现** HelloRetryRequest、PSK、ECH、ML-KEM、压缩、证书压缩。
//!
//! # 文件拆分
//!
//! 单文件超过 700 行硬上限后拆成三个：
//!
//! | 文件 | 内容 |
//! |---|---|
//! | 本文件 | 常量、错误类型、握手消息的**分帧**、字节游标 |
//! | [`client`] | ClientHello 的构造与解析 |
//! | [`server`] | ServerHello 的解析与 `key_share` 布局 |
//!
//! 公开 API **保持不变**：拆出去的条目都从这里 `pub use` 重新导出，
//! 调用方仍然写 `messages::build_client_hello` 这样的路径。

use thiserror::Error;

mod client;
mod server;

#[cfg(test)]
mod tests;

pub use client::{build_client_hello, parse_client_hello, ClientHelloInfo, ClientHelloParams};
pub use server::{parse_server_hello, parse_server_key_share, ServerHelloInfo, ServerKeyShare};

/// 握手消息类型。
pub mod handshake_type {
    /// `client_hello`。
    pub const CLIENT_HELLO: u8 = 1;
    /// `server_hello`。
    pub const SERVER_HELLO: u8 = 2;
    /// `new_session_ticket`。
    pub const NEW_SESSION_TICKET: u8 = 4;
    /// `encrypted_extensions`。
    pub const ENCRYPTED_EXTENSIONS: u8 = 8;
    /// `certificate`。
    pub const CERTIFICATE: u8 = 11;
    /// `certificate_verify`。
    pub const CERTIFICATE_VERIFY: u8 = 15;
    /// `finished`。
    pub const FINISHED: u8 = 20;
}

/// 扩展类型。
pub mod extension {
    /// `server_name`（RFC 6066）。
    pub const SERVER_NAME: u16 = 0x0000;
    /// `supported_groups`（RFC 8446 §4.2.7）。
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    /// `signature_algorithms`（RFC 8446 §4.2.3）。
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    /// `application_layer_protocol_negotiation`（RFC 7301）。
    pub const ALPN: u16 = 0x0010;
    /// `supported_versions`（RFC 8446 §4.2.1）。
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    /// `key_share`（RFC 8446 §4.2.8）。
    pub const KEY_SHARE: u16 = 0x0033;
}

/// 命名组 `x25519`（RFC 8446 §4.2.7）。
pub const GROUP_X25519: u16 = 0x001d;
/// TLS 1.3 版本号（RFC 8446 §4.1.2 的 `supported_versions` 取值）。
pub const VERSION_TLS13: u16 = 0x0304;
/// 记录层 legacy 版本号（TLS 1.2 = 0x0303）。
pub const LEGACY_VERSION: u16 = 0x0303;
/// 密码套件 `TLS_AES_128_GCM_SHA256`。
pub const CIPHER_SUITE_AES_128_GCM_SHA256: u16 = 0x1301;
/// `TLS_AES_256_GCM_SHA384`。
pub const CIPHER_SUITE_AES_256_GCM_SHA384: u16 = 0x1302;
/// 签名算法 `ed25519`（RFC 8422）。
pub const SIG_ED25519: u16 = 0x0807;

/// 握手消息解析错误。全部 fail-closed。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MessageError {
    /// 缓冲区不足以容纳消息头。
    #[error("TLS message: truncated")]
    Truncated,
    /// 消息长度字段与实际字节数不符。
    #[error("TLS message: length mismatch")]
    LengthMismatch,
    /// 不是期望的消息类型。
    #[error("TLS message: unexpected type {0}")]
    UnexpectedType(u8),
    /// 扩展结构畸形。
    #[error("TLS message: malformed extension")]
    MalformedExtension,
    /// 未找到必需的扩展。
    #[error("TLS message: missing extension {0}")]
    MissingExtension(u16),
    /// SNI 不是合法的 host_name。
    #[error("TLS message: malformed server name")]
    MalformedServerName,
}

/// 写一个 `u16` 长度前缀的向量。
fn put_u16_vec(out: &mut Vec<u8>, payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

/// 写一个 `u8` 长度前缀的向量。
fn put_u8_vec(out: &mut Vec<u8>, payload: &[u8]) {
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
}

/// 写一条握手消息（4 字节头 + 载荷）。
pub fn put_handshake(out: &mut Vec<u8>, kind: u8, payload: &[u8]) {
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(payload);
}

/// 解析出一条握手消息，返回 `(类型, 载荷, 消耗字节数)`。
///
/// 只解析**第一条**消息；调用方按消耗字节数继续解析后续消息。
pub fn parse_handshake(input: &[u8]) -> Result<(u8, &[u8], usize), MessageError> {
    if input.len() < 4 {
        return Err(MessageError::Truncated);
    }
    let kind = input[0];
    let len = u32::from_be_bytes([0, input[1], input[2], input[3]]) as usize;
    if input.len() < 4 + len {
        return Err(MessageError::Truncated);
    }
    Ok((kind, &input[4..4 + len], 4 + len))
}

/// 从流式缓冲里取出一条完整握手消息。
///
/// 返回 `None` 表示还需要更多字节。
pub fn take_handshake(buffer: &mut Vec<u8>) -> Result<Option<(u8, Vec<u8>)>, MessageError> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([0, buffer[1], buffer[2], buffer[3]]) as usize;
    if buffer.len() < 4 + len {
        return Ok(None);
    }
    let kind = buffer[0];
    let payload = buffer[4..4 + len].to_vec();
    buffer.drain(..4 + len);
    Ok(Some((kind, payload)))
}

/// 往扩展列表里追加一条扩展。
fn push_ext(exts: &mut Vec<u8>, kind: u16, data: &[u8]) {
    exts.extend_from_slice(&kind.to_be_bytes());
    exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
    exts.extend_from_slice(data);
}

/// 取一条扩展，返回 `(类型, 数据, 剩余)`。
fn take_ext(input: &[u8]) -> Result<(u16, &[u8], &[u8]), MessageError> {
    if input.len() < 4 {
        return Err(MessageError::MalformedExtension);
    }
    let kind = u16::from_be_bytes([input[0], input[1]]);
    let len = usize::from(u16::from_be_bytes([input[2], input[3]]));
    let data = input
        .get(4..4 + len)
        .ok_or(MessageError::MalformedExtension)?;
    Ok((kind, data, &input[4 + len..]))
}

/// 字节游标。
struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset >= self.input.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], MessageError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(MessageError::Truncated)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(MessageError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, MessageError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, MessageError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u8_vec(&mut self) -> Result<&'a [u8], MessageError> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    fn u16_vec(&mut self) -> Result<&'a [u8], MessageError> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }
}
