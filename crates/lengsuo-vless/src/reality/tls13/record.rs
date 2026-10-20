//! TLS 1.3 记录层（RFC 8446 §5）。
//!
//! 参考实现对应 `xtls/reality` 的 `conn.go`（`readRecord` / `writeRecord`）与
//! `cipher_suites.go`（`aead`）。本模块只实现 `TLS_AES_128_GCM_SHA256`
//! 这一条套件（REALITY 服务端与 Xray 的 REALITY 客户端都能接受）。
//!
//! # 关键点
//!
//! * **明文格式**：应用数据后跟 1 字节「内容类型」，再跟 0 字节填充
//!   （RFC 8446 §5.2）。加密时 AAD = 5 字节记录头（type=`0x17`、
//!   legacy_version=`0x0303`、length）。
//! * **nonce**：`iv XOR seq`（seq 为 64 位大端放在 12 字节 nonce 的低 8 字节）。
//! * **记录层不单独加 MAC**：AEAD 自带认证标签。
//!
//! 本模块不含 `unsafe`，密钥与 IV 用完即清零（`zeroize`）。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm;
use thiserror::Error;
use zeroize::Zeroize;

use super::schedule::{TrafficKey, KEY_LEN, NONCE_LEN};

/// 记录层错误。全部 fail-closed：解封失败一律返回错误，不返回明文。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordError {
    /// 记录头非法（版本不是 0x0303，或类型未知）。
    #[error("TLS record: malformed header")]
    MalformedHeader,
    /// AEAD 解封失败（标签不符）。
    #[error("TLS record: decryption failed")]
    DecryptFailed,
    /// 内层明文太短（没有内容类型字节）。
    #[error("TLS record: inner plaintext too short")]
    InnerTooShort,
    /// 记录类型不是本层预期的那一个。
    #[error("TLS record: unexpected type {0}")]
    UnexpectedType(u8),
    /// 底层 I/O 错误。
    #[error("TLS record: io error: {0}")]
    Io(String),
}

/// 记录层内容类型。
pub mod content_type {
    /// `change_cipher_spec`（兼容中间件用，TLS 1.3 里不承载机密数据）。
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    /// `alert`。
    pub const ALERT: u8 = 21;
    /// `handshake`。
    pub const HANDSHAKE: u8 = 22;
    /// `application_data`。
    pub const APPLICATION_DATA: u8 = 23;
}

/// 记录头长度（RFC 8446 §5.1）。
pub const RECORD_HEADER_LEN: usize = 5;

/// 明文记录层：一把 AEAD 密钥 + 序号。
///
/// 读写方向各持一个实例（TLS 1.3 的密钥方向性）。
pub struct RecordLayer {
    cipher: Aes128Gcm,
    iv: [u8; NONCE_LEN],
    sequence: u64,
}

impl core::fmt::Debug for RecordLayer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecordLayer")
            .field("cipher", &"<redacted>")
            .field("sequence", &self.sequence)
            .finish()
    }
}

impl RecordLayer {
    /// 用流量密钥建立记录层。
    pub fn new(key: &TrafficKey) -> Self {
        Self {
            cipher: Aes128Gcm::new_from_slice(&key.key).expect("AES-128 密钥长度固定为 16"),
            iv: key.iv,
            sequence: 0,
        }
    }

    /// 当前序号（用于测试与诊断）。
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// 复制出一个**独立**的记录层实例（密钥与 IV 相同，序号各自从当前值起步）。
    ///
    /// TLS 1.3 的每个方向只有**一条**记录层序列，序号必须严格递增。
    /// 但握手驱动需要把「同一方向的记录层」同时交给两个消费者
    /// （例如：状态机持有的那一份用于诊断/自证，真正收发的那一份用于
    /// 读写）。直接共享同一个实例会让序号被推进两次，导致对端解封失败。
    ///
    /// 本方法复制密钥与 IV 并**保留当前序号**，因此两个实例可以并行推进
    /// 而互不干扰；调用方必须保证**只有一个**实例真正收发记录。
    pub fn clone_layer(&self) -> Self {
        Self {
            cipher: self.cipher.clone(),
            iv: self.iv,
            sequence: self.sequence,
        }
    }

    /// 计算 nonce：`iv XOR seq`（seq 占低 8 字节，大端）。
    fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = self.iv;
        let seq = self.sequence.to_be_bytes();
        for (i, byte) in seq.iter().enumerate() {
            nonce[NONCE_LEN - 8 + i] ^= byte;
        }
        nonce
    }

    /// 把一段明文（已含内容类型字节）封成一条记录。
    ///
    /// `inner` 是「内容类型 + 明文」；本函数**不再**追加内容类型。
    pub fn seal(&mut self, inner: &[u8]) -> Result<Vec<u8>, RecordError> {
        let plaintext_len = inner.len();
        // 记录长度 = 明文 + AEAD 标签长度（16）。
        let total = plaintext_len + 16;
        if total > u16::MAX as usize {
            return Err(RecordError::MalformedHeader);
        }
        let nonce = self.nonce();
        let mut header = [0u8; RECORD_HEADER_LEN];
        header[0] = content_type::APPLICATION_DATA;
        header[1..3].copy_from_slice(&0x0303u16.to_be_bytes());
        header[3..5].copy_from_slice(&(total as u16).to_be_bytes());
        let sealed = self
            .cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: inner,
                    aad: &header,
                },
            )
            .map_err(|_| RecordError::DecryptFailed)?;
        self.sequence = self.sequence.wrapping_add(1);
        let mut out = Vec::with_capacity(RECORD_HEADER_LEN + sealed.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// 封一条握手记录（内容类型 `handshake`）。
    pub fn seal_handshake(&mut self, payload: &[u8]) -> Result<Vec<u8>, RecordError> {
        let mut inner = Vec::with_capacity(payload.len() + 1);
        inner.extend_from_slice(payload);
        inner.push(content_type::HANDSHAKE);
        self.seal(&inner)
    }

    /// 封一条应用数据记录（内容类型 `application_data`）。
    pub fn seal_application(&mut self, payload: &[u8]) -> Result<Vec<u8>, RecordError> {
        let mut inner = Vec::with_capacity(payload.len() + 1);
        inner.extend_from_slice(payload);
        inner.push(content_type::APPLICATION_DATA);
        self.seal(&inner)
    }

    /// 解一条记录，返回 `(内容类型, 明文)`。
    ///
    /// 失败一律返回 [`RecordError`]，**不返回部分明文**。
    pub fn open(&mut self, record: &[u8]) -> Result<(u8, Vec<u8>), RecordError> {
        if record.len() < RECORD_HEADER_LEN + 16 {
            return Err(RecordError::MalformedHeader);
        }
        if record[1..3] != 0x0303u16.to_be_bytes() {
            return Err(RecordError::MalformedHeader);
        }
        let length = usize::from(u16::from_be_bytes([record[3], record[4]]));
        if length != record.len() - RECORD_HEADER_LEN {
            return Err(RecordError::MalformedHeader);
        }
        let nonce = self.nonce();
        let opened = self
            .cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &record[RECORD_HEADER_LEN..],
                    aad: &record[..RECORD_HEADER_LEN],
                },
            )
            .map_err(|_| RecordError::DecryptFailed)?;
        self.sequence = self.sequence.wrapping_add(1);
        // 内层明文：去掉尾部填充零字节后，最后一个非零字节是内容类型。
        let mut end = opened.len();
        while end > 0 && opened[end - 1] == 0 {
            end -= 1;
        }
        if end == 0 {
            return Err(RecordError::InnerTooShort);
        }
        let content = opened[end - 1];
        let payload = opened[..end - 1].to_vec();
        Ok((content, payload))
    }
}

impl Drop for RecordLayer {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

/// AEAD 密钥长度（TLS_AES_128_GCM_SHA256）。
pub const AEAD_KEY_LEN: usize = KEY_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::hash::sha::sha256;

    fn key_from(bytes: &[u8]) -> TrafficKey {
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&bytes[..KEY_LEN]);
        let mut iv = [0u8; NONCE_LEN];
        iv.copy_from_slice(&bytes[KEY_LEN..KEY_LEN + NONCE_LEN]);
        TrafficKey { key, iv }
    }

    #[test]
    fn roundtrip_application_data() {
        // 记录层是对称的：同一把密钥分别用于读写两个方向。
        let mut client = RecordLayer::new(&key_from(&sha256(b"shared traffic")));
        let mut server = RecordLayer::new(&key_from(&sha256(b"shared traffic")));
        let wire = client.seal_application(b"hello reality").unwrap();
        let (content, payload) = server.open(&wire).unwrap();
        assert_eq!(content, content_type::APPLICATION_DATA);
        assert_eq!(payload, b"hello reality");
    }

    #[test]
    fn record_header_layout_matches_rfc8446() {
        let mut layer = RecordLayer::new(&key_from(&sha256(b"k")));
        let wire = layer.seal_handshake(b"abc").unwrap();
        assert_eq!(wire[0], content_type::APPLICATION_DATA);
        assert_eq!(&wire[1..3], &[0x03, 0x03]);
        // 长度 = 内层明文（3 + 1 字节内容类型）+ 16 字节标签。
        assert_eq!(u16::from_be_bytes([wire[3], wire[4]]) as usize, 3 + 1 + 16);
    }

    #[test]
    fn tampered_record_fails_closed() {
        let mut client = RecordLayer::new(&key_from(&sha256(b"a")));
        let mut server = RecordLayer::new(&key_from(&sha256(b"a")));
        let mut wire = client.seal_application(b"payload").unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        assert_eq!(server.open(&wire), Err(RecordError::DecryptFailed));
    }

    #[test]
    fn wrong_direction_key_fails_closed() {
        let mut client = RecordLayer::new(&key_from(&sha256(b"a")));
        let mut server = RecordLayer::new(&key_from(&sha256(b"b")));
        let wire = client.seal_application(b"payload").unwrap();
        assert_eq!(server.open(&wire), Err(RecordError::DecryptFailed));
    }

    #[test]
    fn sequence_numbers_are_distinct_per_record() {
        let mut client = RecordLayer::new(&key_from(&sha256(b"a")));
        let mut server = RecordLayer::new(&key_from(&sha256(b"a")));
        let first = client.seal_application(b"one").unwrap();
        let second = client.seal_application(b"two").unwrap();
        assert_ne!(first, second);
        // 序号必须严格递增，否则服务端读第二条会失败。
        assert_eq!(client.sequence(), 2);
        let (_, one) = server.open(&first).unwrap();
        let (_, two) = server.open(&second).unwrap();
        assert_eq!(one, b"one");
        assert_eq!(two, b"two");
    }

    #[test]
    fn malformed_headers_rejected() {
        let mut layer = RecordLayer::new(&key_from(&sha256(b"a")));
        assert_eq!(layer.open(b"short"), Err(RecordError::MalformedHeader));
        let mut wire = layer.seal_application(b"x").unwrap();
        wire[1] = 0x02;
        let mut server = RecordLayer::new(&key_from(&sha256(b"a")));
        assert_eq!(server.open(&wire), Err(RecordError::MalformedHeader));
    }
}
