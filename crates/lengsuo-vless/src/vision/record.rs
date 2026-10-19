//! VLESS Vision AEAD 记录层：对齐 `common.go` 的 `NewAEAD` / `AEAD` /
//! `IncreaseNonce` / `EncodeLength` / `DecodeLength` / `EncodeHeader` /
//! `DecodeHeader`，并按 `CommonConn.Write/Read` 的记录路径封装/解封。
//!
//! 与 [`crate::xel`] 的差异在密钥派生（见 [`crate::vision`] 模块文档）：本模块的
//! [`Aead::new`] 按参考 `NewAEAD(ctx, key, useAES)` 用 `blake3::derive_key(ctx, key)`
//! 从原始握手材料派生 32 字节密钥，ctx 是握手上下文而非已派生密钥。
//!
//! **与参考的有意偏离（取更严格，全部不可达/在报告偏离清单说明）**：
//! - 参考 nonce 计满 `MaxNonce` 后改用刚产出的记录字节重派生密钥；本实现把
//!   96 位 nonce 用尽视为 fail-closed（[`Error::NonceExhausted`]）。96 位 nonce
//!   在单个连接生命周期内不可达，且参考的二进制 ctx 重派生与 Rust blake3
//!   仅接受 `&str` context 的差异同源，故不重派生。
//! - `DecodeHeader` 参考在魔数不符时把长度清 0 后仍返回 `(0, err)`；本实现直接
//!   返回 [`Error::InvalidHeader`]，语义等价（长度 0 本就落入越界分支）。
//!
//! 本模块不含 `unsafe`。

use aes_gcm::aead::generic_array::typenum::U12;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead as _;
use aes_gcm::aead::Payload;
use aes_gcm::{Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;

/// 记录头魔数（`EncodeHeader`：`h[0]=23, h[1]=3, h[2]=3`）。
pub const MAGIC: [u8; 3] = [23, 3, 3];
/// 记录头长度：3 字节魔数 + BE16 记录体长度前缀。
pub const HEADER_LEN: usize = 5;
/// 记录体最小长度（`DecodeHeader` 的 `l < 17` 判据，即 1 字节明文 + 16 字节 tag）。
pub const MIN_BODY_LEN: usize = 17;
/// 记录体最大长度（TLS 1.3 16384 + 256，RFC 8446 §5.2）。
pub const MAX_BODY_LEN: usize = 16640;
/// `CommonConn.Write` 的单次明文分块上限（8192）。
pub const RECORD_CHUNK: usize = 8192;
/// 两套 AEAD 的 nonce 长度（`common.go` 的 `[12]byte`）。
pub const NONCE_LEN: usize = 12;
/// 两套 AEAD 的 tag 长度。
pub const TAG_LEN: usize = 16;
/// 参考 `MaxNonce`（96 位全 1）。
pub const MAX_NONCE: [u8; NONCE_LEN] = [0xFF; NONCE_LEN];

/// AEAD 套件（`common.go` 的 `useAES` 二选一）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// AES-256-GCM。
    Aes256Gcm,
    /// ChaCha20-Poly1305。
    ChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("记录头非法")]
    InvalidHeader,
    #[error("记录体长度越界：{got} 字节，允许 {min}..={max}")]
    InvalidRecordLength { got: usize, min: usize, max: usize },
    #[error("记录认证失败")]
    AuthFailed,
    #[error("nonce 已用尽，必须重新握手")]
    NonceExhausted,
    #[error("记录截断：需要 {need} 字节，只有 {got} 字节")]
    Truncated { need: usize, got: usize },
    #[error("状态已 poison，必须弃用整条流")]
    Poisoned,
}

/// 参考 `EncodeLength`：BE16 长度。
pub fn encode_length(length: usize) -> [u8; 2] {
    [(length >> 8) as u8, length as u8]
}

/// 参考 `DecodeLength`。
pub fn decode_length(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 8) | usize::from(bytes[1])
}

/// 参考 `EncodeHeader`：`h[0..3] = 23,3,3` + BE16 记录体长度。
pub fn encode_header(header: &mut [u8; HEADER_LEN], body_len: usize) {
    header[0] = MAGIC[0];
    header[1] = MAGIC[1];
    header[2] = MAGIC[2];
    header[3] = (body_len >> 8) as u8;
    header[4] = body_len as u8;
}

/// 参考 `DecodeHeader`：魔数不符或长度越界即失败；成功返回记录体长度。
pub fn decode_header(header: &[u8; HEADER_LEN]) -> Result<usize, Error> {
    let mut body_len = decode_length(&header[3..5]);
    if header[..3] != MAGIC {
        // 参考把长度清 0 后继续；0 < 17 必然落入越界分支，此处直接报非法头。
        body_len = 0;
    }
    if !(MIN_BODY_LEN..=MAX_BODY_LEN).contains(&body_len) {
        return Err(Error::InvalidHeader);
    }
    Ok(body_len)
}

/// 参考 `IncreaseNonce`：96 位大端自增（从 `nonce[11]` 起向低位进位）。
pub fn increase_nonce(nonce: &mut [u8; NONCE_LEN]) -> &mut [u8; NONCE_LEN] {
    for index in (0..NONCE_LEN).rev() {
        nonce[index] = nonce[index].wrapping_add(1);
        if nonce[index] != 0 {
            break;
        }
    }
    nonce
}

fn nonce_array(nonce: &[u8]) -> GenericArray<u8, U12> {
    debug_assert_eq!(nonce.len(), NONCE_LEN);
    let mut array = GenericArray::<u8, U12>::default();
    array.copy_from_slice(nonce);
    array
}

/// 两套 AEAD 的具体后端。
enum Backend {
    Aes(Box<Aes256Gcm>),
    ChaCha(ChaCha20Poly1305),
}

impl core::fmt::Debug for Backend {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Backend([REDACTED])")
    }
}

/// 参考 `common.go` 的 `AEAD`：内部 96 位 nonce + AEAD 后端。
pub struct Aead {
    backend: Backend,
    nonce: [u8; NONCE_LEN],
}

impl core::fmt::Debug for Aead {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Aead")
            .field("nonce", &self.nonce)
            .field("backend", &"[REDACTED]")
            .finish()
    }
}

impl Aead {
    /// 参考 `NewAEAD(ctx, key, useAES)`：`blake3::derive_key(ctx, key)` 派生 32 字节密钥。
    ///
    /// `key` 为握手材料（`nfsKey` / `UnitedKey` 等，长度不拘，参考先 blake3 派生）；
    /// `ctx` 为派生上下文。Rust blake3 仅接受 `&str` context，非 UTF-8 的握手上下文
    /// 见模块文档偏离说明（本卡不做二进制定长 context，取 fail-closed/报告）。
    pub fn new(ctx: &str, key: &[u8], cipher: Cipher) -> Self {
        let derived: [u8; 32] = blake3::derive_key(ctx, key);
        let backend = match cipher {
            Cipher::Aes256Gcm => Backend::Aes(Box::new(
                Aes256Gcm::new_from_slice(&derived).expect("32 字节密钥"),
            )),
            Cipher::ChaCha20Poly1305 => {
                Backend::ChaCha(ChaCha20Poly1305::new_from_slice(&derived).expect("32 字节密钥"))
            }
        };
        Self {
            backend,
            nonce: [0u8; NONCE_LEN],
        }
    }

    /// 当前 nonce（下一次自动取用前的值；参考先加后用）。
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// 参考 `AEAD.Seal`：`nonce == None` 时先 [`increase_nonce`] 再使用。
    pub fn seal(
        &mut self,
        nonce: Option<&[u8]>,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce: &[u8] = match nonce {
            Some(explicit) => explicit,
            None => {
                if self.nonce == MAX_NONCE {
                    return Err(Error::NonceExhausted);
                }
                increase_nonce(&mut self.nonce)
            }
        };
        debug_assert_eq!(nonce.len(), NONCE_LEN);
        let payload = Payload {
            msg: plaintext,
            aad: additional_data,
        };
        match &self.backend {
            Backend::Aes(aead) => aead.encrypt(&nonce_array(nonce), payload),
            Backend::ChaCha(aead) => aead.encrypt(&nonce_array(nonce), payload),
        }
        .map_err(|_| Error::AuthFailed)
    }

    /// 参考 `AEAD.Open`：`nonce == None` 时先 [`increase_nonce`] 再使用。
    pub fn open(
        &mut self,
        nonce: Option<&[u8]>,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce: &[u8] = match nonce {
            Some(explicit) => explicit,
            None => {
                if self.nonce == MAX_NONCE {
                    return Err(Error::NonceExhausted);
                }
                increase_nonce(&mut self.nonce)
            }
        };
        debug_assert_eq!(nonce.len(), NONCE_LEN);
        let payload = Payload {
            msg: ciphertext,
            aad: additional_data,
        };
        match &self.backend {
            Backend::Aes(aead) => aead.decrypt(&nonce_array(nonce), payload),
            Backend::ChaCha(aead) => aead.decrypt(&nonce_array(nonce), payload),
        }
        .map_err(|_| Error::AuthFailed)
    }
}

/// AEAD 记录发送方向（对齐 `CommonConn.Write`：按 8192 分块，5 字节头作 AAD）。
#[derive(Debug)]
pub struct RecordWriter {
    aead: Aead,
}

impl RecordWriter {
    pub fn new(ctx: &str, key: &[u8], cipher: Cipher) -> Self {
        Self {
            aead: Aead::new(ctx, key, cipher),
        }
    }

    pub fn is_poisoned(&self) -> bool {
        false // 发送方向只有 nonce 用尽才失败，失败即返回错误并弃用实例
    }

    /// 已使用记录数（= 已消耗 nonce 次数；仅诊断）。
    pub fn sequence(&self) -> u64 {
        let mut count = 0u64;
        for byte in &self.aead.nonce {
            count = (count << 8) | u64::from(*byte);
        }
        count
    }

    /// 把整段明文按参考分块封成连续记录字节（头 + 密文||tag）。
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        for chunk in plaintext.chunks(RECORD_CHUNK) {
            let body_len = chunk.len() + TAG_LEN;
            if body_len > MAX_BODY_LEN {
                return Err(Error::InvalidRecordLength {
                    got: body_len,
                    min: MIN_BODY_LEN,
                    max: MAX_BODY_LEN,
                });
            }
            let mut header = [0u8; HEADER_LEN];
            encode_header(&mut header, body_len);
            let body = self.aead.seal(None, chunk, &header)?;
            out.extend_from_slice(&header);
            out.extend_from_slice(&body);
        }
        Ok(out)
    }
}

/// AEAD 记录接收方向（对齐 `CommonConn.Read`：重组成完整记录并按序解封）。
pub struct RecordReader {
    pending: Vec<u8>,
    aead: Aead,
    poisoned: bool,
}

impl RecordReader {
    pub fn new(ctx: &str, key: &[u8], cipher: Cipher) -> Self {
        Self {
            pending: Vec::with_capacity(HEADER_LEN + MIN_BODY_LEN),
            aead: Aead::new(ctx, key, cipher),
            poisoned: false,
        }
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// 追加线上字节；凑不齐一条记录属于正常等待。
    pub fn push(&mut self, wire: &[u8]) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.pending.len().saturating_add(wire.len()) > HEADER_LEN + MAX_BODY_LEN {
            let got = self.pending.len() + wire.len();
            self.poisoned = true;
            self.pending.clear();
            return Err(Error::InvalidRecordLength {
                got,
                min: MIN_BODY_LEN,
                max: MAX_BODY_LEN,
            });
        }
        self.pending.extend_from_slice(wire);
        Ok(())
    }

    /// 取出下一条记录的明文；不足一条返回 `Ok(None)`。
    pub fn next_plaintext(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.pending.len() < HEADER_LEN {
            return Ok(None);
        }
        let header: [u8; HEADER_LEN] = self.pending[..HEADER_LEN].try_into().expect("5 字节");
        let body_len = decode_header(&header).map_err(|_| self.fail())?;
        let total = HEADER_LEN + body_len;
        if self.pending.len() < total {
            return Ok(None);
        }
        let body = self.pending[HEADER_LEN..total].to_vec();
        let plaintext = match self.aead.open(None, &body, &header) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                self.poisoned = true;
                self.pending.clear();
                return Err(error);
            }
        };
        self.pending.drain(..total);
        Ok(Some(plaintext))
    }

    /// 流结束检查：残字节即截断。
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.pending.is_empty() {
            return Ok(());
        }
        let got = self.pending.len();
        let need = if self.pending.len() >= HEADER_LEN {
            let header: [u8; HEADER_LEN] = self.pending[..HEADER_LEN].try_into().expect("5 字节");
            match decode_header(&header) {
                Ok(body_len) => HEADER_LEN + body_len - got,
                Err(_) => HEADER_LEN - got,
            }
        } else {
            HEADER_LEN - got
        };
        self.poisoned = true;
        self.pending.clear();
        Err(Error::Truncated { need, got })
    }

    fn fail(&mut self) -> Error {
        self.poisoned = true;
        self.pending.clear();
        Error::InvalidHeader
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &str = "vision-record-test-context";
    const KEY: [u8; 32] = [0xA1; 32];

    #[test]
    fn length_and_header_roundtrip() {
        assert_eq!(encode_length(0x1234), [0x12, 0x34]);
        assert_eq!(decode_length(&[0x12, 0x34]), 0x1234);

        let mut header = [0u8; HEADER_LEN];
        encode_header(&mut header, 17);
        assert_eq!(header, [23, 3, 3, 0, 17]);
        assert_eq!(decode_header(&header).unwrap(), 17);

        let mut max = [0u8; HEADER_LEN];
        encode_header(&mut max, MAX_BODY_LEN);
        assert_eq!(&max[..3], &[23, 3, 3]);
        assert_eq!(decode_header(&max).unwrap(), MAX_BODY_LEN);
    }

    #[test]
    fn header_rejects_bad_magic_and_bounds() {
        let mut header = [0u8; HEADER_LEN];
        encode_header(&mut header, 20);
        header[0] = 22;
        assert_eq!(decode_header(&header), Err(Error::InvalidHeader));
        header = [23, 3, 3, 0, 16];
        assert_eq!(decode_header(&header), Err(Error::InvalidHeader)); // 16 < 17
        header = [23, 3, 3, 0x41, 0x01]; // 16641
        assert_eq!(decode_header(&header), Err(Error::InvalidHeader));
    }

    #[test]
    fn nonce_increments_big_endian() {
        let mut nonce = [0u8; NONCE_LEN];
        increase_nonce(&mut nonce);
        assert_eq!(nonce[11], 1);
        let mut carry = [0u8; NONCE_LEN];
        carry[11] = 0xFF;
        increase_nonce(&mut carry);
        assert_eq!(&carry[10..], &[1, 0]);
    }

    /// `Aead::new(ctx, key)` 内部走 `blake3::derive_key`（而非注入已派生密钥），
    /// 且派生结果与 Go `blake3.DeriveKey` 黄金向量一致（同 `xel_golden.rs` 实跑值）。
    #[test]
    fn new_aead_derives_key_from_context_and_material() {
        // Go 实跑：blake3.DeriveKey(32×0x42, 32×0xA1) == 25e1ad…82b9。
        let expected = [
            0x25, 0xe1, 0xad, 0x43, 0x43, 0x23, 0xaf, 0x1a, 0x27, 0x8d, 0x1c, 0xb0, 0xb6, 0x02,
            0xd3, 0x6f, 0xbf, 0x7f, 0xa3, 0xaf, 0xd8, 0xb8, 0x2e, 0x1b, 0x31, 0xd9, 0x28, 0x1b,
            0x7e, 0x6f, 0x82, 0xb9,
        ];
        let ctx = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        assert_eq!(blake3::derive_key(ctx, &[0xA1u8; 32]), expected);
        // 同一派生语境下加密可被对端独立实例解密（跨实例一致性，非注入共享）。
        let mut sender = Aead::new(ctx, &[0xA1u8; 32], Cipher::Aes256Gcm);
        let mut receiver = Aead::new(ctx, &[0xA1u8; 32], Cipher::Aes256Gcm);
        let ct = sender.seal(None, b"probe", b"hdr").unwrap();
        assert_eq!(receiver.open(None, &ct, b"hdr").unwrap(), b"probe");
    }

    #[test]
    fn record_writer_reader_roundtrip_at_every_split() {
        // 写侧按参考把 9000 字节切成 8192 + 808 两条记录，读侧逐「记录」返回明文。
        let payloads: Vec<Vec<u8>> = vec![
            b"first vision record".to_vec(),
            vec![7u8; 1],
            vec![0xEEu8; 400],
            vec![0xCDu8; 9000],
        ];
        let expected: Vec<Vec<u8>> = vec![
            b"first vision record".to_vec(),
            vec![7u8; 1],
            vec![0xEEu8; 400],
            vec![0xCDu8; 8192],
            vec![0xCDu8; 808],
        ];
        for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
            let mut writer = RecordWriter::new(CTX, &KEY, cipher);
            let mut wire = Vec::new();
            for payload in &payloads {
                wire.extend_from_slice(&writer.seal(payload).unwrap());
            }
            for step in [1usize, 2, 5, 22, 40, wire.len()] {
                let mut reader = RecordReader::new(CTX, &KEY, cipher);
                let mut got = Vec::new();
                for chunk in wire.chunks(step) {
                    reader.push(chunk).unwrap();
                    while let Some(plain) = reader.next_plaintext().unwrap() {
                        got.push(plain);
                    }
                }
                reader.finish().unwrap();
                assert_eq!(got, expected, "{cipher:?} 分块步长 {step}");
            }
        }
    }

    #[test]
    fn record_body_is_header_and_tag_length() {
        let mut writer = RecordWriter::new(CTX, &KEY, Cipher::Aes256Gcm);
        let record = writer.seal(b"payload").unwrap();
        assert_eq!(record.len(), HEADER_LEN + 7 + TAG_LEN);
        assert_eq!(&record[..3], &[23, 3, 3]);
        assert_eq!(&record[3..5], &[0, 23]); // 7 + 16
    }

    #[test]
    fn tampered_header_breaks_authentication() {
        let mut writer = RecordWriter::new(CTX, &KEY, Cipher::Aes256Gcm);
        let wire = writer.seal(b"payload").unwrap();
        let mut reader = RecordReader::new(CTX, &KEY, Cipher::Aes256Gcm);
        let mut tampered = wire.clone();
        tampered[4] ^= 0x01;
        reader.push(&tampered).unwrap();
        let outcome = reader.next_plaintext();
        assert!(
            matches!(outcome, Err(Error::InvalidHeader) | Err(Error::AuthFailed)),
            "头部改动必须失败：{outcome:?}"
        );
        assert!(reader.is_poisoned());
    }

    #[test]
    fn truncated_stream_poisons_on_finish() {
        let mut writer = RecordWriter::new(CTX, &KEY, Cipher::Aes256Gcm);
        let wire = writer.seal(b"record body that is long enough").unwrap();
        let mut reader = RecordReader::new(CTX, &KEY, Cipher::Aes256Gcm);
        reader.push(&wire[..wire.len() - 3]).unwrap();
        assert!(reader.next_plaintext().unwrap().is_none());
        assert!(matches!(reader.finish(), Err(Error::Truncated { .. })));
        assert!(reader.is_poisoned());
    }

    #[test]
    fn debug_output_never_contains_key_bytes() {
        let aead = Aead::new(CTX, &[0xA7u8; 32], Cipher::Aes256Gcm);
        let printed = format!("{aead:?}");
        assert!(!printed.contains("167"), "Debug 泄露密钥字节：{printed}");
    }
}
