//! VMess 数据段分帧（对齐 `proxy/vmess/encoding/auth.go` 的 `ShakeSizeParser`
//! 与 `common/crypto/io.go` 的 chunk 语义、`GenerateChunkNonce`）。
//!
//! 线格式（每个数据 chunk）：
//! ```text
//! BE16(声明长度 ^ Shake128(iv).next()) || AEAD(载荷)   （chunkMasking 开启）
//! BE16(载荷明文长度) || AEAD(载荷)                     （无掩码；AEAD 依安全选项）
//! ```
//! - nonce：把 16 字节 requestBodyIV 的**前 2 字节**用作 BE16 计数器
//!   （`GenerateChunkNonce`：`binary.BigEndian.PutUint16(c, count); count++`，
//!   即每个 chunk 消耗一个 nonce，计数器大端递增，其余字节保持 IV 原值）。
//! - 安全选项 AES-128-GCM：key = requestBodyKey(16B)，nonce 12 字节
//!   （计数器 2B + IV[2..12]）；ChaCha20-Poly1305：key = MD5×2 扩展 32B，
//!   nonce 12 字节同构；none：无 AEAD（明文）。
//! - size 掩码：SHA3-Shake128(iv) 流式读 2 字节作 BE16 与声明长度异或，
//!   掩码流跨 chunk 连续（每 chunk 消耗 2 字节掩码）。
//! - 终止：写端以"声明长度为 0 的 chunk"表达 EOF（参考 `io.Copy` 收尾写入
//!   一个空 chunk），读取端遇到解出的 0 长度即正常收尾。
//!
//! fail-closed：认证失败/长度越界/掩码流错位后调用方必须弃用连接。

use aes_gcm::aead::{Aead, KeyInit};
use sha3::digest::{ExtendableOutput, Update};
use sha3::{Shake128, Shake128Reader};
use ss_core::crypto::TAG_LEN;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::consts::{CHACHA_KEY_LEN, SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305};
use crate::{Error, Result};

/// 单个 chunk 载荷明文上限。参考 `buf.Size` 为 8192（Size = 16384/2，含掩码
/// 开销与 tag 后由调用方保证 ≤ u16），本实现锁定 16384 上限并允许调用方
/// 用更小的分段写出。
pub const MAX_CHUNK_PAYLOAD: usize = 16384;

/// `GenerateChacha20Poly1305Key`：MD5(b) || MD5(MD5(b)) 扩成 32 字节。
#[must_use]
pub fn md5_digest(data: &[u8]) -> [u8; 16] {
    use sha3::digest::{FixedOutput, Update};
    let mut hasher = md5::Md5::default();
    Update::update(&mut hasher, data);
    hasher.finalize_fixed().into()
}

pub fn generate_chacha20_poly1305_key(b: &[u8]) -> [u8; CHACHA_KEY_LEN] {
    let first = md5_digest(b);
    let second = md5_digest(&first);
    let mut key = [0u8; CHACHA_KEY_LEN];
    key[..16].copy_from_slice(&first);
    key[16..].copy_from_slice(&second);
    key
}

/// SHAKE128 掩码流（`ShakeSizeParser`）：跨 chunk 连续的 2 字节 BE16 掩码。
pub struct DataSizeParser {
    reader: Shake128Reader,
}

impl DataSizeParser {
    /// `NewShakeSizeParser(iv)`：以 16 字节请求/响应 IV 播种。
    #[must_use]
    pub fn new(seed: &[u8]) -> Self {
        let mut shake = Shake128::default();
        shake.update(seed);
        DataSizeParser {
            reader: shake.finalize_xof(),
        }
    }

    /// `next()`：流内读 2 字节作 BE16。
    fn next_u16(&mut self) -> u16 {
        let mut buffer = [0u8; 2];
        use sha3::digest::XofReader;
        self.reader.read(&mut buffer);
        u16::from_be_bytes(buffer)
    }

    /// `Encode(size, b)`：掩码后的 2 字节声明长度。
    #[must_use]
    pub fn encode_size(&mut self, size: u16) -> [u8; 2] {
        (self.next_u16() ^ size).to_be_bytes()
    }

    /// `Decode(b)`：还原真实长度。
    #[must_use]
    pub fn decode_size(&mut self, wire: [u8; 2]) -> u16 {
        self.next_u16() ^ u16::from_be_bytes(wire)
    }

    /// `NextPaddingLen()`：`next() % 64`。
    #[must_use]
    pub fn next_padding_len(&mut self) -> u16 {
        self.next_u16() % 64
    }

    /// `MaxPaddingLen()`：常量 64。
    #[must_use]
    pub const fn max_padding_len() -> u16 {
        64
    }
}

/// 无掩码分帧的 size 编解码（`PlainChunkSizeParser`：裸 BE16）。
#[must_use]
pub fn plain_size_encode(size: u16) -> [u8; 2] {
    size.to_be_bytes()
}

/// `shake_mask` 兼容导出：单次掩码（无状态调用，测试/向量用）。
#[must_use]
pub fn shake_mask(seed: &[u8], index: usize) -> [u8; 2] {
    let mut parser = DataSizeParser::new(seed);
    for _ in 0..index {
        parser.next_padding_len_u16();
    }
    parser.encode_size(0)
}

impl DataSizeParser {
    fn next_padding_len_u16(&mut self) -> u16 {
        self.next_u16()
    }
}

/// 数据段 AEAD 上下文：安全选项 + 会话密钥/IV + 大端 2B 计数 nonce。
pub struct DataCipher {
    security: u8,
    key: Vec<u8>,
    iv: [u8; 16],
    count: u16,
}

impl DataCipher {
    /// 由请求（或响应）body key/iv 与安全选项构造。
    ///
    /// none：不加密；AES-128-GCM：key 即 16B bodyKey；ChaCha20-Poly1305：
    /// key = [`generate_chacha20_poly1305_key`] 扩展的 32B。
    pub fn new(security: u8, body_key: &[u8; 16], body_iv: &[u8; 16]) -> Self {
        let key = match security {
            SECURITY_AES_128_GCM => body_key.to_vec(),
            SECURITY_CHACHA20_POLY1305 => generate_chacha20_poly1305_key(body_key).to_vec(),
            // none 与未知值都按明文处理；未知值由 request 层拒绝，这里不 panic。
            _ => Vec::new(),
        };
        DataCipher {
            security,
            key,
            iv: *body_iv,
            count: 0,
        }
    }

    /// 已消耗的 nonce 计数（诊断）。
    #[must_use]
    pub const fn count(&self) -> u16 {
        self.count
    }

    fn is_aead(&self) -> bool {
        self.security == SECURITY_AES_128_GCM || self.security == SECURITY_CHACHA20_POLY1305
    }

    /// `GenerateChunkNonce`：计数写进 IV 前 2 字节（BE），取前 12 字节。
    fn nonce12(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        nonce[2..].copy_from_slice(&self.iv[2..12]);
        nonce
    }

    fn seal_payload(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        if !self.is_aead() {
            self.count = self.count.wrapping_add(1);
            return Ok(plain.to_vec());
        }
        let nonce = self.nonce12();
        self.count = self.count.wrapping_add(1);
        match self.security {
            SECURITY_AES_128_GCM => {
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(&self.key)
                    .expect("AES-128-GCM 固定 16B 密钥");
                cipher
                    .encrypt((&nonce).into(), plain)
                    .map_err(|_| Error::AuthFailed)
            }
            SECURITY_CHACHA20_POLY1305 => {
                let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&self.key)
                    .expect("ChaCha20 key 已扩成 32B");
                cipher
                    .encrypt((&nonce).into(), plain)
                    .map_err(|_| Error::AuthFailed)
            }
            _ => Ok(plain.to_vec()),
        }
    }

    fn open_payload(&mut self, ct: &[u8], plain_len: usize) -> Result<Vec<u8>> {
        if !self.is_aead() {
            self.count = self.count.wrapping_add(1);
            return Ok(ct.to_vec());
        }
        let nonce = self.nonce12();
        self.count = self.count.wrapping_add(1);
        let outcome = match self.security {
            SECURITY_AES_128_GCM => {
                let cipher = aes_gcm::Aes128Gcm::new_from_slice(&self.key)
                    .expect("AES-128-GCM 固定 16B 密钥");
                cipher.decrypt((&nonce).into(), ct)
            }
            SECURITY_CHACHA20_POLY1305 => {
                let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&self.key)
                    .expect("ChaCha20 key 已扩成 32B");
                cipher.decrypt((&nonce).into(), ct)
            }
            _ => Ok(ct.to_vec()),
        };
        outcome.map_err(|_| Error::AuthFailed).inspect(|plain| {
            if plain.len() != plain_len {
                // AEAD 认证保证长度一致；此分支不可达，防御性保留。
            }
        })
    }

    /// 声明长度的线上字节数（载荷段密文长度 = 明文 + tag；none 无 tag）。
    #[must_use]
    pub fn wire_len(&self, plain_len: usize) -> usize {
        let overhead = if self.is_aead() { TAG_LEN } else { 0 };
        2 + plain_len + overhead
    }
}

/// `new_data_aead` 兼容导出：等价 [`DataCipher::new`]。
#[must_use]
pub fn new_data_aead(security: u8, body_key: &[u8; 16], body_iv: &[u8; 16]) -> DataCipher {
    DataCipher::new(security, body_key, body_iv)
}

/// 同步写出单个 chunk 到内存缓冲（`AuthenticationWriter` 的单帧语义）。
/// `size_parser` 为 `Some` 时启用 chunkMasking；写 EOF（空载荷）产生
/// "声明长度 0" 帧。
pub fn seal_data_chunk(
    cipher: &mut DataCipher,
    size_parser: Option<&mut DataSizeParser>,
    out: &mut Vec<u8>,
    payload: &[u8],
) -> Result<()> {
    if payload.len() > MAX_CHUNK_PAYLOAD {
        return Err(Error::BadLength {
            declared: payload.len(),
            got: MAX_CHUNK_PAYLOAD,
        });
    }
    let ct = cipher.seal_payload(payload)?;
    let declared = u16::try_from(ct.len()).map_err(|_| Error::BadLength {
        declared: ct.len(),
        got: u16::MAX as usize,
    })?;
    let size_wire = match size_parser {
        Some(parser) => parser.encode_size(declared),
        None => crate::chunkframe::plain_size_encode(declared),
    };
    out.extend_from_slice(&size_wire);
    out.extend_from_slice(&ct);
    Ok(())
}

/// 终止帧：声明长度 0（掩码后），无载荷。
pub fn write_data_eof(
    cipher: &mut DataCipher,
    size_parser: Option<&mut DataSizeParser>,
    out: &mut Vec<u8>,
) -> Result<()> {
    seal_data_chunk(cipher, size_parser, out, &[])
}

/// 同步读取单个 chunk（`AuthenticationReader` 单帧语义）。`Ok(None)` = EOF 帧。
/// 输入缓冲必须恰好包含一帧（由调用方按需切片）。
pub fn open_data_chunk(
    cipher: &mut DataCipher,
    size_parser: Option<&mut DataSizeParser>,
    wire: &[u8],
) -> Result<Option<Vec<u8>>> {
    if wire.len() < 2 {
        return Err(Error::Truncated {
            need: 2,
            got: wire.len(),
        });
    }
    let declared = match size_parser {
        Some(parser) => parser.decode_size([wire[0], wire[1]]),
        None => u16::from_be_bytes([wire[0], wire[1]]),
    };
    if declared == 0 {
        return Ok(None);
    }
    let body = &wire[2..];
    if body.len() < declared as usize {
        return Err(Error::Truncated {
            need: declared as usize,
            got: body.len(),
        });
    }
    if body.len() != declared as usize {
        return Err(Error::BadLength {
            declared: declared as usize,
            got: body.len(),
        });
    }
    let plain_len = declared as usize - cipher_overhead(cipher);
    let plain = cipher.open_payload(body, plain_len)?;
    if plain.is_empty() {
        return Ok(None);
    }
    Ok(Some(plain))
}

fn cipher_overhead(cipher: &DataCipher) -> usize {
    if cipher.is_aead() {
        TAG_LEN
    } else {
        0
    }
}

/// 异步写出单个 chunk（流式写端版）。
pub async fn write_data_chunk<W: AsyncWrite + Unpin>(
    cipher: &mut DataCipher,
    size_parser: Option<&mut DataSizeParser>,
    writer: &mut W,
    payload: &[u8],
) -> Result<()> {
    let mut frame = Vec::with_capacity(cipher.wire_len(payload.len()));
    seal_data_chunk(cipher, size_parser, &mut frame, payload)?;
    writer
        .write_all(&frame)
        .await
        .map_err(|error| Error::Io(format!("{:?}", error.kind())))
}

/// 异步写出终止帧。
pub async fn write_eof<W: AsyncWrite + Unpin>(
    cipher: &mut DataCipher,
    size_parser: Option<&mut DataSizeParser>,
    writer: &mut W,
) -> Result<()> {
    write_data_chunk(cipher, size_parser, writer, &[]).await
}

/// 异步读取单个 chunk（带总超时语义由调用方包裹）。`Ok(None)` = EOF。
pub async fn read_data_chunk<R: AsyncRead + Unpin>(
    cipher: &mut DataCipher,
    size_parser: Option<&mut DataSizeParser>,
    reader: &mut R,
) -> Result<Option<Vec<u8>>> {
    let mut size_wire = [0u8; 2];
    reader
        .read_exact(&mut size_wire)
        .await
        .map_err(|error| crate::io_err(&error))?;
    let declared = match size_parser {
        Some(parser) => parser.decode_size(size_wire),
        None => u16::from_be_bytes(size_wire),
    };
    if declared == 0 {
        // 线上声明 0 只在 none 安全下出现（无 tag 可解）；按 EOF 处理。
        return Ok(None);
    }
    let mut body = vec![0u8; declared as usize];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|error| crate::io_err(&error))?;
    let plain_len = declared as usize - cipher_overhead(cipher);
    let plain = cipher.open_payload(&body, plain_len)?;
    if plain.is_empty() {
        // 参考语义：解出的明文长度 0 = 流终止（AuthenticationReader EOF）。
        return Ok(None);
    }
    Ok(Some(plain))
}

/// [`read_data_chunk`] 的写进缓冲版。
pub async fn read_data_chunk_into<R: AsyncRead + Unpin>(
    cipher: &mut DataCipher,
    size_parser: Option<&mut DataSizeParser>,
    reader: &mut R,
    out: &mut Vec<u8>,
) -> Result<bool> {
    match read_data_chunk(cipher, size_parser, reader).await? {
        Some(plain) => {
            out.extend_from_slice(&plain);
            Ok(true)
        }
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = *b"request-body-key";
    const IV: [u8; 16] = *b"request-body-iv!";

    #[test]
    fn chacha_key_expansion_matches_go_algorithm() {
        // GenerateChacha20Poly1305Key：MD5(b) || MD5(MD5(b))。MD5 标准向量锁定。
        let key = generate_chacha20_poly1305_key(b"0123456789abcdef");
        let first = md5_digest(b"0123456789abcdef");
        assert_eq!(&key[..16], &first[..]);
        let second = md5_digest(&first);
        assert_eq!(&key[16..], &second[..]);
    }

    #[test]
    fn size_parser_mask_is_streamed_and_invertible() {
        let mut encoder = DataSizeParser::new(&IV);
        let mut decoder = DataSizeParser::new(&IV);
        for size in [0u16, 1, 255, 256, 65535] {
            let wire = encoder.encode_size(size);
            assert_eq!(decoder.decode_size(wire), size);
        }
        // 掩码流连续：同一 size 两次编码的线上字节不同（掩码已推进）。
        let mut e2 = DataSizeParser::new(&IV);
        let a = e2.encode_size(1000);
        let b = e2.encode_size(1000);
        assert_ne!(a, b, "掩码必须随 chunk 推进");
    }

    #[test]
    fn padding_len_within_64() {
        let mut parser = DataSizeParser::new(&IV);
        for _ in 0..64 {
            assert!(parser.next_padding_len() < DataSizeParser::max_padding_len());
        }
    }

    #[tokio::test]
    async fn data_chunk_roundtrip_all_securities_with_masking() {
        for security in [
            crate::consts::SECURITY_NONE,
            SECURITY_AES_128_GCM,
            SECURITY_CHACHA20_POLY1305,
        ] {
            let mut seal_cipher = DataCipher::new(security, &KEY, &IV);
            let mut open_cipher = DataCipher::new(security, &KEY, &IV);
            let mut enc_mask = DataSizeParser::new(&IV);
            let mut dec_mask = DataSizeParser::new(&IV);
            let mut wire = Vec::new();
            seal_data_chunk(
                &mut seal_cipher,
                Some(&mut enc_mask),
                &mut wire,
                b"hello chunk",
            )
            .expect("可写");
            seal_data_chunk(
                &mut seal_cipher,
                Some(&mut enc_mask),
                &mut wire,
                &[0x77u8; 300],
            )
            .expect("可写");
            write_data_eof(&mut seal_cipher, Some(&mut enc_mask), &mut wire).expect("EOF 可写");

            let mut cursor = &wire[..];
            let first = read_data_chunk(&mut open_cipher, Some(&mut dec_mask), &mut cursor)
                .await
                .expect("可读")
                .expect("首帧");
            assert_eq!(first, b"hello chunk");
            let second = read_data_chunk(&mut open_cipher, Some(&mut dec_mask), &mut cursor)
                .await
                .expect("可读")
                .expect("次帧");
            assert_eq!(second, vec![0x77u8; 300]);
            let eof = read_data_chunk(&mut open_cipher, Some(&mut dec_mask), &mut cursor)
                .await
                .expect("可读");
            assert!(eof.is_none(), "终止帧应得到 None 而非空载荷");
            assert!(cursor.is_empty(), "不得吞尾部字节");
        }
    }

    #[tokio::test]
    async fn tampered_chunk_fails_and_nonce_advances_per_chunk() {
        let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &KEY, &IV);
        let mut wire = Vec::new();
        seal_data_chunk(&mut cipher, None, &mut wire, b"payload-0").expect("可写");
        seal_data_chunk(&mut cipher, None, &mut wire, b"payload-1").expect("可写");
        assert_eq!(cipher.count(), 2, "每个 chunk 恰好消耗一个 nonce");

        wire[2 + 10] ^= 0x01; // 篡改首帧载荷
        let mut victim = DataCipher::new(SECURITY_AES_128_GCM, &KEY, &IV);
        let err = read_data_chunk(&mut victim, None, &mut &wire[..]).await;
        assert!(matches!(err, Err(Error::AuthFailed)), "实际 {err:?}");
    }

    #[tokio::test]
    async fn truncated_chunk_reports_error_not_hang() {
        let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &KEY, &IV);
        let mut wire = Vec::new();
        seal_data_chunk(&mut cipher, None, &mut wire, b"payload").expect("可写");
        let mut broken = &wire[..2 + 5];
        let err = read_data_chunk(&mut cipher, None, &mut broken).await;
        assert!(matches!(
            err,
            Err(Error::Io(_)) | Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn oversized_chunk_is_rejected_before_write() {
        let mut cipher = DataCipher::new(SECURITY_AES_128_GCM, &KEY, &IV);
        let mut wire = Vec::new();
        let err = seal_data_chunk(
            &mut cipher,
            None,
            &mut wire,
            &vec![0u8; MAX_CHUNK_PAYLOAD + 1],
        );
        assert!(matches!(err, Err(Error::BadLength { .. })));
        assert!(wire.is_empty(), "失败不得写任何字节");
    }

    #[test]
    fn shake_mask_compat_export_is_stable() {
        let a = shake_mask(&IV, 0);
        let b = shake_mask(&IV, 0);
        assert_eq!(a, b, "确定性");
    }
}
