//! TCP AEAD chunk 帧编解码（与 Xray AuthenticationReader/Writer + AEADChunkSizeParser 线格式对齐）。
//!
//! 线格式（每个 chunk）：
//! ```text
//! [AEAD(BE16(payload_plain_len)) 18B] [AEAD(payload) payload+16B]
//! ```
//! - 线上 size 明文 = **载荷明文长度**（Xray：调用方传 encryptedSize，Encode 内部减 Overhead，
//!   净效果 = 存明文长；Decode 时加回 Overhead 得密文总长）
//! - EOF：线上 size 明文 == 0（Xray 读者侧判据：decoded == Overhead(16)）
//! - nonce：size 段与 payload 段共用同一小端递增序列（先 size 后 payload）
//! - nonce 取尽：`write_chunk`/`write_eof`/`read_chunk` 一律透传
//!   `Error::NonceExhausted`（fail-closed，不回绕重用；见 `crate::crypto::NonceCounter`）

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::{SessionAead, TAG_LEN};
use crate::{Error, Result};

/// 单个 chunk 载荷上限（Xray buf.Size = 8192）。
pub const MAX_CHUNK_PAYLOAD: usize = 8192;
const SIZE_PLAIN_LEN: usize = 2;
/// size 段线上长度（2B 密文 + 16B tag）。
pub const SIZE_WIRE_LEN: usize = SIZE_PLAIN_LEN + TAG_LEN;

/// 把一个明文 chunk 编码并写出（写 size 段 + payload 段，消耗 2 个 nonce）。
pub async fn write_chunk<W: AsyncWrite + Unpin>(
    w: &mut W,
    aead: &mut SessionAead,
    payload: &[u8],
) -> Result<()> {
    if payload.len() > MAX_CHUNK_PAYLOAD {
        return Err(Error::InvalidLength(payload.len()));
    }
    let size_ct = aead.seal(&(payload.len() as u16).to_be_bytes())?;
    debug_assert_eq!(size_ct.len(), SIZE_WIRE_LEN);
    let payload_ct = aead.seal(payload)?;
    w.write_all(&size_ct).await?;
    w.write_all(&payload_ct).await?;
    Ok(())
}

/// 写 EOF 终止 chunk（线上 size 明文 = 0，Xray 读者解出 0+16==Overhead 判流结束）。
pub async fn write_eof<W: AsyncWrite + Unpin>(w: &mut W, aead: &mut SessionAead) -> Result<()> {
    let size_ct = aead.seal(&0u16.to_be_bytes())?;
    w.write_all(&size_ct).await?;
    Ok(())
}

/// 从流中读取一个 chunk。返回 `Ok(None)` 表示对端正常收尾（EOF chunk）。
pub async fn read_chunk<R: AsyncRead + Unpin>(
    r: &mut R,
    aead: &mut SessionAead,
) -> Result<Option<Vec<u8>>> {
    let mut size_wire = [0u8; SIZE_WIRE_LEN];
    r.read_exact(&mut size_wire).await?;
    let size_plain = aead.open(&size_wire)?;
    if size_plain.len() != SIZE_PLAIN_LEN {
        return Err(Error::InvalidLength(size_plain.len()));
    }
    // Xray Decode：线上明文 + Overhead = 密文总长（含 tag）
    let stored = u16::from_be_bytes([size_plain[0], size_plain[1]]);
    let payload_ct_len = stored as usize + TAG_LEN;
    if stored == 0 {
        // decoded(16) == Overhead → 正常 EOF
        return Ok(None);
    }
    // 参考 `common/crypto/auth.go:179` 用**含 tag 的 size**（Decode 已加回
    // Overhead）与 `buf.Size = 8192` 比较，因此载荷明文上限是 8192 - 16 = 8176。
    if stored as usize + TAG_LEN > MAX_CHUNK_PAYLOAD {
        return Err(Error::InvalidLength(payload_ct_len));
    }
    let mut payload_wire = vec![0u8; payload_ct_len];
    r.read_exact(&mut payload_wire).await?;
    Ok(Some(aead.open(&payload_wire)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CipherSuite;
    use crate::kdf::hkdf_sha1_subkey;
    use tokio::io::duplex;

    fn test_aead() -> (SessionAead, SessionAead) {
        let subkey = hkdf_sha1_subkey(&[3u8; 16], &[9u8; 16], 16);
        (
            SessionAead::new(CipherSuite::Aes128Gcm, subkey.clone()),
            SessionAead::new(CipherSuite::Aes128Gcm, subkey),
        )
    }

    #[tokio::test]
    async fn chunk_roundtrip_over_stream() {
        let (mut tx, mut rx) = duplex(64 * 1024);
        let (mut enc, mut dec) = test_aead();
        let payload = vec![0xABu8; 1000];
        write_chunk(&mut tx, &mut enc, &payload).await.unwrap();
        let got = read_chunk(&mut rx, &mut dec).await.unwrap();
        assert_eq!(got.unwrap(), payload);
    }

    #[tokio::test]
    async fn eof_chunk_signals_none() {
        let (mut tx, mut rx) = duplex(64 * 1024);
        let (mut enc, mut dec) = test_aead();
        write_chunk(&mut tx, &mut enc, b"data").await.unwrap();
        write_eof(&mut tx, &mut enc).await.unwrap();
        assert_eq!(
            read_chunk(&mut rx, &mut dec).await.unwrap().unwrap(),
            b"data"
        );
        assert!(read_chunk(&mut rx, &mut dec).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn multi_chunk_nonce_alignment() {
        // 多 chunk 连续收发，验证 size/payload 共用 nonce 序列不错位
        let (mut tx, mut rx) = duplex(64 * 1024);
        let (mut enc, mut dec) = test_aead();
        let msgs: Vec<Vec<u8>> = vec![b"first".to_vec(), vec![1u8; 200], vec![2u8; 5000]];
        for m in &msgs {
            write_chunk(&mut tx, &mut enc, m).await.unwrap();
        }
        write_eof(&mut tx, &mut enc).await.unwrap();
        let mut got = Vec::new();
        while let Some(c) = read_chunk(&mut rx, &mut dec).await.unwrap() {
            got.push(c);
        }
        assert_eq!(got, msgs);
    }

    #[tokio::test]
    async fn oversized_chunk_rejected() {
        let subkey = hkdf_sha1_subkey(&[3u8; 16], &[9u8; 16], 16);
        let mut enc = SessionAead::new(CipherSuite::Aes128Gcm, subkey.clone());
        let mut dec = SessionAead::new(CipherSuite::Aes128Gcm, subkey);
        // 合法 AEAD，但声明的载荷明文长越界（> 8192）—— 须 fail-closed
        let size_ct = enc
            .seal(&((MAX_CHUNK_PAYLOAD + 1) as u16).to_be_bytes())
            .unwrap();
        let mut stream = std::io::Cursor::new(size_ct);
        let res = read_chunk(&mut stream, &mut dec).await;
        assert!(matches!(res, Err(Error::InvalidLength(_))));
    }

    #[tokio::test]
    async fn tampered_payload_fails_closed() {
        let (mut tx, mut rx) = duplex(64 * 1024);
        let (mut enc, mut dec) = test_aead();
        write_chunk(&mut tx, &mut enc, b"payload").await.unwrap();
        let mut wire = Vec::new();
        drop(tx); // 写端关闭后 read_to_end 才能收到 EOF，禁止无限等待。
        tokio::time::timeout(std::time::Duration::from_secs(2), rx.read_to_end(&mut wire))
            .await
            .expect("test stream must reach EOF")
            .unwrap();
        wire[SIZE_WIRE_LEN] ^= 0xFF; // 破坏 payload 段首字节
        let mut r = &wire[..];
        let res = read_chunk(&mut r, &mut dec).await;
        assert!(matches!(res, Err(Error::AuthFailed)));
    }
}
