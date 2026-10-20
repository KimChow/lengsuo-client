//! ChaCha20-Poly1305 安全档：MD5 扩展密钥 + AEAD 封装（IETF 变体）。
//!
//! 对齐参考（固定 commit `d2758a02`，只读参考检出 `~/ref/xray`）：
//! - `proxy/vmess/encoding/auth.go` 的 `GenerateChacha20Poly1305Key`：
//!   `key32 = MD5(b) || MD5(MD5(b))`（先 MD5，再对前 16 字节做一次 MD5）。
//! - `proxy/vmess/encoding/client.go` 的 `SecurityType_CHACHA20_POLY1305` 分支：
//!   body 用扩展后的 32B 密钥 + 12B nonce；认证长度段用
//!   `KDF16(bodyKey, "auth_len")` 再扩展出的 32B 密钥。
//! - `common/protocol/headers.pb.go` 的 `SecurityType_CHACHA20_POLY1305 = 4`。
//!
//! 线格式语义（与 AES 档同构，便于统一分派）：
//! - nonce 12 字节；tag 16 字节；AAD 参与认证（长度段与载荷段各自组装）。
//! - fail-closed：解密失败一律 [`Error::AuthFailed`]，绝不返回明文。

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;

use crate::consts::{CHACHA_KEY_LEN, CHACHA_NONCE_LEN};
use crate::{Error, Result};

/// `GenerateChacha20Poly1305Key`：`MD5(b) || MD5(MD5(b))` 扩展成 32 字节。
///
/// 参考 `proxy/vmess/encoding/auth.go`：
/// ```go
/// func GenerateChacha20Poly1305Key(b []byte) []byte {
///     key := make([]byte, 32)
///     t := md5.Sum(b)
///     copy(key, t[:])
///     t = md5.Sum(key[:16])
///     copy(key[16:], t[:])
///     return key
/// }
/// ```
#[must_use]
pub fn expand_key(base: &[u8]) -> [u8; CHACHA_KEY_LEN] {
    let first = crate::chunkframe::md5_digest(base);
    let second = crate::chunkframe::md5_digest(&first);
    let mut key = [0u8; CHACHA_KEY_LEN];
    key[..16].copy_from_slice(&first);
    key[16..].copy_from_slice(&second);
    key
}

/// 固定 16 字节基础密钥的扩展（请求/响应 body key 的长度）。
#[must_use]
pub fn expand_key16(base: &[u8; 16]) -> [u8; CHACHA_KEY_LEN] {
    expand_key(base)
}

/// ChaCha20-Poly1305 封装（12B nonce / 16B tag / AAD 参与认证）。
#[must_use]
pub fn seal(
    key: &[u8; CHACHA_KEY_LEN],
    nonce: &[u8; CHACHA_NONCE_LEN],
    plain: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(nonce.into(), Payload { msg: plain, aad })
        .expect("ChaCha20-Poly1305 加密只在长度异常时失败，此处输入长度已受控")
}

/// ChaCha20-Poly1305 解封装；tag 校验失败即 [`Error::AuthFailed`]。
pub fn open(
    key: &[u8; CHACHA_KEY_LEN],
    nonce: &[u8; CHACHA_NONCE_LEN],
    ct: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), Payload { msg: ct, aad })
        .map_err(|_| Error::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: [u8; 16] = *b"b831381d-6324-4d";

    #[test]
    fn expand_key_is_md5_chain() {
        let key = expand_key(&BASE);
        let first = crate::chunkframe::md5_digest(&BASE);
        let second = crate::chunkframe::md5_digest(&first);
        assert_eq!(&key[..16], &first[..]);
        assert_eq!(&key[16..], &second[..]);
        // 扩展结果必须与 16B 基础密钥不同（不能直接当 AES 密钥用）。
        assert_ne!(&key[..16], &BASE[..]);
    }

    #[test]
    fn seal_open_roundtrip_with_aad() {
        let key = expand_key(&BASE);
        let nonce = [0x11u8; 12];
        let aad = [0x5Au8; 16];
        let ct = seal(&key, &nonce, b"vmess chacha payload", &aad);
        assert_eq!(ct.len(), b"vmess chacha payload".len() + 16);
        let pt = open(&key, &nonce, &ct, &aad).expect("可解");
        assert_eq!(pt, b"vmess chacha payload");
    }

    #[test]
    fn wrong_aad_or_flipped_bit_fails_closed() {
        let key = expand_key(&BASE);
        let nonce = [0x11u8; 12];
        let aad = [0x5Au8; 16];
        let mut ct = seal(&key, &nonce, b"payload", &aad);
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(matches!(
            open(&key, &nonce, &ct, &aad),
            Err(Error::AuthFailed)
        ));
        let clean = seal(&key, &nonce, b"payload", &aad);
        let mut other_aad = aad;
        other_aad[0] ^= 0x01;
        assert!(matches!(
            open(&key, &nonce, &clean, &other_aad),
            Err(Error::AuthFailed)
        ));
    }
}
