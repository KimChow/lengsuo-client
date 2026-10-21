//! 主线响应头的两段封/解（服务端 `EncodeResponseHeader` ↔ 客户端
//! `DecodeResponseHeader`）。
//!
//! 语义来源：参考 `proxy/vmess/encoding/server.go` 的 `EncodeResponseHeader`
//! 与 `proxy/vmess/encoding/client.go` 的 `DecodeResponseHeader`，固定 commit
//! `d2758a02`。两段都是 AES-128-GCM，**无 AAD**，nonce = KDF 截 12 字节，
//! 密钥/IV 各用独立的 KDF 盐。

use crate::consts::{
    KDF_SALT_AEAD_RESP_HEADER_LEN_IV, KDF_SALT_AEAD_RESP_HEADER_LEN_KEY,
    KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV, KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY,
};
use crate::{Error, Result};

use super::internal::{aes128gcm_open, aes128gcm_seal, kdf12, kdf16_paths};

/// 封主线响应头长度段：`BE16(明文长度)` + tag 共 18 字节，无 AAD
/// （服务端 `EncodeResponseHeader` 的长度段路径）。
pub fn seal_response_header_length(key: &[u8; 16], nonce: &[u8; 12], plain_len: u16) -> Vec<u8> {
    aes128gcm_seal(key, nonce, &plain_len.to_be_bytes(), &[])
}

/// 封主线响应头载荷段：明文 + tag，无 AAD。
pub fn seal_response_header_payload(key: &[u8; 16], nonce: &[u8; 12], plain: &[u8]) -> Vec<u8> {
    aes128gcm_seal(key, nonce, plain, &[])
}

/// 主线响应头长度段派生：`KDF16(respKey, "AEAD Resp Header Len Key")` 与
/// `KDF(respIV, "AEAD Resp Header Len IV")[:12]`。
#[must_use]
pub fn response_header_length_key_iv(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
) -> ([u8; 16], [u8; 12]) {
    let key = kdf16_paths(
        response_key,
        KDF_SALT_AEAD_RESP_HEADER_LEN_KEY.as_bytes(),
        &[],
    );
    let iv = kdf12(
        response_iv,
        KDF_SALT_AEAD_RESP_HEADER_LEN_IV.as_bytes(),
        &[],
    );
    (key, iv)
}

/// 主线响应头载荷段派生：`KDF16(respKey, "AEAD Resp Header Key")` 与
/// `KDF(respIV, "AEAD Resp Header Payload IV")[:12]`。
#[must_use]
pub fn response_header_payload_key_iv(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
) -> ([u8; 16], [u8; 12]) {
    let key = kdf16_paths(
        response_key,
        KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY.as_bytes(),
        &[],
    );
    let iv = kdf12(
        response_iv,
        KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV.as_bytes(),
        &[],
    );
    (key, iv)
}

/// 解密主线响应头长度段（18 字节密文 → 2 字节 BE16 明文；无 AAD）。
pub fn open_response_header_length(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    wire: &[u8; 18],
) -> Result<u16> {
    let (key, iv) = response_header_length_key_iv(response_key, response_iv);
    let plain = aes128gcm_open(&key, &iv, wire, &[]);
    let plain = plain?;
    if plain.len() != 2 {
        return Err(Error::BadLength {
            declared: plain.len(),
            got: 2,
        });
    }
    Ok(u16::from_be_bytes([plain[0], plain[1]]))
}

/// 解密主线响应头载荷段（`len+16` 字节密文 → 明文；无 AAD）。
pub fn open_response_header_payload(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    wire: &[u8],
) -> Result<Vec<u8>> {
    let (key, iv) = response_header_payload_key_iv(response_key, response_iv);
    aes128gcm_open(&key, &iv, wire, &[])
}
