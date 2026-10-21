//! 头部 AEAD 的内部基元：KDF 路径拼接 + AES-128-GCM 封/解。
//!
//! 这里的 KDF 路径语义是参考的「路径元素拼接」：`kdf16_paths` / `kdf12` 把
//! 盐与调用方给的路径元素依次拼进一条数组，交给 [`crate::kdf`] 的链式派生。
//! 非公开 API——只在本模块的兄弟子模块里用（`pub(super)`）。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm;

use crate::kdf::kdf_n;
use crate::Result;

/// KDF16：盐 + 路径元素拼接后链式派生 16 字节。
pub(super) fn kdf16_paths(key: &[u8], salt: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    let mut all = Vec::with_capacity(paths.len() + 1);
    all.push(salt);
    all.extend_from_slice(paths);
    crate::kdf::kdf16(key, &all)
}

/// KDF 截 12 字节：作 AEAD nonce 用。
pub(super) fn kdf12(key: &[u8], salt: &[u8], paths: &[&[u8]]) -> [u8; 12] {
    let mut all = Vec::with_capacity(paths.len() + 1);
    all.push(salt);
    all.extend_from_slice(paths);
    let out = kdf_n(key, &all, 12).expect("12 <= 32");
    out.try_into().expect("12 字节")
}

/// AES-128-GCM 封装（固定 16B 密钥 / 12B nonce）。
pub(super) fn aes128gcm_seal(
    key: &[u8; 16],
    nonce: &[u8; 12],
    plain: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("AES-128-GCM 固定 16 字节密钥");
    cipher
        .encrypt(nonce.into(), Payload { msg: plain, aad })
        .expect("AES-GCM 加密只在长度异常时失败，此处输入长度已受控")
}

/// AES-128-GCM 解封；认证失败一律 [`crate::Error::AuthFailed`]。
pub(super) fn aes128gcm_open(
    key: &[u8; 16],
    nonce: &[u8; 12],
    ct: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("AES-128-GCM 固定 16 字节密钥");
    cipher
        .decrypt(nonce.into(), Payload { msg: ct, aad })
        .map_err(|_| crate::Error::AuthFailed)
}
