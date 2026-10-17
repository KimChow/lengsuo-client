//! 密钥派生与记录加密封装（v0）。
//!
//! 参数（写入文件头，可读回）：
//! - 派生：HKDF-SHA256，`salt` 16 字节随机，输出 32 字节密钥；`iterations` 字段固定为 1，
//!   为后续替换 memory-hard KDF 预留（见 crate 文档与 `result.md` 遗留项）。
//! - 加密：AES-256-GCM，每条记录独立随机 12 字节 nonce，AAD 绑定文件头，
//!   跨文件搬移记录必然认证失败。
//! - 校验：文件内含 verifier 记录（固定明文的密文），口令错误立即判定，
//!   不与记录篡改混淆。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::StoreError;

/// 容器 magic（8 字节，含格式标记）。
pub(crate) const MAGIC: [u8; 8] = *b"LSCRED01";
/// 本实现唯一支持的 schema 版本。
pub(crate) const SCHEMA_VERSION: u32 = 1;
/// HKDF salt 长度。
pub(crate) const SALT_LEN: usize = 16;
/// AES-GCM nonce 长度。
pub(crate) const NONCE_LEN: usize = 12;
/// 派生密钥长度（AES-256）。
pub(crate) const KEY_LEN: usize = 32;
/// 头部定长前缀长度：magic(8) + schema_version(4) + iterations(4) + key_len(4) + salt(16)。
/// 不含 `verifier_len` 与 verifier 本身（两者长度随参数变化，由编解码侧另计）。
pub(crate) const HEADER_PREFIX_LEN: usize = 8 + std::mem::size_of::<u32>() * 3 + SALT_LEN;
/// verifier 明文（固定值，仅用于口令自检，不含用户数据）。
pub(crate) const VERIFIER_PLAIN: &[u8] = b"lengsuo-cred-store-verifier";

/// KDF 参数：随文件头落盘，读回时用于校验与将来迁移。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// 容器 schema 版本。
    pub schema_version: u32,
    /// HKDF 迭代轮数（v0 固定 1；预留字段）。
    pub iterations: u32,
    /// 派生密钥长度（字节）。
    pub key_len: u32,
}

impl KdfParams {
    /// v0 默认参数。
    pub const V0: Self = Self {
        schema_version: SCHEMA_VERSION,
        iterations: 1,
        key_len: KEY_LEN as u32,
    };

    /// 是否为本实现可服务的参数组合（版本不识别即 fail-closed）。
    pub fn is_supported(&self) -> bool {
        self.schema_version == SCHEMA_VERSION
            && self.iterations >= 1
            && self.key_len == KEY_LEN as u32
    }
}

/// 由口令与 salt 派生密钥；返回受 `Zeroizing` 保护的密钥。
pub(crate) fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    if passphrase.is_empty() {
        return Err(StoreError::WrongPassphrase);
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), passphrase);
    // info 绑定 schema 版本与密钥长度，避免不同版本/用途之间密钥复用。
    let mut info = format!(
        "lengsuo-credential-store-v{}|keylen{}",
        params.schema_version, params.key_len
    )
    .into_bytes();
    let mut okm = Zeroizing::new(vec![0u8; params.key_len as usize]);
    hk.expand(&info, okm.as_mut_slice())
        .map_err(|_| StoreError::MalformedContainer("kdf expand failed"))?;
    // 多轮拉伸：v0 iterations=1；将来调高参数即按轮把上一轮输出并入 info 继续。
    for _ in 1..params.iterations {
        info.extend_from_slice(okm.as_slice());
        hk.expand(&info, okm.as_mut_slice())
            .map_err(|_| StoreError::MalformedContainer("kdf expand failed"))?;
    }
    Ok(okm)
}

/// 加密：随机 nonce + AES-256-GCM，返回 `nonce || ciphertext`。
pub(crate) fn seal(
    key: &[u8],
    aad: &[u8],
    rng: &mut impl RngCore,
    plaintext: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let body = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| StoreError::RecordAuthentication)?;
    let mut out = Vec::with_capacity(NONCE_LEN + body.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// 解密 `nonce || ciphertext`；认证失败返回 [`StoreError::RecordAuthentication`]。
pub(crate) fn open(
    key: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    if sealed.len() < NONCE_LEN {
        return Err(StoreError::MalformedContainer("sealed record too short"));
    }
    let (nonce_bytes, body) = sealed.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), Payload { msg: body, aad })
        .map_err(|_| StoreError::RecordAuthentication)?;
    Ok(Zeroizing::new(plain))
}

pub(crate) fn random_bytes<const N: usize>(rng: &mut impl RngCore) -> [u8; N] {
    let mut buf = [0u8; N];
    rng.fill_bytes(&mut buf);
    buf
}
