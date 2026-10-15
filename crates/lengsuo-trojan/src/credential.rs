//! Trojan 凭据：密码的 SHA224 小写十六进制哈希（56 字节 ASCII）。
//!
//! 参考基线：Xray v26.3.27，完整 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，
//! `proxy/trojan/protocol.go` 将 56 字节密码哈希作为请求头部前缀。
//! 原始密码不被持有，密码与哈希都不得进入日志或 Debug 输出。

use sha2::Digest as _;
use subtle::{Choice, ConstantTimeEq};

/// 线上头部中的密码哈希长度：SHA224 摘要 28 字节，十六进制展开为 56 字符。
pub const HASH_LEN: usize = 56;

/// 持有 SHA224 小写十六进制哈希字节；不派生 Debug，避免泄露凭据。
pub struct Credential {
    hash: [u8; HASH_LEN],
}

impl Credential {
    /// 由密码计算哈希；不做大小写或空白归一化，避免与参考实现语义偏差。
    #[must_use]
    pub fn new(password: &str) -> Self {
        let digest = sha2::Sha224::digest(password.as_bytes());
        let hex = hex::encode(digest);
        let mut hash = [0u8; HASH_LEN];
        // hex::encode 对 28 字节摘要必定产出 56 字节，长度不符属于实现错误。
        hash.copy_from_slice(hex.as_bytes());
        Credential { hash }
    }

    /// 哈希字节，即头部的线上格式。
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.hash
    }

    /// 哈希的小写十六进制文本形式，与 `as_bytes` 内容一致。
    #[must_use]
    pub fn as_hex(&self) -> &str {
        // 来源是 hex::encode 的字节，必定为合法 ASCII。
        std::str::from_utf8(&self.hash).expect("十六进制字节必定是合法 ASCII")
    }

    /// 与对端发送的哈希字节做常量时间比较；长度不符直接判为失败。
    #[must_use]
    pub fn verify(&self, candidate: &[u8]) -> bool {
        candidate.len() == HASH_LEN && bool::from(self.hash.as_slice().ct_eq(candidate))
    }
}

impl Clone for Credential {
    fn clone(&self) -> Self {
        Credential { hash: self.hash }
    }
}

impl ConstantTimeEq for Credential {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.hash.ct_eq(&other.hash)
    }
}

impl core::fmt::Debug for Credential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 不输出哈希的任何前缀，密码与哈希都不得进入日志。
        f.write_str("Credential(<redacted>)")
    }
}
