//! VMess KDFv1（对应参考 `proxy/vmess/aead/kdf.go` 的 `KDF` / `KDF16`）。
//!
//! 参考用 HMAC-SHA256 的**链式嵌套**构造：根 HMAC 的 key 固定为
//! `KDFSaltConstVMessAEADKDF`，随后每个 path 元素把它再包一层
//! （`hmac.New(func() hash.Hash { 上一层 }, []byte(v))`），最后把 `key`
//! 作为最内层的消息写入。等价展开即：
//!
//! ```text
//! acc = HMAC_SHA256(key = "VMess AEAD KDF", msg = key)
//! for p in paths: acc = HMAC_SHA256(key = p, msg = acc)
//! ```
//!
//! 输出长度参数化：`kdf` 返回完整 32 字节标签，`kdf16` / `kdf_n` 取前缀
//! （参考里就是 `KDF(...)[:16]`、`[:12]` 的切片用法）。

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::consts::KDF_SALT_VMESS_AEAD_KDF;
use crate::{Error, Result};

/// HMAC-SHA256 标签长度（字节）。
pub const KDF_MAX_LEN: usize = 32;

/// 单个 path 元素。参考里 path 是 `string`，Go 的字符串可以带任意字节
/// （authID/nonce 是二进制），因此这里接受 `&[u8]` 而不是 `&str`。
pub type PathElem<'a> = &'a [u8];

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// `KDF(key, path...)`：链式派生，返回 32 字节标签。
pub fn kdf(key: &[u8], paths: &[PathElem<'_>]) -> Vec<u8> {
    let mut acc = hmac_sha256(KDF_SALT_VMESS_AEAD_KDF.as_bytes(), key);
    for p in paths {
        acc = hmac_sha256(p, &acc);
    }
    acc
}

/// 输出长度参数化的 `KDF`：取标签前缀 `out_len` 字节。
///
/// `out_len > 32` 是协议外用法（参考只做切片截断），fail-closed 拒绝。
pub fn kdf_n(key: &[u8], paths: &[PathElem<'_>], out_len: usize) -> Result<Vec<u8>> {
    if out_len > KDF_MAX_LEN {
        return Err(Error::BadLength {
            declared: out_len,
            got: KDF_MAX_LEN,
        });
    }
    let full = kdf(key, paths);
    Ok(full[..out_len].to_vec())
}

/// `KDF16(key, path...)`：16 字节密钥前缀。
/// KDF16 输出长度（= AuthID/密钥长度 16 字节）。
pub const ID_BYTES: usize = 16;

pub fn kdf16(key: &[u8], paths: &[PathElem<'_>]) -> [u8; ID_BYTES] {
    let full = kdf(key, paths);
    let mut out = [0u8; ID_BYTES];
    out.copy_from_slice(&full[..ID_BYTES]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HMAC-SHA256 公共规范向量（RFC 4231 用空 key 的等价校验不可用——这里用
    /// 标准 HMAC-SHA256 测试向量锁定 hmac_sha256 原语；KDF 链结构由其余测试覆盖）。
    #[test]
    fn hmac_sha256_rfc4231_case1() {
        // RFC 4231 Test Case 1：key = 0x0b x20, data = "Hi There"
        let key = [0x0bu8; 20];
        let got = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(got),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "RFC 4231 TC1"
        );
    }

    #[test]
    fn kdf_output_is_deterministic_and_len_parametric() {
        let key = [7u8; 16];
        let a = kdf(&key, &[b"x".as_slice()]);
        let b = kdf(&key, &[b"x".as_slice()]);
        assert_eq!(a, b);
        assert_eq!(a.len(), KDF_MAX_LEN);
        assert_eq!(kdf16(&key, &[b"x".as_slice()])[..], a[..16]);
        assert_eq!(kdf_n(&key, &[b"x".as_slice()], 12).unwrap(), a[..12]);
    }

    #[test]
    fn kdf_path_elements_are_not_commutative() {
        let key = [3u8; 16];
        let ab = kdf(&key, &[b"A".as_slice(), b"B".as_slice()]);
        let ba = kdf(&key, &[b"B".as_slice(), b"A".as_slice()]);
        assert_ne!(ab, ba);
        // 单元素路径也不等于拼接路径（链式嵌套不是简单连接）
        let joined = kdf(&key, &[b"AB".as_slice()]);
        assert_ne!(ab, joined);
    }

    #[test]
    fn kdf_overlong_output_fails_closed() {
        assert!(matches!(
            kdf_n(&[0u8; 16], &[], KDF_MAX_LEN + 1),
            Err(Error::BadLength { .. })
        ));
    }
}
