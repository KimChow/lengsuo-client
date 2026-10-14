//! 密钥派生（与 Xray v26.3.27 shadowsocks/config.go 行为逐字节对齐）。
//!
//! - `evp_bytes_to_key`：口令 → 主密钥（OpenSSL EVP_BytesToKey，MD5，无 salt）
//! - `hkdf_sha1_subkey`：主密钥 + 会话 salt → subkey（HKDF-SHA1，info = "ss-subkey"）
//! - `behavior_seed_hmac`：防探测种子输入 = HMAC-SHA256(b"SSBSKDF", master_key)

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

/// EVP_BytesToKey（D_iii = MD5(D_ii + password)，无 salt，输出 key_len 字节）。
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len + 16);
    let mut prev: [u8; 16] = [0u8; 16];
    let mut first = true;
    while out.len() < key_len {
        let mut hasher = Md5::new();
        if !first {
            // Go: 首轮 md5(password)，后续 md5(prev + password)；首轮不掺 prev
            Digest::update(&mut hasher, prev);
        }
        first = false;
        Digest::update(&mut hasher, password);
        prev = hasher.finalize().into();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

/// HKDF-SHA1 派生 subkey（salt = 会话 IV/salt，info = b"ss-subkey"）。
pub fn hkdf_sha1_subkey(master_key: &[u8], salt: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
    let mut okm = vec![0u8; out_len];
    hk.expand(b"ss-subkey", &mut okm)
        .expect("ss-subkey expand cannot fail");
    okm
}

/// 防探测 behavior seed 的输入：HMAC-SHA256(b"SSBSKDF", master_key)。
/// （Xray：服务端再过 crc64-ECMA 累积，客户端过 crc32-IEEE；本函数只给 HMAC 中间值。）
pub fn behavior_seed_hmac(master_key: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(b"SSBSKDF").expect("hmac accepts any key length");
    mac.update(master_key);
    let out = mac.finalize().into_bytes();
    out.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 黄金向量来源：tools/gen_vectors.py（行为按 Xray v26.3.27 复算）。
    #[test]
    fn evp_golden_vectors() {
        let cases = [
            ("test", 16, "098f6bcd4621d373cade4e832627b4f6"),
            (
                "test",
                32,
                "098f6bcd4621d373cade4e832627b4f60a9172716ae6428409885b8b829ccb05",
            ),
            (
                "secret-password-2026",
                16,
                "0bbedf2c25844fbec9f2497b93a6f4d3",
            ),
            (
                "secret-password-2026",
                32,
                "0bbedf2c25844fbec9f2497b93a6f4d3e815b698d2466f8d3094b0374e670406",
            ),
        ];
        for (password, klen, want) in cases {
            assert_eq!(
                hex::encode(evp_bytes_to_key(password.as_bytes(), klen)),
                want
            );
        }
    }

    #[test]
    fn subkey_golden_vector() {
        let master = hex::decode("098f6bcd4621d373cade4e832627b4f6").unwrap();
        let salt = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(
            hex::encode(hkdf_sha1_subkey(&master, &salt, 16)),
            "85ce1bd75b58dc1afca72a5904040f4a"
        );
    }

    #[test]
    fn behavior_hmac_golden_vector() {
        let master = hex::decode("098f6bcd4621d373cade4e832627b4f6").unwrap();
        assert_eq!(
            hex::encode(behavior_seed_hmac(&master)),
            "cd0709d2146c26702e92250aab8f5d5c9b9922ec4fe3a8dfa373c48ace54a99c"
        );
    }
}
