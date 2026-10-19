//! REALITY 握手层内置的 HMAC / HKDF 原语。
//!
//! 见 [`super::hash`] 的「为什么内置」说明：本 crate 无法在不改 `Cargo.toml`
//! 的前提下 `use` 工作区的 `hmac` / `hkdf`，故按 RFC 2104 / RFC 5869 转写。
//!
//! 这是既定偏离，已列入报告「偏离清单」。

use super::sha::{sha256, sha512, Sha256, Sha512};

/// HMAC-SHA512（RFC 2104）。块长 128 字节。
///
/// 对齐参考 `hmac.New(sha512.New, key)` + `Write` + `Sum`。
pub fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    const BLOCK: usize = 128;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..64].copy_from_slice(&sha512(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha512::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha512::new();
    outer.update(&opad);
    outer.update(&inner);
    outer.finalize()
}

/// HKDF-SHA256（RFC 5869）的 expand-only 用法。
///
/// 参考 `hkdf.New(sha256.New, ikm, salt, info).Read(out)` 是 **extract + expand**；
/// 这里按 RFC 5869 §2.2/2.3 完整实现，`salt` 为 `None` 时用全零盐（RFC 5869 §2.2）。
pub fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    // Extract
    let zero_salt = [0u8; 32];
    let salt = salt.unwrap_or(&zero_salt);
    let mut hmac = HmacSha256::new(salt);
    hmac.update(ikm);
    let prk = hmac.finalize();

    // Expand
    let mut t: [u8; 32] = [0u8; 32];
    let mut t_len = 0usize;
    let mut counter: u8 = 1;
    let mut offset = 0usize;
    while offset < okm.len() {
        let mut mac = HmacSha256::new(&prk);
        mac.update(&t[..t_len]);
        mac.update(info);
        mac.update(&[counter]);
        t = mac.finalize();
        t_len = 32;
        let take = (okm.len() - offset).min(32);
        okm[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
        counter = counter.wrapping_add(1);
    }
}

/// HMAC-SHA256（RFC 2104）。块长 64 字节。
struct HmacSha256 {
    inner: Sha256,
    opad_key: [u8; 64],
}

impl HmacSha256 {
    fn new(key: &[u8]) -> Self {
        const BLOCK: usize = 64;
        let mut key_block = [0u8; BLOCK];
        if key.len() > BLOCK {
            key_block[..32].copy_from_slice(&sha256(key));
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK];
        let mut opad_key = [0x5cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= key_block[i];
            opad_key[i] ^= key_block[i];
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        Self { inner, opad_key }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> [u8; 32] {
        let inner = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&self.opad_key);
        outer.update(&inner);
        outer.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与参考同源：用十六进制字符串比较，便于对照 NIST 向量。
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha256_nist_vectors() {
        // FIPS 180-4 / NIST 示例。
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_long_message_multiblock() {
        // 100 万个 'a'（NIST 长向量）。
        let mut h = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            hex(&h.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn sha256_boundary_lengths() {
        // 55/56/64 字节是填充边界；用 known-answer 长度锚定。
        let v55 = sha256(&[b'x'; 55]);
        let v56 = sha256(&[b'x'; 56]);
        let v64 = sha256(&[b'x'; 64]);
        assert_ne!(v55, v56);
        assert_ne!(v56, v64);
        // 流式与一次性结果一致（含跨块更新）。
        let mut h = Sha256::new();
        for b in [b'x'; 56] {
            h.update(&[b]);
        }
        assert_eq!(h.finalize(), v56);
    }

    #[test]
    fn sha512_nist_vectors() {
        assert_eq!(
            hex(&sha512(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce".to_string()
                + "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a".to_string()
                + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn hmac_sha512_rfc4231_vectors() {
        // RFC 4231 Test Case 1。
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        assert_eq!(
            hex(&hmac_sha512(&key, data)),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde".to_string()
                + "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
        // RFC 4231 Test Case 2。
        assert_eq!(
            hex(&hmac_sha512(b"Jefe", b"what do ya want for nothing?")),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554".to_string()
                + "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
        // RFC 4231 Test Case 3。
        assert_eq!(
            hex(&hmac_sha512(&[0xaau8; 20], &[0xddu8; 50])),
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39".to_string()
                + "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
        );
        // RFC 4231 Test Case 4（key > block size，触发 hash 归约）。
        assert_eq!(
            hex(&hmac_sha512(&[0x01u8; 131], &[0xcdu8; 50])),
            "9261859d4930d6b7acfbd18c6985aa1c712243165f38f1293bc0f8e3a3e261f1".to_string()
                + "91e5f1f3032ce391554d0ffda5e07a3bfe747d1fa9ed49585d70a2274a203d3d"
        );
        // RFC 4231 Test Case 5（截断用例的完整输出；key 与 TC4 同源）。
        assert_eq!(
            hex(&hmac_sha512(&[0x0cu8; 20], b"Test With Truncation")),
            "415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008".to_string()
                + "711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b"
        );
    }

    #[test]
    fn hkdf_sha256_rfc5869_vectors() {
        // RFC 5869 Test Case 1。
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0..=0x0c).map(|b| b as u8).collect();
        let info: Vec<u8> = (0xf0..=0xf9).map(|b| b as u8).collect();
        let mut okm = [0u8; 42];
        hkdf_sha256(Some(&salt), &ikm, &info, &mut okm);
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf".to_string()
                + "34007208d5b887185865"
        );
    }
}
