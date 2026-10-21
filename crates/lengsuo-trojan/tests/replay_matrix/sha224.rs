//! 独立的 SHA-224 实现（FIPS 180-4），只用于**交叉校验** trojan 请求头里那
//! 56 字节前缀的来源。
//!
//! 为什么要自己写：仓内 `lengsuo_trojan::credential::Credential::new` 用的就是
//! SHA-224，如果用例直接拿它的输出当判据，就等于「用被测对象证明被测对象」。
//! 这里另写一份与 crate 无关的实现，用它独立算出「密码 → 56 字节小写 hex」，
//! 再与参考客户端实际写出的头部前缀、以及本仓 `Credential` 三方对照：
//!
//! - 参考头部前缀 == 独立实现的 SHA224(密码) ⇒ 前缀是**口令的函数**，
//!   不是会话随机数、不是时间戳；
//! - 两次独立会话的头部逐字节相同 ⇒ 前缀与会话无关。
//!
//! 两者合起来才支撑「请求头里没有任何一次性字段」的结论。
//!
//! 自检向量：`""` → `d14a028c…`、`"abc"` → `23097d22…`（用例内断言）。

#![allow(dead_code)]

/// SHA-224 初始散列值（FIPS 180-4 §5.3.3）。
const H0: [u32; 8] = [
    0xc105_9ed8,
    0x367c_d507,
    0x3070_dd17,
    0xf70e_5939,
    0xffc0_0b31,
    0x6858_1511,
    0x64f9_8fa7,
    0xbefa_4fa4,
];

/// 64 个轮常量。
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

fn rotr(value: u32, bits: u32) -> u32 {
    value.rotate_right(bits)
}

/// SHA-224 摘要（28 字节）。
pub fn sha224(data: &[u8]) -> [u8; 28] {
    let mut h = H0;
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for block in message.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (index, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[index] = u32::from_be_bytes(*word);
        }
        for index in 16..64 {
            let s0 = rotr(w[index - 15], 7) ^ rotr(w[index - 15], 18) ^ (w[index - 15] >> 3);
            let s1 = rotr(w[index - 2], 17) ^ rotr(w[index - 2], 19) ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for index in 0..64 {
            let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(value);
        }
    }

    // SHA-224 = SHA-256 的截断版：只取前 7 个字（28 字节），丢弃第 8 个。
    let mut out = [0u8; 28];
    for (index, word) in h.iter().take(7).enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// 密码 → SHA-224 摘要的**小写十六进制**文本（56 字节 ASCII）。
///
/// 十六进制小写是参考实现 `proxy/trojan/config.go` 的 `hexSha224` 的语义
/// （Go 的 `hex.Encode` 输出小写）。
pub fn hex_sha224(password: &str) -> String {
    let digest = sha224(password.as_bytes());
    let mut out = String::with_capacity(56);
    for byte in digest {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap());
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{hex_sha224, sha224};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn known_vectors() {
        assert_eq!(
            hex(&sha224(b"")),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            hex(&sha224(b"abc")),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
        assert_eq!(
            hex(&sha224(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
        );
        assert_eq!(hex_sha224("").len(), 56);
    }
}
