//! 恢复码 KDF（Argon2id）与恢复码编码。
//!
//! 契约 §4：
//!
//! | 项 | 值 |
//! |---|---|
//! | 熵 | **≥ 128 bit**（16 字节随机） |
//! | 编码 | **base32**（无 padding，Crockford 或 RFC 4648 择一，**两端必须一致**） |
//! | 分组显示 | 4 组 × 8 字符（`-` 分隔），**仅显示一次** |
//! | KDF | **Argon2id**（参数见 §4.1）；⛔ 不用 `pbkdf2` 默认轮数 |
//! | 输出 | 32 字节 DEK |
//!
//! ### 本卡的两处拍板
//!
//! 1. **base32 变体 = RFC 4648**（标准字母表 `A-Z` + `2-7`），非 Crockford。
//! 2. **熵取 160 bit（20 字节）**：4 组 × 8 字符 = 32 个 base32 字符
//!    ⇔ 32 × 5 = 160 bit ⇒ 正好 20 字节。
//!    ⛔ **不得用 16 字节再补零凑 32 字符**（那会把 128 bit 熵降成 32 字符的假象）。
//!    这与契约 §4「熵 ≥ 128 bit」不冲突 —— 160 bit 满足该下界。
//!
//! ### KDF 参数（v1 冻结，契约 §4.1）
//!
//! ```text
//! memoryCost = 64 MiB (65536 KiB)
//! timeCost   = 3
//! parallelism = 1
//! salt       = 16 字节随机（存服务端）
//! outputLen  = 32
//! ```
//!
//! ⚠️ 参数变更 = 已发的恢复码全部失效 ⇒ 参数**版本化**（存 `kdf_params` 字段），
//! 恢复时按存的值算。

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::entropy::Entropy;
use crate::error::Error;

/// KDF 参数版本（v1）。
pub const KDF_PARAMS_VERSION: u32 = 1;

/// 恢复码 KDF 参数（v1 冻结）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// 内存代价（KiB）。
    pub memory_cost: u32,
    /// 时间代价（迭代轮数）。
    pub time_cost: u32,
    /// 并行度。
    pub parallelism: u32,
    /// 输出长度（字节）。
    pub output_len: usize,
    /// salt 长度（字节）。
    pub salt_len: usize,
    /// 参数版本号（变更 ⇒ 已发恢复码全部失效）。
    pub version: u32,
}

/// v1 冻结参数：64 MiB / t=3 / p=1 / 输出 32 字节 / salt 16 字节。
pub const KDF_PARAMS_V1: KdfParams = KdfParams {
    memory_cost: 65536,
    time_cost: 3,
    parallelism: 1,
    output_len: 32,
    salt_len: 16,
    version: KDF_PARAMS_VERSION,
};

/// 恢复码的分组数。
pub const RECOVERY_GROUPS: usize = 4;

/// 每组字符数。
pub const RECOVERY_GROUP_LEN: usize = 8;

/// 恢复码总字符数（不含分隔符）：4 × 8 = 32。
pub const RECOVERY_CODE_LEN: usize = RECOVERY_GROUPS * RECOVERY_GROUP_LEN;

/// 恢复码熵的字节数：32 字符 × 5 bit / 8 = **20 字节（160 bit）**。
pub const RECOVERY_ENTROPY_LEN: usize = 20;

/// base32 字母表：**RFC 4648**（`A-Z` + `2-7`）。
///
/// ⚠️ 本卡选定 RFC 4648 ⇒ 服务端解码必须用同一张表。
pub const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 恢复码：32 个 base32 字符，按 4 组 × 8 字符用 `-` 分隔。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCode {
    /// 32 个 base32 字符（无 padding、无分隔符）。
    pub chars: String,
    /// 熵字节（20 字节）。
    pub entropy: [u8; RECOVERY_ENTROPY_LEN],
}

/// 恢复码派生结果：`(恢复码, salt, 派生出的 DEK)`。
///
/// salt 是 16 字节随机（**存服务端**）；DEK 是 Argon2id 派生的 32 字节。
pub type DerivedDek = (RecoveryCode, [u8; 16], Zeroizing<Vec<u8>>);

impl RecoveryCode {
    /// 显示形态：`AAAA-BBBB-CCCC-DDDD`。
    pub fn display(&self) -> String {
        group(&self.chars)
    }
}

/// 把 32 个字符按 4 组 × 8 字符分组，用 `-` 连接。
fn group(chars: &str) -> String {
    let mut out = String::with_capacity(RECOVERY_CODE_LEN + RECOVERY_GROUPS - 1);
    for (i, chunk) in chars.as_bytes().chunks(RECOVERY_GROUP_LEN).enumerate() {
        if i > 0 {
            out.push('-');
        }
        out.push_str(std::str::from_utf8(chunk).expect("base32 字符均为 ASCII"));
    }
    out
}

/// 生成恢复码。
///
/// 熵取 **20 字节（160 bit）** ⇒ base32 后恰好 32 个字符 ⇒ 4 组 × 8。
pub fn generate_recovery_code(entropy: &mut impl Entropy) -> Result<RecoveryCode, Error> {
    let mut bytes = [0u8; RECOVERY_ENTROPY_LEN];
    entropy.fill(&mut bytes)?;
    Ok(RecoveryCode {
        chars: base32_encode(&bytes),
        entropy: bytes,
    })
}

/// base32 编码（RFC 4648，无 padding）。
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let bits = u64::from(buf[0]) << 32
            | u64::from(buf[1]) << 24
            | u64::from(buf[2]) << 16
            | u64::from(buf[3]) << 8
            | u64::from(buf[4]);
        // 每 5 bit 一个字符；不足处补 0（padding 位不输出）。
        // 输出字符数 = ceil(chunk_len * 8 / 5)。
        let chars = (chunk.len() * 8).div_ceil(5);
        for i in 0..8 {
            if i < chars {
                let idx = ((bits >> (35 - 5 * i)) & 0x1f) as usize;
                out.push(BASE32_ALPHABET[idx] as char);
            }
        }
    }
    out
}

/// 从 20 字节熵恢复 base32 字符（不校验字符集 —— 解码在服务端做）。
pub fn recovery_chars_from_entropy(entropy: &[u8; RECOVERY_ENTROPY_LEN]) -> String {
    base32_encode(entropy)
}

/// 用指定参数派生 DEK。
///
/// ⛔ **必须 Argon2id**（不是 Argon2i/Argon2d）。
pub fn derive_dek(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if salt.len() != params.salt_len {
        return Err(Error::KdfParams);
    }
    let p = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(params.output_len),
    )
    .map_err(|_| Error::KdfParams)?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new(vec![0u8; params.output_len]);
    a2.hash_password_into(password, salt, out.as_mut())
        .map_err(|_| Error::KdfFailed)?;
    Ok(out)
}

/// 生成恢复码并派生 DEK 的完整流程。
///
/// 返回 [`DerivedDek`]：`(恢复码, salt, 派生出的 DEK)`。
pub fn derive_from_recovery_code(
    params: &KdfParams,
    entropy: &mut impl Entropy,
) -> Result<DerivedDek, Error> {
    let code = generate_recovery_code(entropy)?;
    let mut salt = [0u8; 16];
    entropy.fill(&mut salt)?;
    let dek = derive_dek(code.chars.as_bytes(), &salt, params)?;
    Ok((code, salt, dek))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_v1_match_the_contract() {
        assert_eq!(KDF_PARAMS_V1.memory_cost, 65536);
        assert_eq!(KDF_PARAMS_V1.time_cost, 3);
        assert_eq!(KDF_PARAMS_V1.parallelism, 1);
        assert_eq!(KDF_PARAMS_V1.output_len, 32);
        assert_eq!(KDF_PARAMS_V1.salt_len, 16);
        assert_eq!(KDF_PARAMS_V1.version, 1);
    }

    #[test]
    fn base32_of_20_bytes_is_32_chars() {
        let data = [0u8; 20];
        let encoded = base32_encode(&data);
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }

    #[test]
    fn base32_known_vector() {
        // RFC 4648 测试向量："" / "f" / "fo" / "foo" / "foob" / "fooba" / "foobar"
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn base32_alphabet_is_rfc4648() {
        assert_eq!(BASE32_ALPHABET, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
        // Crockford 会用 0/1 排除在这里 —— 本卡明确**不**选 Crockford。
        assert!(!BASE32_ALPHABET.contains(&b'0'));
        assert!(!BASE32_ALPHABET.contains(&b'1'));
    }

    #[test]
    fn display_is_four_groups_of_eight() {
        let code = RecoveryCode {
            chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".to_owned(),
            entropy: [0u8; 20],
        };
        assert_eq!(code.display(), "ABCDEFGH-IJKLMNOP-QRSTUVWX-YZ234567");
        assert_eq!(code.display().len(), 35);
        assert_eq!(code.display().matches('-').count(), 3);
    }
}
