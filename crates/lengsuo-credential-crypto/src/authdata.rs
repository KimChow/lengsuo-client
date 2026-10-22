//! authData（attested credential data）的逐字节构造。
//!
//! 契约 §2：
//!
//! ```text
//! authData = rpIdHash(32) || flags(1) || signCount(4, 大端) || aaguid(16)
//!          || credIdLen(2, 大端) || credId(n) || COSE_Key(77)
//! ```
//!
//! | 段 | 偏移 | 长度 | 说明 |
//! |---|---|---|---|
//! | rpIdHash | 0 | 32 | `SHA-256(rp_id)` |
//! | flags | 32 | 1 | 见 [`crate::flags`] |
//! | signCount | 33 | 4 | **大端**；托管模式每次签名递增 |
//! | aaguid | 37 | 16 | ⭐ **必须全零** |
//! | credIdLen | 53 | 2 | 大端 |
//! | credId | 55 | n | 16 字节（契约 §1.3） |
//! | COSE_Key | 55+n | 77 | 见 [`crate::cose`] |
//!
//! ⚠️ `signCount` 是**大端** 4 字节（跨仓最容易写反的地方）。
//! ⚠️ `credIdLen` 是**大端** 2 字节。

use crate::cose::COSE_KEY_LEN;
use crate::error::Error;
use crate::flags;

/// AAGUID 长度。
pub const AAGUID_LEN: usize = 16;

/// ⭐ **AAGUID 必须 16 字节全零**（托管模式不做真实证明）。
///
/// 依据：浏览器内核在 `fmt = "none"` 下强制要求 aaguid 为全零。
pub const AAGUID: [u8; AAGUID_LEN] = [0u8; AAGUID_LEN];

/// `credential_id` 长度（契约 §1.3：16 字节原始字节，不是 base64 变体）。
pub const CREDENTIAL_ID_LEN: usize = 16;

/// authData 里 credId 段的长度前缀宽度。
const CRED_ID_LEN_WIDTH: usize = 2;

/// authData 中除 credId 外的固定部分长度：
/// 32 (rpIdHash) + 1 (flags) + 4 (signCount) + 16 (aaguid) + 2 (credIdLen) + 77 (COSE_Key)。
pub const FIXED_LEN: usize = 32 + 1 + 4 + AAGUID_LEN + CRED_ID_LEN_WIDTH + COSE_KEY_LEN;

/// authData 里 credId 段的起始偏移。
pub const CRED_ID_OFFSET: usize = 32 + 1 + 4 + AAGUID_LEN;

/// authData 里 COSE_Key 段的起始偏移（相对整段）。
pub fn cose_offset(cred_id_len: usize) -> usize {
    CRED_ID_OFFSET + CRED_ID_LEN_WIDTH + cred_id_len
}

/// authData 的分段偏移与长度（供测试逐段断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthDataLayout {
    /// rpIdHash 长度。
    pub rp_id_hash_len: usize,
    /// flags 长度。
    pub flags_len: usize,
    /// signCount 长度。
    pub sign_count_len: usize,
    /// aaguid 长度。
    pub aaguid_len: usize,
    /// credIdLen 前缀长度。
    pub cred_id_len_len: usize,
    /// credId 长度。
    pub cred_id_len: usize,
    /// COSE_Key 长度。
    pub cose_key_len: usize,
    /// 整段总长。
    pub total_len: usize,
}

/// 构造 authData。
///
/// 参数：
/// - `rp_id_hash`：`SHA-256(rp_id)`，32 字节
/// - `flags`：标志位，见 [`crate::flags`]
/// - `sign_count`：签名计数器，**大端**写入
/// - `credential_id`：凭据 ID（16 字节原始字节）
/// - `cose_key`：COSE_Key 字节（77 字节）
///
/// ⛔ `aaguid` **不由调用方提供**（硬约束：本层自己生成，且必须全零）。
pub fn build(
    rp_id_hash: &[u8; 32],
    flags: u8,
    sign_count: u32,
    credential_id: &[u8],
    cose_key: &[u8],
) -> Result<Vec<u8>, Error> {
    flags::validate(flags)?;
    if cose_key.len() != COSE_KEY_LEN {
        return Err(Error::InvalidLength {
            expected: COSE_KEY_LEN,
            actual: cose_key.len(),
        });
    }
    let cred_id_len = u16::try_from(credential_id.len()).map_err(|_| Error::InvalidLength {
        expected: usize::from(u16::MAX),
        actual: credential_id.len(),
    })?;

    let mut out = Vec::with_capacity(FIXED_LEN + credential_id.len());
    out.extend_from_slice(rp_id_hash);
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    out.extend_from_slice(&AAGUID);
    out.extend_from_slice(&cred_id_len.to_be_bytes());
    out.extend_from_slice(credential_id);
    out.extend_from_slice(cose_key);
    Ok(out)
}

/// 描述一段 authData 的分段布局。
pub fn layout(credential_id_len: usize) -> AuthDataLayout {
    AuthDataLayout {
        rp_id_hash_len: 32,
        flags_len: 1,
        sign_count_len: 4,
        aaguid_len: AAGUID_LEN,
        cred_id_len_len: CRED_ID_LEN_WIDTH,
        cred_id_len: credential_id_len,
        cose_key_len: COSE_KEY_LEN,
        total_len: FIXED_LEN + credential_id_len,
    }
}

/// 取出 authData 里的 flags 字节。
pub fn flags_of(auth_data: &[u8]) -> Result<u8, Error> {
    if auth_data.len() < 33 {
        return Err(Error::InvalidLength {
            expected: 33,
            actual: auth_data.len(),
        });
    }
    Ok(auth_data[32])
}

/// 取出 authData 里的 signCount（大端 4 字节）。
pub fn sign_count_of(auth_data: &[u8]) -> Result<u32, Error> {
    if auth_data.len() < 37 {
        return Err(Error::InvalidLength {
            expected: 37,
            actual: auth_data.len(),
        });
    }
    Ok(u32::from_be_bytes([
        auth_data[33],
        auth_data[34],
        auth_data[35],
        auth_data[36],
    ]))
}

/// 取出 authData 里的 aaguid。
pub fn aaguid_of(auth_data: &[u8]) -> Result<[u8; AAGUID_LEN], Error> {
    if auth_data.len() < 53 {
        return Err(Error::InvalidLength {
            expected: 53,
            actual: auth_data.len(),
        });
    }
    let mut out = [0u8; AAGUID_LEN];
    out.copy_from_slice(&auth_data[37..53]);
    Ok(out)
}

/// 取出 authData 里的 credential_id。
pub fn credential_id_of(auth_data: &[u8]) -> Result<&[u8], Error> {
    if auth_data.len() < 55 {
        return Err(Error::InvalidLength {
            expected: 55,
            actual: auth_data.len(),
        });
    }
    let len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let end = 55 + len;
    if auth_data.len() < end {
        return Err(Error::InvalidLength {
            expected: end,
            actual: auth_data.len(),
        });
    }
    Ok(&auth_data[55..end])
}

/// 取出 authData 里的 COSE_Key。
pub fn cose_key_of(auth_data: &[u8]) -> Result<&[u8], Error> {
    if auth_data.len() < 55 {
        return Err(Error::InvalidLength {
            expected: 55,
            actual: auth_data.len(),
        });
    }
    let len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let start = cose_offset(len);
    let end = start + COSE_KEY_LEN;
    if auth_data.len() < end {
        return Err(Error::InvalidLength {
            expected: end,
            actual: auth_data.len(),
        });
    }
    Ok(&auth_data[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::cose_key;

    fn sample() -> Vec<u8> {
        build(
            &[0x11; 32],
            flags::MANAGED_DEFAULT,
            0x0102_0304,
            &[0x22; CREDENTIAL_ID_LEN],
            &cose_key(&[0x33; 32], &[0x44; 32]),
        )
        .unwrap()
    }

    #[test]
    fn total_length_is_148_for_16_byte_credential_id() {
        assert_eq!(sample().len(), 148);
        assert_eq!(FIXED_LEN, 132);
        assert_eq!(layout(16).total_len, 148);
    }

    #[test]
    fn segment_offsets_and_lengths_are_exact() {
        let data = sample();
        let lay = layout(16);
        assert_eq!(lay.rp_id_hash_len, 32);
        assert_eq!(lay.flags_len, 1);
        assert_eq!(lay.sign_count_len, 4);
        assert_eq!(lay.aaguid_len, 16);
        assert_eq!(lay.cred_id_len_len, 2);
        assert_eq!(lay.cred_id_len, 16);
        assert_eq!(lay.cose_key_len, 77);

        assert_eq!(&data[0..32], &[0x11u8; 32]);
        assert_eq!(data[32], 0x45);
        assert_eq!(&data[33..37], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&data[37..53], &[0u8; 16]);
        assert_eq!(&data[53..55], &[0x00, 0x10]);
        assert_eq!(&data[55..71], &[0x22u8; 16]);
        // COSE_Key 段：头 10 字节 + x(32) + y 头 3 字节 + y(32)
        assert_eq!(&data[71..81], &[165, 1, 2, 3, 38, 32, 1, 33, 88, 32]);
        assert_eq!(&data[113..116], &[34, 88, 32]);
        assert_eq!(&data[116..148], &[0x44u8; 32]);
    }

    #[test]
    fn aaguid_is_all_zero() {
        let data = sample();
        assert_eq!(&data[37..53], &[0u8; 16]);
        assert_eq!(aaguid_of(&data).unwrap(), [0u8; 16]);
    }

    #[test]
    fn sign_count_is_big_endian() {
        let data = sample();
        assert_eq!(&data[33..37], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(sign_count_of(&data).unwrap(), 0x0102_0304);
    }

    #[test]
    fn accessors_round_trip() {
        let data = sample();
        assert_eq!(flags_of(&data).unwrap(), 0x45);
        assert_eq!(credential_id_of(&data).unwrap(), &[0x22u8; 16]);
        assert_eq!(cose_key_of(&data).unwrap().len(), 77);
    }

    #[test]
    fn unknown_flag_bits_are_rejected() {
        let err = build(
            &[0u8; 32],
            0x02,
            0,
            &[0u8; CREDENTIAL_ID_LEN],
            &cose_key(&[0u8; 32], &[0u8; 32]),
        );
        assert_eq!(err, Err(Error::UnknownFlagBits { bits: 0x02 }));
    }

    #[test]
    fn wrong_cose_key_length_is_rejected() {
        let err = build(
            &[0u8; 32],
            flags::MANAGED_DEFAULT,
            0,
            &[0u8; CREDENTIAL_ID_LEN],
            &[0u8; 76],
        );
        assert_eq!(
            err,
            Err(Error::InvalidLength {
                expected: 77,
                actual: 76
            })
        );
    }
}
