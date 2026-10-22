//! COSE_Key（77 字节固定模板）。
//!
//! 契约 §2.2：
//!
//! ```text
//! [165, 1, 2, 3, 38, 32, 1, 33, 88, 32]   (10B)  CBOR: map(1) -> map(2) -> map(3) -> [1:2]
//! x: 32 字节                                     EC2 x 坐标
//! [34, 88, 32]                          (3B)   CBOR: bytes(32)
//! y: 32 字节                                     EC2 y 坐标
//!                                         ────
//!                                         77 字节
//! ```
//!
//! 逐段拆解（CBOR 头）：
//! - `165` = `0xa5` = map(5)
//! - `1` = key 1（kty）→ `2` = 2（EC2）
//! - `3` = key 3（alg）→ `38 32` = negative int −7 ⇒ **ES256**
//! - `1` = key 1（crv）→ `33` = negative int −3 ⇒ **P-256**
//! - `88 32` = bytes(32) = x 坐标
//! - `34` = key −4（y 坐标）→ `88 32` = bytes(32) = y 坐标
//!
//! ⚠️ **必须恰好 77 字节** ⇒ 测试逐字节断言。

/// COSE_Key 固定长度（契约 §2.2）。
pub const COSE_KEY_LEN: usize = 77;

/// COSE_Key 的固定 10 字节头。
pub const COSE_KEY_PREFIX: [u8; 10] = [165, 1, 2, 3, 38, 32, 1, 33, 88, 32];

/// COSE_Key 里 y 坐标前的 3 字节头（CBOR: 负 key −4 + bytes(32)）。
pub const COSE_KEY_Y_PREFIX: [u8; 3] = [34, 88, 32];

/// 由公钥坐标构造 COSE_Key 字节。
pub fn cose_key(x: &[u8; 32], y: &[u8; 32]) -> [u8; COSE_KEY_LEN] {
    let mut out = [0u8; COSE_KEY_LEN];
    out[0..10].copy_from_slice(&COSE_KEY_PREFIX);
    out[10..42].copy_from_slice(x);
    out[42..45].copy_from_slice(&COSE_KEY_Y_PREFIX);
    out[45..77].copy_from_slice(y);
    out
}

/// 从 COSE_Key 字节里取回 X 坐标。
pub fn x_from_cose(bytes: &[u8]) -> Result<[u8; 32], crate::error::Error> {
    if bytes.len() != COSE_KEY_LEN {
        return Err(crate::error::Error::InvalidLength {
            expected: COSE_KEY_LEN,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[10..42]);
    Ok(out)
}

/// 从 COSE_Key 字节里取回 Y 坐标。
pub fn y_from_cose(bytes: &[u8]) -> Result<[u8; 32], crate::error::Error> {
    if bytes.len() != COSE_KEY_LEN {
        return Err(crate::error::Error::InvalidLength {
            expected: COSE_KEY_LEN,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[45..77]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_is_exactly_77() {
        let key = cose_key(&[0x11; 32], &[0x22; 32]);
        assert_eq!(key.len(), 77);
        assert_eq!(COSE_KEY_LEN, 77);
    }

    #[test]
    fn head_and_tail_are_the_contract_bytes() {
        let key = cose_key(&[0x11; 32], &[0x22; 32]);
        assert_eq!(&key[0..10], &COSE_KEY_PREFIX);
        assert_eq!(&key[42..45], &COSE_KEY_Y_PREFIX);
        assert_eq!(&key[10..42], &[0x11u8; 32]);
        assert_eq!(&key[45..77], &[0x22u8; 32]);
    }

    #[test]
    fn prefix_decodes_as_the_contract_cbor_shape() {
        // map(5) { 1: 2, 3: -7, -1: 2, -2: bytes(32), -3: bytes(32) }
        assert_eq!(COSE_KEY_PREFIX[0], 0xa5);
        // kty = 2 (EC2)
        assert_eq!(&COSE_KEY_PREFIX[1..3], &[1, 2]);
        // alg = -7 (ES256)
        assert_eq!(&COSE_KEY_PREFIX[3..6], &[3, 38, 32]);
        // crv = -3 (P-256)
        assert_eq!(&COSE_KEY_PREFIX[6..9], &[1, 33, 88]);
        // x = bytes(32)
        assert_eq!(COSE_KEY_PREFIX[9], 32);
        // y key = -4, then bytes(32)
        assert_eq!(COSE_KEY_Y_PREFIX[0], 34);
        assert_eq!(&COSE_KEY_Y_PREFIX[1..], &[88, 32]);
    }

    #[test]
    fn coordinates_round_trip() {
        let x = [0xa5u8; 32];
        let y = [0x5au8; 32];
        let key = cose_key(&x, &y);
        assert_eq!(x_from_cose(&key).unwrap(), x);
        assert_eq!(y_from_cose(&key).unwrap(), y);
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert!(x_from_cose(&[0u8; 76]).is_err());
        assert!(y_from_cose(&[0u8; 78]).is_err());
    }
}
