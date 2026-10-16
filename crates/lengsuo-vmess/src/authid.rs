//! VMess AuthID（对齐 `proxy/vmess/aead/authid.go`）。
//!
//! 线格式（加密前的 16 字节明文）：`BE64(unix 秒) || 随机 4B || BE32(CRC32-IEEE(前 12B))`，
//! 整体用 AES-128-ECB 单块加密，密钥 = `KDF16(cmdKey, "AES Auth ID Encryption")`。
//! 解码方（服务端）逐用户解密后校验 CRC32 与时间窗（`|t - now| <= 120` 秒，负时间戳
//! 直接拒绝）；客户端侧本模块只生成与自检，不做服务端 Match/重放过滤（那是服务端
//! 职责，依赖连接状态）。
//!
//! 与参考的对应：`CreateAuthID`（生成）、`NewAuthIDDecoder.Decode`（解码三段）、
//! `Match` 的时间窗判据（`math.Abs(|float64(t)| - now) > 120`）。CRC32 用
//! `crc32fast`（IEEE 表，与 Go `hash/crc32` ChecksumIEEE 一致）。

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use crc32fast::Hasher as Crc32;

use crate::consts::{AUTH_ID_LEN, AUTH_ID_TIME_WINDOW_SECS, KDF_SALT_AUTH_ID_ENCRYPTION_KEY};
use crate::kdf::kdf16;
use crate::{fill_random, Error, Result};

/// AuthID 长度（= AES-128 块长）。
pub const AUTH_ID_LEN_USIZE: usize = AUTH_ID_LEN;
/// 服务端时间窗：`|ts - now| > 120` 秒即无效（`authid.go` Match）。
pub const TIME_WINDOW_SECS: i64 = AUTH_ID_TIME_WINDOW_SECS;

/// AuthID 密文（16 字节，即一条 AES-128-ECB 块）。
#[derive(Clone, PartialEq, Eq)]
pub struct AuthId([u8; AUTH_ID_LEN]);

impl AuthId {
    /// 由 16 字节构造；不校验内容（解码路径先解密再验 CRC）。
    #[must_use]
    pub fn from_bytes(bytes: [u8; AUTH_ID_LEN]) -> Self {
        AuthId(bytes)
    }

    /// 线上 16 字节。
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AUTH_ID_LEN] {
        &self.0
    }
}

/// 故意脱敏：AuthID 是认证凭据的一部分，`{:?}` 只给长度。
impl core::fmt::Debug for AuthId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthId").field("len", &AUTH_ID_LEN).finish()
    }
}

/// `KDF16(cmdKey, "AES Auth ID Encryption")` → AES-128 密钥（`NewCipherFromKey`）。
#[must_use]
pub fn auth_id_aes_key(cmd_key: &[u8]) -> [u8; 16] {
    kdf16(cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY.as_bytes()])
}

/// CRC32-IEEE（与 Go `crc32.ChecksumIEEE` 一致）。
fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut hasher = Crc32::new();
    hasher.update(bytes);
    hasher.finalize()
}

/// `CreateAuthID`：随机 4 字节由系统 CSPRNG 提供，失败 fail-closed。
pub fn create_auth_id(cmd_key: &[u8], unix_seconds: i64) -> Result<AuthId> {
    let mut random = [0u8; 4];
    fill_random(&mut random)?;
    Ok(create_auth_id_with(cmd_key, unix_seconds, &random))
}

/// 确定性变体（测试与向量生成用）：随机段由调用方注入。
#[must_use]
pub fn create_auth_id_with(cmd_key: &[u8], unix_seconds: i64, random: &[u8; 4]) -> AuthId {
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&unix_seconds.to_be_bytes());
    plain[8..12].copy_from_slice(random);
    let checksum = crc32_ieee(&plain[..12]);
    plain[12..].copy_from_slice(&checksum.to_be_bytes());
    let key = auth_id_aes_key(cmd_key);
    let cipher = Aes128::new(GenericArray::from_slice(&key));
    let mut block = GenericArray::clone_from_slice(&plain);
    cipher.encrypt_block(&mut block);
    AuthId(block.into())
}

/// `Decode` 后的三段明文。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedAuthId {
    /// BE64 时间戳（可为负，负值由 [`time_in_window`] 判 `NegativeTime`）。
    pub unix_seconds: i64,
    /// 随机 4 字节。
    pub random: [u8; 4],
    /// CRC32 校验值（解密方重算比对）。
    pub checksum: u32,
}

/// 解密并拆出三段；不校验 CRC/时间窗（那是 [`decode_auth_id`] / 服务端职责）。
///
/// 与参考 `Decode` 一致：AES-128-ECB 单块解密后按 `t || rand || zero` 拆分。
#[must_use]
pub fn decode_auth_id_bytes(cmd_key: &[u8], auth_id: &[u8; AUTH_ID_LEN]) -> DecodedAuthId {
    let key = auth_id_aes_key(cmd_key);
    let cipher = Aes128::new(GenericArray::from_slice(&key));
    let mut block = GenericArray::clone_from_slice(auth_id);
    cipher.decrypt_block(&mut block);
    let plain: [u8; 16] = block.into();
    let unix_seconds = i64::from_be_bytes(plain[..8].try_into().expect("8 字节"));
    let random = plain[8..12].try_into().expect("4 字节");
    let checksum = u32::from_be_bytes(plain[12..].try_into().expect("4 字节"));
    DecodedAuthId {
        unix_seconds,
        random,
        checksum,
    }
}

/// 完整校验路径：解密 + CRC32 重算 + 时间窗（`|t - now| > 120` 拒绝，负时间拒绝）。
///
/// 返回 `Ok(())` 表示该 AuthID 对 `cmd_key` 合法且新鲜。CRC 不匹配按
/// [`Error::AuthFailed`]（与"错误密钥解出垃圾"不可区分，避免侧信道）。
pub fn decode_auth_id(cmd_key: &[u8], auth_id: &[u8; AUTH_ID_LEN], now_unix: i64) -> Result<()> {
    let decoded = decode_auth_id_bytes(cmd_key, auth_id);
    let mut plain = [0u8; 12];
    plain[..8].copy_from_slice(&decoded.unix_seconds.to_be_bytes());
    plain[8..].copy_from_slice(&decoded.random);
    if crc32_ieee(&plain) != decoded.checksum {
        return Err(Error::AuthFailed);
    }
    if !time_in_window(decoded.unix_seconds, now_unix) {
        return Err(if decoded.unix_seconds < 0 {
            Error::NegativeTime
        } else {
            let delta = decoded.unix_seconds - now_unix;
            Error::ExpiredTime {
                delta_secs: delta.abs(),
                window_secs: TIME_WINDOW_SECS,
            }
        });
    }
    Ok(())
}

/// `Match` 的时间窗判据：`|t - now| <= 120` 秒有效；负时间戳一律无效。
#[must_use]
pub fn time_in_window(unix_seconds: i64, now_unix: i64) -> bool {
    unix_seconds >= 0 && (unix_seconds - now_unix).abs() <= TIME_WINDOW_SECS
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    const CMD_KEY: &[u8; 16] = b"b831381d-6324-4d"; // 16 字节假 cmdKey（测试专用）

    #[test]
    fn authid_roundtrip_and_fields() {
        let random = [0x01, 0x02, 0x03, 0x04];
        let ts = 1_700_000_000i64;
        let auth = create_auth_id_with(CMD_KEY, ts, &random);
        assert_eq!(auth.as_bytes().len(), 16);
        let decoded = decode_auth_id_bytes(CMD_KEY, auth.as_bytes());
        assert_eq!(decoded.unix_seconds, ts);
        assert_eq!(decoded.random, random);
        // CRC 自洽。
        let mut plain = [0u8; 12];
        plain[..8].copy_from_slice(&ts.to_be_bytes());
        plain[8..].copy_from_slice(&random);
        assert_eq!(decoded.checksum, crc32_ieee(&plain));
        assert!(time_in_window(decoded.unix_seconds, ts));
    }

    #[test]
    fn aes_ecb_block_is_reference_compatible() {
        // AES-128-ECB 单块 FIPS-197 标准向量（key=00..0f, pt=00112233...），
        // 锁定我们与 Go crypto/aes 同为标准 AES。
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plain = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let cipher = Aes128::new(GenericArray::from_slice(&key));
        let mut block = GenericArray::clone_from_slice(&plain);
        cipher.encrypt_block(&mut block);
        assert_eq!(
            hex::encode(block),
            "69c4e0d86a7b0430d8cdb78070b4c55a",
            "FIPS-197 C.1 AES-128 标准向量"
        );
    }

    #[test]
    fn wrong_cmd_key_fails_crc_check() {
        let ts = 1_700_000_000i64;
        let auth = create_auth_id(CMD_KEY, ts).expect("可生成");
        let evil = [0xFFu8; 16];
        assert!(matches!(
            decode_auth_id(&evil, auth.as_bytes(), ts),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn time_window_boundaries() {
        let now = 1_000_000i64;
        assert!(time_in_window(now, now));
        assert!(time_in_window(now - 120, now));
        assert!(time_in_window(now + 120, now));
        assert!(!time_in_window(now - 121, now));
        assert!(!time_in_window(now + 121, now));
        assert!(!time_in_window(-1, now));
    }

    #[test]
    fn tampered_authid_is_auth_failed() {
        let ts = 1_700_000_000i64;
        let mut bytes = *create_auth_id(CMD_KEY, ts).expect("可生成").as_bytes();
        bytes[0] ^= 0x01;
        assert!(matches!(
            decode_auth_id(CMD_KEY, &bytes, ts),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn debug_never_prints_authid_bytes() {
        let auth = create_auth_id(CMD_KEY, 1_700_000_000).expect("可生成");
        let printed = format!("{auth:?}");
        assert!(printed.contains("AuthId") && !printed.contains("hex"));
    }
}
