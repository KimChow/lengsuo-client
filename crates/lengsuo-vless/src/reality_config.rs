//! REALITY 客户端配置：解析期校验（fail-closed）。
//!
//! 对齐参考 `infra/conf/transport_internet.go` `REALITYConfig.Build` 的客户端分支：
//! fingerprint（`unsafe`/`hellogolang` → 未知）→ password/publicKey
//! （空 → base64 raw-url → 32 字节）→ shortId（长度 → hex）。
//! 任一步失败都**必须**由调用方当作启动失败，不得降级成「无 REALITY 直连」。
//!
//! crate 内无 base64 依赖（不得新增），故自带 raw-url 解码器。

use crate::reality::shortid::parse_short_id;
use crate::reality::{Fingerprint, RealityClientConfig};
use thiserror::Error;

/// REALITY 配置解析失败。全部 fail-closed：不得降级成「无 REALITY 直连」。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// 参考 `empty "password"`。
    #[error(r#"REALITY: empty "password""#)]
    EmptyPublicKey,
    /// 参考 `invalid "password"`：base64 raw-url 解码失败或不是 32 字节。
    #[error(r#"REALITY: invalid "password""#)]
    InvalidPublicKey,
    /// 参考 `unknown "fingerprint"`。
    #[error(r#"REALITY: unknown "fingerprint""#)]
    UnknownFingerprint,
    /// 参考客户端明确拒绝 `unsafe` / `hellogolang`。
    #[error(r#"REALITY: invalid "fingerprint""#)]
    InvalidFingerprint,
    /// 参考 `too long "shortId"` / `invalid "shortId"`。
    #[error(r#"REALITY: invalid "shortId""#)]
    InvalidShortId,
}

/// 明文配置中对端可见的 REALITY 字段（参考 `realitySettings` 的客户端子集）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RealitySettings {
    /// `serverName`；空串时按参考回退到目标地址。
    pub server_name: String,
    /// `password`（参考里非空即覆盖 `publicKey`）。
    pub password: String,
    /// `publicKey`（base64 raw-url，解码后须为 32 字节）。
    pub public_key: String,
    /// `shortId`（十六进制字符串，最多 16 个字符）。
    pub short_id: String,
    /// `fingerprint`；空串在参考里归一为 `HelloChrome_Auto`。
    pub fingerprint: String,
}

/// 经校验的 REALITY 客户端配置。
#[derive(Clone)]
pub struct RealityConfig {
    pub(crate) client: RealityClientConfig,
    /// 配置里的指纹明文（诊断用；`Fingerprint` 的 `Debug` 只给枚举）。
    fingerprint_name: String,
}

impl std::fmt::Debug for RealityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityConfig")
            .field("server_name", &self.client.server_name)
            .field("public_key", &"<redacted>")
            .field("short_id", &"<redacted>")
            .field("fingerprint", &self.fingerprint_name)
            .finish()
    }
}

impl RealityConfig {
    /// 解析并校验配置。任一步失败都返回错误，调用方**必须**当作启动失败。
    ///
    /// 判定顺序对齐参考 `REALITYConfig.Build` 的客户端分支：
    /// fingerprint（`unsafe`/`hellogolang` → 未知）→ password/publicKey
    /// （空 → base64 → 32 字节）→ shortId（长度 → hex）。
    pub fn from_settings(settings: RealitySettings) -> Result<Self, ConfigError> {
        let fingerprint = settings.fingerprint.to_ascii_lowercase();
        if fingerprint == "unsafe" || fingerprint == "hellogolang" {
            return Err(ConfigError::InvalidFingerprint);
        }
        let parsed =
            Fingerprint::parse(&fingerprint).map_err(|_| ConfigError::UnknownFingerprint)?;
        let password = if settings.password.is_empty() {
            &settings.public_key
        } else {
            &settings.password
        };
        if password.is_empty() {
            return Err(ConfigError::EmptyPublicKey);
        }
        let public_key = decode_public_key(password).ok_or(ConfigError::InvalidPublicKey)?;
        let short_id =
            parse_short_id(&settings.short_id).map_err(|_| ConfigError::InvalidShortId)?;
        Ok(Self {
            client: RealityClientConfig {
                server_name: Some(settings.server_name).filter(|name| !name.is_empty()),
                public_key,
                short_id,
                fingerprint: parsed,
            },
            fingerprint_name: fingerprint,
        })
    }

    /// `serverName` 为空时按参考回退到目标地址。
    pub fn server_name<'a>(&'a self, dest: &'a str) -> &'a str {
        self.client.effective_server_name(dest)
    }
}

/// base64 raw-url（RFC 4648 §5，无 padding）解码公钥，**必须**恰好 32 字节。
///
/// crate 内无 base64 依赖（不得新增），故自带解码器：拒绝 padding、URL 字符集
/// 之外的字符、以及尾组冗余位非零的畸形编码（Go `RawURLEncoding` 同样报错）。
fn decode_public_key(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    let groups = bytes.len().div_ceil(4);
    for (index, group) in bytes.chunks(4).enumerate() {
        let mut value = 0u64;
        for byte in group {
            value = (value << 6) | u64::from(base64_sextet(*byte)?);
        }
        let bits = group.len() * 6;
        let produced = bits / 8;
        // 尾组只产出 `produced` 字节，其外的**低位**必须是补的 0
        // （3 字符 → 低 2 位、2 字符 → 低 4 位），非零即畸形（Go 同样报错）。
        // 第 k 个产出字节位于 `[bits-8(k+1), bits-8k)`。
        let spare = bits - produced * 8;
        if index + 1 == groups && group.len() < 4 && value & ((1u64 << spare) - 1) != 0 {
            return None;
        }
        for index in 0..produced {
            out.push(((value >> (bits - 8 * (index + 1))) & 0xff) as u8);
        }
    }
    out.try_into().ok()
}

/// 单个 base64url 字符 → 6 位值。
fn base64_sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            out.push(TABLE[(n >> 18) as usize & 0x3f] as char);
            out.push(TABLE[(n >> 12) as usize & 0x3f] as char);
            if chunk.len() > 1 {
                out.push(TABLE[(n >> 6) as usize & 0x3f] as char);
            }
            if chunk.len() > 2 {
                out.push(TABLE[n as usize & 0x3f] as char);
            }
        }
        out
    }

    fn settings(public_key: String) -> RealitySettings {
        RealitySettings {
            server_name: "www.example.com".to_owned(),
            password: String::new(),
            public_key,
            short_id: "3132333435363738".to_owned(),
            fingerprint: "chrome".to_owned(),
        }
    }

    #[test]
    fn public_key_roundtrips_raw_url() {
        let key: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(37)).collect();
        let decoded = decode_public_key(&b64(&key)).expect("合法 base64url");
        assert_eq!(&decoded[..], &key[..]);
    }

    #[test]
    fn public_key_rejects_invalid_base64_and_wrong_length() {
        assert_eq!(decode_public_key(""), None);
        assert_eq!(decode_public_key("A"), None, "长度 1 mod 4 非法");
        assert_eq!(decode_public_key("AA=A"), None, "padding 不是 raw-url");
        assert_eq!(decode_public_key("+/+/"), None, "标准表字符不在 URL 字符集");
        assert_eq!(decode_public_key(&b64(&[0x11; 31])), None, "31 字节");
        assert_eq!(decode_public_key(&b64(&[0x11; 33])), None, "33 字节");
        assert_eq!(decode_public_key("AQ"), None, "尾组冗余位非零");
    }

    #[test]
    fn config_is_fail_closed() {
        assert_eq!(
            RealityConfig::from_settings(settings(String::new())).err(),
            Some(ConfigError::EmptyPublicKey)
        );
        assert_eq!(
            RealityConfig::from_settings(settings("%%%".to_owned())).err(),
            Some(ConfigError::InvalidPublicKey)
        );
        assert_eq!(
            RealityConfig::from_settings(settings(b64(&[7; 31]))).err(),
            Some(ConfigError::InvalidPublicKey)
        );
        let mut unknown = settings(b64(&[7; 32]));
        unknown.fingerprint = "curl".to_owned();
        assert_eq!(
            RealityConfig::from_settings(unknown).err(),
            Some(ConfigError::UnknownFingerprint)
        );
        let mut unsafe_fp = settings(b64(&[7; 32]));
        unsafe_fp.fingerprint = "unsafe".to_owned();
        assert_eq!(
            RealityConfig::from_settings(unsafe_fp).err(),
            Some(ConfigError::InvalidFingerprint)
        );
        let mut bad_sid = settings(b64(&[7; 32]));
        bad_sid.short_id = "1234567890abcdef0".to_owned();
        assert_eq!(
            RealityConfig::from_settings(bad_sid).err(),
            Some(ConfigError::InvalidShortId)
        );
    }

    #[test]
    fn config_accepts_reference_forms() {
        let config = RealityConfig::from_settings(settings(b64(&[7; 32]))).expect("合法配置");
        assert_eq!(config.server_name("1.2.3.4:443"), "www.example.com");
        // 空 serverName 按参考回退到目标地址。
        let mut fallback = settings(b64(&[7; 32]));
        fallback.server_name.clear();
        let config = RealityConfig::from_settings(fallback).expect("空 SNI 合法");
        assert_eq!(config.server_name("1.2.3.4:443"), "1.2.3.4:443");
        // `password` 非空即覆盖 `publicKey`（参考语义）。
        let mut alias = settings(String::new());
        alias.password = b64(&[9; 32]);
        assert!(RealityConfig::from_settings(alias).is_ok());
        // 空 fingerprint 归一为 chrome（合法）。
        let mut default_fp = settings(b64(&[7; 32]));
        default_fp.fingerprint.clear();
        assert!(RealityConfig::from_settings(default_fp).is_ok());
        // Debug 不得泄露公钥。
        let config = RealityConfig::from_settings(settings(b64(&[7; 32]))).unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&b64(&[7; 32])));
    }
}
