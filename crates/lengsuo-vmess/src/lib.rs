#![forbid(unsafe_code)]
//! VMess AEAD 客户端原语层（KDF / AuthID / 头部 AEAD / 请求头编码 / 数据段分帧）。
//!
//! 定位：**只做客户端原语**——不做服务器、不做网络连接、不做会话状态机。
//!
//! 语义来源（只读参考，Go 侧同类）：
//! - `proxy/vmess/aead/{consts.go,kdf.go,authid.go,encrypt.go}`
//! - `proxy/vmess/encoding/{auth.go,client.go}`（仅客户端请求头编码路径）
//! - `common/crypto/{authenticator.go,io.go}`（数据段 AEAD 分帧与递增 nonce）
//!
//! 关键语义（不可偏离）：
//! - [`kdf`]：HMAC-SHA256 链式派生，链式方式是「把上一级 HMAC 作为下一级 HMAC 的 hash 工厂」，
//!   输出长度参数化（KDF=32、KDF16=16）。
//! - [`authid`]：16 字节 = BE64 时间戳 || 随机 4 字节 || CRC32-IEEE(前 12 字节) BE32，
//!   整体用 AES-128-ECB（密钥 = `KDF16(cmdKey, "AES Auth ID Encryption")`）加密。
//! - 头部两段 AES-128-GCM 均以 AuthID 作为 AAD；线上 = AuthID || len CT(18) || 连接侧随机 8B || body CT。
//! - 响应头解密后的 4 字节 = **认证明文 FNV32a(body||IV||key)**（不是 CRC32 校验和，也不是密文）。
//! - 数据段分帧复用 `ss-core::chunk`：size 段是**裸 BE16 长度**（ShakeSizeParser 掩码异或，
//!   非 AEAD 封包），载荷段是 AEAD(pt)，每段各消耗一个递增 nonce。
//!
//! 复用约束：目标地址一律使用 [`ss_core::target::TargetAddr`]，本 crate 无第二套地址实现；
//! AEAD/chunk 骨架一律走 `ss-core::{crypto,chunk}`。
//!
//! 互通状态：**未验证**。未与 Xray/sing-box VMess 服务端做实跑互通，本模块不宣称互通兼容；
//! 固定向量仅来自静态阅读参考代码（非参考二进制实跑产物），逐条列在
//! `docs/vmess-status.md`。含密钥材料的结构体一律不实现 `Debug`，错误消息只携带长度/字段名。
//!
//! 当前范围限制（不静默假装支持）：
//! - 请求头只发 `none` 与 `auth_aead` 两类安全选项；`legacy`（历史认证模式）与
//!   `OuterHash`（旧版外层 MD5 混淆）不实现，相关方法返回 [`Error::Unsupported`]。
//! - 设备时间偏移固定 0；参考的 `TimeDiff` 可配置偏移属客户端会话层，原语层不覆盖。

pub mod aead;
pub mod authid;
pub mod chunkframe;
pub mod consts;
pub mod kdf;
pub mod request;
pub mod testvector;

pub use crate::consts::{
    KDF_SALT_AEAD_RESP_HEADER_LEN_IV, KDF_SALT_AEAD_RESP_HEADER_LEN_KEY,
    KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV, KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY,
    KDF_SALT_AUTH_ID_ENCRYPTION_KEY, KDF_SALT_VMESS_AEAD_KDF, KDF_SALT_VMESS_HEADER_LEN_AEAD_IV,
    KDF_SALT_VMESS_HEADER_LEN_AEAD_KEY, KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV,
    KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY,
};
pub use aead::{
    open_response_header_length, open_response_header_payload, open_vmess_aead_header,
    parse_auth_id_from_header, response_header_length_key_iv, response_header_payload_key_iv,
    seal_header_with, seal_vmess_aead_header, HEADER_NONCE_LEN, RESPONSE_AUTH_LEN,
    RESPONSE_AUTH_SALT,
};
pub use authid::{
    auth_id_aes_key, create_auth_id, create_auth_id_with, decode_auth_id, decode_auth_id_bytes,
    time_in_window, AuthId, TIME_WINDOW_SECS,
};
pub use chunkframe::{
    generate_chacha20_poly1305_key, md5_digest, new_data_aead, open_data_chunk, plain_size_encode,
    read_data_chunk, read_data_chunk_into, seal_data_chunk, shake_mask, write_data_chunk,
    write_data_eof, DataCipher, DataSizeParser, MAX_CHUNK_PAYLOAD,
};
pub use kdf::{kdf, kdf16, kdf_n, ID_BYTES, KDF_MAX_LEN};
pub use request::{
    fnv1a32, CipherSpec, Command, HeaderPlanner, KeySource, RequestHeader, SecurityOption, KEY_LEN,
    NONCE_LEN,
};
pub use testvector::{
    aead_encrypt_case, aead_seal_case, auth_id_case, kdf_case, legacy_reduced_key_case,
    request_plaintext_case, response_auth_case, shake_size_case,
};

/// 本 crate 统一错误类型。
///
/// 约束：任何变体都**不得携带密钥、明文、随机数或线上字节**，只允许携带长度与字段名，
/// 以免通过 `Display`/`Debug` 泄漏凭据。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 通用 fail-closed 鉴权/解码失败（无细节，避免侧信道与泄漏）。
    #[error("VMess AEAD authentication or decoding failed")]
    AuthFailed,

    /// 头部载荷被截断：期望 `{need}` 字节，实际 `{got}` 字节。
    #[error("VMess header truncated: need {need} bytes, got {got}")]
    Truncated { need: usize, got: usize },

    /// 头部声明长度非法或超出上限。
    #[error("VMess header length invalid: declared {declared}, got {got}")]
    BadLength { declared: usize, got: usize },

    /// 非法或不受支持的版本字节。
    #[error("VMess invalid version byte")]
    InvalidVersion,

    /// 头部字段值非法（携带字段名，不携带值字节）。
    #[error("VMess header field invalid: {field}")]
    InvalidField { field: &'static str },

    /// 时间戳超出允许窗口（携带秒数差，不携带原始时间戳）。
    #[error("VMess timestamp outside {window_secs}s window (delta {delta_secs}s)")]
    ExpiredTime { delta_secs: i64, window_secs: i64 },

    /// 时间戳为负（VMess 规定直接拒绝）。
    #[error("VMess timestamp is negative")]
    NegativeTime,

    /// 重放（同一 AuthID 二次出现）。
    #[error("VMess replayed AuthID")]
    Replay,

    /// AES-128-ECB 单块加解密失败（密钥长度不符）。
    #[error("AES block cipher failed")]
    Cipher,

    /// 随机数源不可用（绝不回退固定/零随机）。
    #[error("cryptographic RNG unavailable")]
    Random,

    /// 该能力在本原语层未实现（fail-closed，不静默降级）。
    #[error("VMess capability not implemented in the primitive layer: {feature}")]
    Unsupported { feature: &'static str },

    /// 底层 ss-core 原语错误。
    #[error("ss-core error: {0}")]
    Core(#[from] ss_core::Error),

    /// I/O 错误（仅帧读写用到）。
    #[error("io error: {0}")]
    Io(String),
}

/// 本 crate 统一结果类型。
pub type Result<T> = std::result::Result<T, Error>;

/// 由 `std::io::Error` 生成 [`Error::Io`]，只保留错误种类，**不保留消息文本**（可能含路径等）。
pub(crate) fn io_err(e: &std::io::Error) -> Error {
    Error::Io(format!("{:?}", e.kind()))
}

/// 填充随机字节；失败即 fail-closed（返回 [`Error::Random`]），绝不使用零值或固定值回退。
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::Random)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write as _;

    /// 含密钥材料的类型手动 Debug 输出必须脱敏（含 KeySource/各处理器）。
    #[test]
    fn debug_outputs_are_redacted() {
        use crate::chunkframe::DataSizeParser;
        use crate::request::{CipherSpec, KeySource, SecurityOption};
        let ks = KeySource {
            body_key: [0xA5u8; 16],
            body_iv: [0x5Au8; 16],
            response_header: 0x0F,
        };
        // KeySource 未实现 Debug：只能检查字段访问不经过格式化。
        let _ = (ks.body_key[0], ks.body_iv[0], ks.response_header);
        let spec = CipherSpec {
            security: SecurityOption::None,
        };
        assert!(format!("{spec:?}").contains("None"));
        let parser = DataSizeParser::new(&[0u8; 16]);
        // DataSizeParser 未实现 Debug（内含掩码流状态）。
        let _ = std::hint::black_box(&parser);
    }

    /// 错误消息不得含密钥材料：所有变体的 Display 仅含长度/字段名。
    #[test]
    fn error_display_contains_only_lengths_and_field_names() {
        let secret_hex = {
            let mut s = String::new();
            for b in 0xA0u8..=0xAF {
                write!(&mut s, "{b:02x}").unwrap();
            }
            s
        };
        let errors = [
            Error::AuthFailed,
            Error::Truncated { need: 32, got: 12 },
            Error::BadLength {
                declared: 4096,
                got: 12,
            },
            Error::InvalidVersion,
            Error::InvalidField { field: "cmd" },
            Error::ExpiredTime {
                delta_secs: 300,
                window_secs: 120,
            },
            Error::NegativeTime,
            Error::Replay,
            Error::Cipher,
            Error::Random,
            Error::Unsupported {
                feature: "legacy auth",
            },
            Error::Io("UnexpectedEof".into()),
        ];
        for e in &errors {
            let text = e.to_string();
            assert!(!text.is_empty());
            assert!(!text.contains(&secret_hex), "error text leaks secret bytes");
        }
    }

    /// Display 里出现的多位数字只允许是长度/秒数，不允许是端口/地址等可关联数据。
    #[test]
    fn error_display_field_names_are_static_str() {
        let e = Error::InvalidField { field: "security" };
        assert_eq!(e.to_string(), "VMess header field invalid: security");
        let e = Error::Unsupported {
            feature: "legacy auth",
        };
        assert_eq!(
            e.to_string(),
            "VMess capability not implemented in the primitive layer: legacy auth"
        );
    }
}
