//! 本 crate 的错误类型。
//!
//! 纪律（照本仓既有风格）：
//! - 错误文本**不含密钥字节、nonce、密文或明文**，只出现长度与语义。
//! - 认证/解析失败一律 fail-closed：调用方必须弃用该数据，不得回退到明文。
//! - 变体之间**语义可区分**，不合并成一个笼统的 `Crypto` 错误。

/// 凭据密码学层的错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// 熵源不可用（拿不到系统随机数）。
    #[error("熵源不可用")]
    EntropyUnavailable,

    /// ES256 密钥生成失败。
    #[error("ES256 密钥生成失败")]
    KeyGeneration,

    /// PKCS#8 私钥被拒绝（格式非法，或公私钥不一致）。
    #[error("PKCS#8 私钥被拒绝")]
    KeyRejected,

    /// 输入长度与协议要求不符。
    #[error("长度不合法：期望 {expected} 字节，实际 {actual} 字节")]
    InvalidLength {
        /// 协议要求的长度。
        expected: usize,
        /// 实际给出的长度。
        actual: usize,
    },

    /// CBOR 值无法编码（当前只支持 map / text / bytes / int，故实际不可达）。
    #[error("CBOR 编码失败")]
    CborEncode,

    /// 标志位含协议未定义的位。
    #[error("标志位含未定义位 {bits:#04x}")]
    UnknownFlagBits {
        /// 被置起的未定义位。
        bits: u8,
    },

    /// 信封魔数不匹配：不是本协议的信封。
    #[error("信封魔数不匹配")]
    EnvelopeBadMagic,

    /// 信封版本不受支持。
    #[error("信封版本不受支持：期望 {expected}，实际 {got}")]
    EnvelopeVersion {
        /// 本 crate 支持的版本。
        expected: u32,
        /// 信封里声明的版本。
        got: u32,
    },

    /// 信封长度字段与实际字节数不符。
    #[error("信封长度不符：声明 {declared} 字节，实际 {actual} 字节")]
    EnvelopeLength {
        /// 头里声明的长度。
        declared: usize,
        /// 实际字节数。
        actual: usize,
    },

    /// 信封认证解密失败：密文被篡改，或 AAD（header）与封入时不一致。
    #[error("信封认证失败")]
    EnvelopeAuthFailed,

    /// KDF 参数不合法（越界或不满足最小强度）。
    #[error("KDF 参数不合法")]
    KdfParams,

    /// KDF 计算失败。
    #[error("KDF 计算失败")]
    KdfFailed,
}

impl From<crate::entropy::EntropyError> for Error {
    fn from(_: crate::entropy::EntropyError) -> Self {
        Self::EntropyUnavailable
    }
}

impl From<crate::flags::FlagsError> for Error {
    fn from(error: crate::flags::FlagsError) -> Self {
        match error {
            crate::flags::FlagsError::UnknownBits { bits } => Self::UnknownFlagBits { bits },
        }
    }
}
