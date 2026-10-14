use thiserror::Error;

/// ss-core 统一错误类型。
#[derive(Debug, Error)]
pub enum Error {
    #[error("buffer too short: need {need} bytes, got {got}")]
    TooShort { need: usize, got: usize },

    #[error("invalid ATYP value: {0:#04x}")]
    InvalidAddressType(u8),

    #[error("invalid length prefix: {0}")]
    InvalidLength(usize),

    #[error("invalid key length for cipher suite")]
    InvalidKeyLength,

    #[error("AEAD seal failed")]
    SealFailed,

    #[error("AEAD authentication failed (wrong key, tampered data, or nonce desync)")]
    AuthFailed,

    #[error("unsupported cipher: {0}")]
    UnsupportedCipher(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
