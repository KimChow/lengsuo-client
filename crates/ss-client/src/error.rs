use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("handshake rejected: {0}")]
    Handshake(String),

    #[error("core protocol error: {0}")]
    Core(#[from] ss_core::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
