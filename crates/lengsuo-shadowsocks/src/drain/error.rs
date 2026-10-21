//! 排空（drain）路径上的错误类型。
//!
//! 文案与嵌套结构逐条镜像参考实现的 `errors.New(...)`，不得改写。

use std::io;

/// Errors mirroring the reference's `errors.New(...)` strings.
#[derive(Debug)]
pub enum DrainError {
    /// `"drained connection"`.
    Drained,
    /// `"unable to drain connection"` wrapping the underlying IO failure.
    UnableToDrain(io::Error),
    /// The reference's `errors.New(drainErr).Base(err)` nesting.
    Nested {
        drain: Box<DrainError>,
        origin: Box<DrainError>,
    },
    /// A handshake failure, kept so `WithError` can pass it through unchanged.
    Handshake(HandshakeError),
}

impl std::fmt::Display for DrainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DrainError::Drained => write!(f, "drained connection"),
            DrainError::UnableToDrain(e) => write!(f, "unable to drain connection: {e}"),
            DrainError::Nested { drain, origin } => write!(f, "{drain}: {origin}"),
            DrainError::Handshake(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DrainError {}

/// Handshake failures that trigger a drain, one variant per `drain.WithError`
/// call site in `ReadTCPSession`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// `"failed to read 50 bytes"` — header shorter than 50 bytes.
    ShortHeader,
    /// `"failed to match an user"` — no account matched (wrong password).
    NoUser,
    /// `"failed iv check"` — repeated IV / salt.
    IvNotUnique,
    /// `"failed to initialize decoding stream"`.
    DecodeInit,
    /// `"failed to read address"`.
    Address,
    /// `"invalid remote address."`.
    InvalidAddress,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            HandshakeError::ShortHeader => "failed to read 50 bytes",
            HandshakeError::NoUser => "failed to match an user",
            HandshakeError::IvNotUnique => "failed iv check",
            HandshakeError::DecodeInit => "failed to initialize decoding stream",
            HandshakeError::Address => "failed to read address",
            HandshakeError::InvalidAddress => "invalid remote address.",
        })
    }
}

impl std::error::Error for HandshakeError {}
