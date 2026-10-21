//! padding 帧的编解码：`PaddingError` / `PaddedChunk` / `encode_padded` /
//! `dechunk_padded`。
//!
//! 参考实现对应 `proxy/vmess/encoding/{client,server}.go` 的头部长度前缀 padding
//! （详见 `super` 的模块文档）。

use std::io;

use super::policy::PaddingPolicy;

/// Maximum padding length, from `dice.Roll(16)` (exclusive bound 16).
///
/// The value is additionally capped at 15 by the high-nibble encoding: a length
/// of 16 would overflow into the low nibble that carries the security type.
pub const MAX_PADDING_LEN: usize = 15;

/// Errors from padding encode/decode. Every decode failure is fail-closed: the
/// caller must drop the connection rather than pass the frame through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaddingError {
    /// `padding_len` does not fit the high nibble (reference: `paddingLen > 15`
    /// would corrupt the security nibble).
    LengthOutOfRange(usize),
    /// The padded chunk is shorter than the declared padding length.
    ///
    /// Mirrors the reference's `ReadFullFrom` returning `io.ErrUnexpectedEOF`
    /// ("failed to read padding").
    Truncated { declared: usize, available: usize },
    /// No payload remained after stripping the padding.
    EmptyPayload,
}

impl std::fmt::Display for PaddingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaddingError::LengthOutOfRange(n) => {
                write!(f, "padding length {n} exceeds {MAX_PADDING_LEN}")
            }
            PaddingError::Truncated {
                declared,
                available,
            } => write!(
                f,
                "failed to read padding: declared {declared}, available {available}"
            ),
            PaddingError::EmptyPayload => write!(f, "padded chunk carried no payload"),
        }
    }
}

impl std::error::Error for PaddingError {}

impl From<PaddingError> for io::Error {
    fn from(e: PaddingError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

/// A padded chunk: the payload plus the padding block that followed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddedChunk {
    /// The original payload.
    pub payload: Vec<u8>,
    /// The random padding bytes, length `padding_len`.
    pub padding: Vec<u8>,
}

impl PaddedChunk {
    /// Length of the padding block (the value stored in the high nibble).
    pub fn padding_len(&self) -> usize {
        self.padding.len()
    }

    /// The wire form: payload followed by the padding block.
    ///
    /// The reference writes the padding *after* the header fields and before the
    /// checksum, so on the wire the padding trails the meaningful bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload.len() + self.padding.len());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.padding);
        out
    }

    /// Encode the padding length into the high nibble of `flags`, preserving the
    /// low nibble. Port of `byte(paddingLen<<4) | byte(header.Security)`.
    pub fn encode_flags(&self, low_nibble: u8) -> Result<u8, PaddingError> {
        let len = self.padding.len();
        if len > MAX_PADDING_LEN {
            return Err(PaddingError::LengthOutOfRange(len));
        }
        Ok(((len as u8) << 4) | (low_nibble & 0x0F))
    }
}

/// Port of `int(buffer.Byte(35) >> 4)`: recover the padding length from a flags
/// byte, discarding the low nibble.
pub fn decode_flags(flags: u8) -> usize {
    (flags >> 4) as usize
}

/// Port of the encode side: `paddingLen` from `dice.Roll(16)`, then that many
/// random bytes appended after the header fields.
///
/// `low_nibble` is the security-type nibble the caller already has; the returned
/// flags byte is what goes in the header.
pub fn encode_padded(
    payload: &[u8],
    policy: &mut PaddingPolicy,
    low_nibble: u8,
) -> Result<(Vec<u8>, u8), PaddingError> {
    let chunk = policy.pad(payload)?;
    let flags = chunk.encode_flags(low_nibble)?;
    Ok((chunk.to_bytes(), flags))
}

/// Port of the decode side: read `padding_len` from the flags byte, then strip
/// exactly that many trailing bytes.
///
/// `padding_len` is passed separately (rather than parsed from `bytes`) because
/// the reference reads it from a header byte that is *outside* the padded
/// region — `dechunk_padded` cannot infer it from the buffer alone. Callers
/// typically do `dechunk_padded(body, decode_flags(flags))`.
///
/// Fail-closed: a declared length larger than the buffer is [`PaddingError::Truncated`],
/// and a frame that is nothing but padding is [`PaddingError::EmptyPayload`]
/// (the reference would hand an empty buffer to the address parser and fail there
/// instead; we surface it earlier and just as loudly).
pub fn dechunk_padded(bytes: &[u8], padding_len: usize) -> Result<Vec<u8>, PaddingError> {
    if padding_len > MAX_PADDING_LEN {
        return Err(PaddingError::LengthOutOfRange(padding_len));
    }
    if padding_len > bytes.len() {
        return Err(PaddingError::Truncated {
            declared: padding_len,
            available: bytes.len(),
        });
    }
    let payload_len = bytes.len() - padding_len;
    if payload_len == 0 {
        return Err(PaddingError::EmptyPayload);
    }
    Ok(bytes[..payload_len].to_vec())
}
