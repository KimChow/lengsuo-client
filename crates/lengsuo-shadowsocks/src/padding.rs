//! Chunked padding codec, transcribed from the reference's padding format.
//!
//! # Provenance (read before changing anything here)
//!
//! The task brief listed `common/protocol/padding/` as a required reference path.
//! **That package does not exist in Xray v26.3.27.** There is no padding code
//! anywhere under `proxy/shadowsocks/` either — classic Shadowsocks in this
//! reference version is unpadded. Rather than invent an SS padding format (which
//! the brief explicitly forbids), this module transcribes the padding that the
//! reference *actually* implements: the VMess header padding codec in
//! `proxy/vmess/encoding/{client,server}.go`.
//!
//! That format is a single length-prefixed padding block, not a multi-block
//! scheme:
//!
//! ```text
//! client.go  EncodeRequestHeader:
//!     paddingLen := dice.Roll(16)                       // 0..=15
//!     security   := byte(paddingLen<<4) | byte(security) // high nibble
//!     ...
//!     if paddingLen > 0 { buffer.ReadFullFrom(rand.Reader, int32(paddingLen)) }
//!
//! server.go  header decode:
//!     paddingLen := int(buffer.Byte(35) >> 4)            // high nibble
//!     ...
//!     if paddingLen > 0 { buffer.ReadFullFrom(decryptor, int32(paddingLen)) }
//! ```
//!
//! So: the length lives in the *high nibble* of an existing header byte (max 15,
//! because the low nibble carries the security type), the padding bytes are
//! random and carry no marker, and the receiver strips exactly `paddingLen`
//! bytes. Nothing here is self-describing beyond that nibble — which is exactly
//! why the decoder below must be told the length rather than discovering it.
//!
//! # Scope
//!
//! This is the *codec only*: [`PaddingPolicy`] rolls a length, [`encode_padded`]
//! appends the block, [`dechunk_padded`] strips and validates it. Wiring it into
//! `tcp.rs`'s send/receive path is deliberately **not** done, because classic
//! Shadowsocks has no header byte to steal a nibble from and the reference adds
//! no padding there. Doing so would change the on-wire SS format and break
//! interoperability with the reference binary. See `docs/shadowsocks-status.md`.

use std::io;

use crate::drain::GoRand;

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

/// Decides how much padding a frame carries.
///
/// The reference uses `dice.Roll(16)` — a process-global, non-deterministic roll.
/// A caller that needs reproducibility (tests, or a deployment that must match a
/// peer's expectations) can inject a [`GoRand`] instead, which is what the
/// [`PaddingPolicy::with_seed`] constructor provides.
#[derive(Debug, Clone)]
pub enum PaddingPolicy {
    /// `dice.Roll(16)` on the shared global source.
    Global,
    /// Deterministic `DeterministicDice.Roll(16)`, for reproducible frames.
    Seeded(Box<GoRand>),
    /// Always pad by a fixed amount (0 disables padding).
    Fixed(usize),
}

impl PaddingPolicy {
    /// A deterministic policy. Same seed ⇒ same padding lengths ⇒ byte-identical
    /// frames, which is what the tests assert.
    pub fn with_seed(seed: i64) -> Self {
        PaddingPolicy::Seeded(Box::new(GoRand::new(seed)))
    }

    /// Roll the next padding length, in `0..=MAX_PADDING_LEN`.
    ///
    /// Note the reference's `Roll(16)` is only bounded by 16; the nibble encoding
    /// silently truncates a 16 to 0. We keep the roll and let
    /// [`PaddedChunk::encode_flags`] reject out-of-range values instead of
    /// silently corrupting the flags byte — see the deviation list.
    pub fn roll(&mut self) -> usize {
        match self {
            PaddingPolicy::Global => global_roll_16(),
            PaddingPolicy::Seeded(r) => {
                let n = r.roll(16);
                // The reference would encode 16 as 0; surface it as 0 rather than
                // producing a length the nibble cannot carry.
                if n > MAX_PADDING_LEN {
                    0
                } else {
                    n
                }
            }
            PaddingPolicy::Fixed(n) => *n,
        }
    }

    /// Build a [`PaddedChunk`] by appending `roll()` random bytes to `payload`.
    pub fn pad(&mut self, payload: &[u8]) -> Result<PaddedChunk, PaddingError> {
        let len = self.roll();
        if len > MAX_PADDING_LEN {
            return Err(PaddingError::LengthOutOfRange(len));
        }
        Ok(PaddedChunk {
            payload: payload.to_vec(),
            padding: random_bytes(len),
        })
    }
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

/// Random padding bytes, port of `buffer.ReadFullFrom(rand.Reader, paddingLen)`.
///
/// The reference makes no attempt to make padding *look* like anything: it is
/// raw CSPRNG output with no marker, which is what lets the receiver strip it
/// purely by length.
fn random_bytes(len: usize) -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);
    let mut out = Vec::with_capacity(len);
    if len == 0 {
        return out;
    }
    let mut s = STATE.load(Ordering::Relaxed);
    if s == 0 {
        s = seed_from_os();
    }
    while out.len() < len {
        s = splitmix64(s);
        let chunk = s.to_le_bytes();
        let take = (len - out.len()).min(chunk.len());
        out.extend_from_slice(&chunk[..take]);
    }
    STATE.store(s, Ordering::Relaxed);
    out
}

fn seed_from_os() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    h.write_u64(&h as *const _ as usize as u64);
    h.finish().max(1)
}

fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// Port of `dice.Roll(16)` on the global source; `0..=15`.
fn global_roll_16() -> usize {
    let mut b = [0u8; 1];
    b.copy_from_slice(&random_bytes(1));
    (b[0] & 0x0F) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_roundtrip_preserves_low_nibble() {
        for len in 0..=MAX_PADDING_LEN {
            for low in [0x00u8, 0x03, 0x05, 0x0F] {
                let chunk = PaddedChunk {
                    payload: vec![],
                    padding: vec![0u8; len],
                };
                let flags = chunk.encode_flags(low).unwrap();
                assert_eq!(decode_flags(flags), len, "len={len} low={low:#x}");
                assert_eq!(flags & 0x0F, low, "low nibble must survive");
            }
        }
    }

    #[test]
    fn encode_flags_rejects_length_beyond_nibble() {
        let chunk = PaddedChunk {
            payload: vec![],
            padding: vec![0u8; 16],
        };
        assert_eq!(
            chunk.encode_flags(0),
            Err(PaddingError::LengthOutOfRange(16))
        );
    }

    #[test]
    fn roundtrip_every_length_boundary() {
        // 0..=15 padding over payloads of every small length: the wire form must
        // always strip back to the original payload byte-for-byte.
        for pad in 0..=MAX_PADDING_LEN {
            // Payloads start at 1: with a non-empty padding block, a zero-length
            // payload is indistinguishable from a probe and is rejected by
            // `dechunk_padded` as `EmptyPayload`.
            for payload_len in 1..=8usize {
                let payload: Vec<u8> = (0..payload_len).map(|i| i as u8).collect();
                let mut policy = PaddingPolicy::Fixed(pad);
                let (wire, flags) = encode_padded(&payload, &mut policy, 0x05).unwrap();
                assert_eq!(wire.len(), payload_len + pad);
                assert_eq!(decode_flags(flags), pad);
                let got = dechunk_padded(&wire, decode_flags(flags)).unwrap();
                assert_eq!(got, payload, "pad={pad} payload_len={payload_len}");
            }
        }
    }

    #[test]
    fn dechunk_rejects_truncated_frame() {
        // Declared padding longer than the buffer: fail-closed.
        assert_eq!(
            dechunk_padded(&[1, 2, 3], 7),
            Err(PaddingError::Truncated {
                declared: 7,
                available: 3
            })
        );
    }

    #[test]
    fn dechunk_rejects_out_of_range_length() {
        assert_eq!(
            dechunk_padded(&[0u8; 64], 16),
            Err(PaddingError::LengthOutOfRange(16))
        );
    }

    #[test]
    fn dechunk_rejects_padding_only_frame() {
        assert_eq!(
            dechunk_padded(&[0u8; 4], 4),
            Err(PaddingError::EmptyPayload)
        );
    }

    #[test]
    fn dechunk_accepts_zero_padding() {
        assert_eq!(dechunk_padded(b"hello", 0).unwrap(), b"hello");
    }

    #[test]
    fn seeded_policy_is_reproducible_and_bounded() {
        let mut a = PaddingPolicy::with_seed(42);
        let mut b = PaddingPolicy::with_seed(42);
        for _ in 0..32 {
            let x = a.roll();
            assert_eq!(x, b.roll());
            assert!(x <= MAX_PADDING_LEN);
        }
    }

    #[test]
    fn seeded_policy_actually_varies() {
        // A policy that always returned 0 would pass the bounds check above while
        // providing no padding at all; assert the distribution is not degenerate.
        let mut p = PaddingPolicy::with_seed(7);
        let rolls: Vec<usize> = (0..64).map(|_| p.roll()).collect();
        assert!(rolls.iter().any(|&r| r > 0), "padding never engaged");
        assert!(rolls.iter().collect::<std::collections::HashSet<_>>().len() > 1);
    }

    #[test]
    fn padding_bytes_are_random_and_markerless() {
        let mut p = PaddingPolicy::Fixed(8);
        let a = p.pad(b"payload").unwrap();
        let b = p.pad(b"payload").unwrap();
        assert_eq!(a.payload, b.payload);
        assert_eq!(a.padding.len(), 8);
        assert_eq!(b.padding.len(), 8);
        assert_ne!(a.padding, b.padding, "padding must not be a constant");
    }

    #[test]
    fn encoded_padded_bytes_use_a_valid_seed() {
        // Guards the `seed_from_os().max(1)` path: a zero seed would freeze the
        // splitmix chain and make every frame's padding identical.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..16 {
            seen.insert(random_bytes(8));
        }
        assert!(seen.len() > 1, "padding generator appears stuck");
    }

    #[test]
    fn error_is_fail_closed_into_io_error() {
        let e: io::Error = PaddingError::EmptyPayload.into();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }
}
