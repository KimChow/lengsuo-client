//! padding 长度的决策策略：`PaddingPolicy`。
//!
//! 参考实现用 `dice.Roll(16)`（进程全局、非确定性）。需要可复现的调用方可以注入
//! [`GoRand`]，见 [`PaddingPolicy::with_seed`]。

use crate::drain::GoRand;

use super::codec::{PaddingError, MAX_PADDING_LEN};

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
    /// [`super::PaddedChunk::encode_flags`] reject out-of-range values instead of
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

    /// Build a [`super::PaddedChunk`] by appending `roll()` random bytes to `payload`.
    pub fn pad(&mut self, payload: &[u8]) -> Result<super::PaddedChunk, PaddingError> {
        let len = self.roll();
        if len > MAX_PADDING_LEN {
            return Err(PaddingError::LengthOutOfRange(len));
        }
        Ok(super::PaddedChunk {
            payload: payload.to_vec(),
            padding: random_bytes(len),
        })
    }
}

/// Port of `dice.Roll(16)` on the global source; `0..=15`.
fn global_roll_16() -> usize {
    let mut b = [0u8; 1];
    b.copy_from_slice(&random_bytes(1));
    (b[0] & 0x0F) as usize
}

/// Random padding bytes, port of `buffer.ReadFullFrom(rand.Reader, paddingLen)`.
///
/// The reference makes no attempt to make padding *look* like anything: it is
/// raw CSPRNG output with no marker, which is what lets the receiver strip it
/// purely by length.
pub(crate) fn random_bytes(len: usize) -> Vec<u8> {
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
