//! Behavior-probing mitigation for the Shadowsocks inbound.
//!
//! Ported from Xray `common/drain` (`drainer.go`, `dice.go`) and its call sites
//! in `proxy/shadowsocks/protocol.go` / `validator.go`. A censor can replay
//! opaque bytes at the inbound port and measure how much the peer reads or how
//! long it stays alive; that difference is a password oracle. Xray answers by
//! *draining* a password-derived, per-deployment-fixed amount before dropping
//! the connection, so a wrong password costs an observer the same as a right one.
//!
//! Ported pieces:
//! * [`BehaviorSeedLimitedDrainer::new`] — `NewBehaviorSeedLimitedDrainer`,
//!   seed-derived sizes `16+38 / 3266 / 64`, bit-compatible PRNG (see
//!   [`go_rand`]).
//! * [`BehaviorSeedLimitedDrainer::acknowledge_receive`] — authenticated bytes
//!   are credited back, so a valid client never pays the drain.
//! * [`BehaviorSeedSource`] — `Validator.GetBehaviorSeed`: the seed is `0`
//!   (fixed) until the first *failed* handshake and random thereafter.
//! * [`BehaviorSeedLimitedDrainer::with_error`] — `drain.WithError`, drain
//!   before surfacing the handshake error.
//! * [`BehaviorSeedLimitedDrainer::slow_read_penalty`] — bounded slow-read
//!   punishment (a deliberate extension; see `docs/shadowsocks-status.md`).

use std::io::{self, Read};

pub mod go_rand;
mod rng_cooked;

pub use go_rand::GoRand;

/// Foundation of the drain budget: reference `NewBehaviorSeedLimitedDrainer(seed, 16+38, …)`.
pub const DRAIN_FOUNDATION: usize = 16 + 38;
/// Exclusive upper bound of the seed-derived base drain; reference `3266`.
pub const MAX_BASE_DRAIN_SIZE: usize = 3266;
/// Exclusive upper bound of the extra roll, before the reference's `+1`; `64`.
pub const MAX_RAND_DRAIN: usize = 64;
/// Size of the plaintext salt/IV prefix, credited via `AcknowledgeReceive(ivLen)`.
pub const SALT_LEN: usize = 32;

/// Grace period before a peer that sent *nothing at all* is judged hostile.
pub const SLOW_READ_GRACE: std::time::Duration = std::time::Duration::from_millis(500);
/// Below this rate a peer is treated as a slow-read prober.
pub const SLOW_READ_MIN_BYTES_PER_SEC: f64 = 64.0;

/// Port of `drain.BehaviorSeedLimitedDrainer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BehaviorSeedLimitedDrainer {
    /// Remaining drain budget, in bytes.
    pub drain_size: i64,
}

impl BehaviorSeedLimitedDrainer {
    /// Port of `drain.NewBehaviorSeedLimitedDrainer`.
    ///
    /// The reference signature is
    /// `(behaviorSeed int64, drainFoundation, maxBaseDrainSize, maxRandDrain int)`.
    /// `behaviorSeed` arrives as `uint64` from `Validator.GetBehaviorSeed`, so
    /// the `int64` cast is part of the port and lives in [`BehaviorSeedSource`].
    ///
    /// The reference never returns a non-nil error here (it only annotates a
    /// possible constructor failure), so this returns `Self`; [`Self::try_new`]
    /// exists for callers that must thread a `Result`.
    pub fn new(
        behavior_seed: i64,
        drain_foundation: usize,
        max_base_drain_size: usize,
        max_rand_drain: usize,
    ) -> Self {
        let mut behavior_rand = GoRand::new(behavior_seed);
        let base_drain_size = behavior_rand.roll(max_base_drain_size) as i64;
        let rand_drain_max = behavior_rand.roll(max_rand_drain) as i64 + 1;
        // NOTE: the second roll is *not* deterministic in the reference — it
        // calls `dice.Roll`, i.e. the process-global `math/rand` source.
        let rand_drain_rolled = global_roll(rand_drain_max as usize) as i64;
        Self {
            drain_size: drain_foundation as i64 + base_drain_size + rand_drain_rolled,
        }
    }

    /// [`Self::new`] with the Shadowsocks constants (`16+38`, `3266`, `64`).
    pub fn new_shadowsocks(behavior_seed: i64) -> Self {
        Self::new(
            behavior_seed,
            DRAIN_FOUNDATION,
            MAX_BASE_DRAIN_SIZE,
            MAX_RAND_DRAIN,
        )
    }

    /// `Result`-shaped wrapper matching the reference's `(Drainer, error)` return.
    pub fn try_new(
        behavior_seed: i64,
        drain_foundation: usize,
        max_base_drain_size: usize,
        max_rand_drain: usize,
    ) -> Result<Self, DrainError> {
        Ok(Self::new(
            behavior_seed,
            drain_foundation,
            max_base_drain_size,
            max_rand_drain,
        ))
    }

    /// Port of `AcknowledgeReceive`.
    ///
    /// Bytes already authenticated count against the budget. The reference uses
    /// unchecked `int` arithmetic, so the budget is allowed to go negative;
    /// negative simply means "nothing left to drain" (see [`Self::drain`]).
    /// Keeping the sign is load-bearing for parity: since the budget is
    /// seed-derived, bytes-received-so-far stays the only observable, and a
    /// saturating clamp would introduce a difference exactly at exhaustion.
    pub fn acknowledge_receive(&mut self, size: usize) {
        self.drain_size -= size as i64;
    }

    /// Port of `Drain`.
    ///
    /// When the budget is positive, consume exactly `drain_size` further bytes:
    /// * peer supplied them all and then hit EOF → `Err(Drained)`
    ///   (`"drained connection"` — we were talking to a prober),
    /// * peer went away early → `Err(UnableToDrain(..))`.
    ///
    /// When the budget is already non-positive, this is a no-op returning `Ok`.
    pub fn drain<R: Read>(&self, reader: &mut R) -> Result<(), DrainError> {
        if self.drain_size > 0 {
            match drain_read_n(reader, self.drain_size as usize) {
                Ok(()) => Err(DrainError::Drained),
                Err(e) => Err(DrainError::UnableToDrain(e)),
            }
        } else {
            Ok(())
        }
    }

    /// Port of `drain.WithError`: drain first, then report the handshake error.
    ///
    /// A drain that *succeeds* replaces the caller's error with the drain error,
    /// exactly as the reference nests the two.
    pub fn with_error<R: Read>(&self, reader: &mut R, err: DrainError) -> DrainError {
        match self.drain(reader) {
            Ok(()) => err,
            Err(drain_err) => DrainError::Nested {
                drain: Box::new(drain_err),
                origin: Box::new(err),
            },
        }
    }

    /// Bounded slow-read punishment.
    ///
    /// A prober that trickles bytes must still pay the full budget, but must not
    /// be able to pin a worker thread indefinitely. Returns `true` when the peer
    /// should be dropped immediately instead of being drained further.
    ///
    /// This is a deliberate extension beyond the reference (which relies on the
    /// caller's socket deadlines); see the deviation list.
    pub fn slow_read_penalty(&self, bytes_read: usize, elapsed: std::time::Duration) -> bool {
        if bytes_read == 0 {
            return elapsed >= SLOW_READ_GRACE;
        }
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0 {
            return false;
        }
        (bytes_read as f64 / secs) < SLOW_READ_MIN_BYTES_PER_SEC
    }
}

/// Port of `drain.drainReadN`: `io.CopyN(io.Discard, reader, n)`.
fn drain_read_n<R: Read>(reader: &mut R, n: usize) -> io::Result<()> {
    let mut buf = [0u8; 512];
    let mut remaining = n;
    while remaining > 0 {
        let want = remaining.min(buf.len());
        match reader.read(&mut buf[..want]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "eof while draining",
                ))
            }
            Ok(got) => remaining -= got,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Port of `dice.Roll` on the shared process-global `math/rand` source.
fn global_roll(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    use std::sync::atomic::{AtomicU64, Ordering};
    static GLOBAL: AtomicU64 = AtomicU64::new(0);
    let mut state = GLOBAL.load(Ordering::Relaxed);
    if state == 0 {
        state = os_entropy().max(1);
    }
    GLOBAL.store(splitmix64(state), Ordering::Relaxed);
    (splitmix64(state) >> 11) as usize % n
}

fn os_entropy() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    h.finish()
}

fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// Port of `Validator.behaviorSeed` / `GetBehaviorSeed` / the seeding half of `Add`.
///
/// Reference behavior, which this type reproduces exactly:
///
/// ```text
/// Add(user):                                  // validator.go
///     if !v.behaviorFused {
///         hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
///         hashkdf.Write(account.Key)
///         v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
///     }
///
/// GetBehaviorSeed():
///     v.behaviorFused = true
///     if v.behaviorSeed == 0 { v.behaviorSeed = dice.RollUint64() }
///     return v.behaviorSeed
/// ```
///
/// The important consequence is the anti-oracle property: the seed is derived from
/// the **pre-shared key at configuration time**, so every connection in a
/// deployment computes the same drain budget. `random_u64()` is the fallback for a
/// validator that somehow has no user added; it is *not* the normal path.
#[derive(Debug, Default)]
pub struct BehaviorSeedSource {
    behavior_seed: u64,
    behavior_fused: bool,
}

impl BehaviorSeedSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Port of the `Add(user)` seeding half: fold this account's key into the
    /// running CRC-64, unless the seed has already been read.
    ///
    /// Folding (rather than assigning) is what makes a multi-user validator's seed
    /// a function of *all* its keys, exactly as `crc64.Update` chains.
    pub fn add_key(&mut self, key: &[u8]) {
        if self.behavior_fused {
            return;
        }
        let hashkdf = crate::persist::hmac_sha256(b"SSBSKDF", key);
        self.behavior_seed = crc64_update(self.behavior_seed, &hashkdf);
    }

    /// Port of `GetBehaviorSeed`; latches, and falls back to a random seed only
    /// when no key was ever folded in.
    pub fn get_behavior_seed(&mut self) -> u64 {
        self.behavior_fused = true;
        if self.behavior_seed == 0 {
            self.behavior_seed = random_u64();
        }
        self.behavior_seed
    }

    /// `GetBehaviorSeed` narrowed to the reference's `int64` parameter type.
    pub fn get_behavior_seed_i64(&mut self) -> i64 {
        self.get_behavior_seed() as i64
    }

    /// True once [`Self::get_behavior_seed`] has been called at least once.
    pub fn is_fused(&self) -> bool {
        self.behavior_fused
    }

    /// Convenience for the common one-user case: derive the seed from a single key
    /// and return it. Equivalent to `add_key(key); get_behavior_seed()`.
    pub fn from_key(key: &[u8]) -> u64 {
        let mut src = Self::new();
        src.add_key(key);
        src.get_behavior_seed()
    }
}

/// Fallback seed, port of `dice.RollUint64()` — the process-global `math/rand`
/// source. Only reached when a validator has no user folded in.
fn random_u64() -> u64 {
    let x = os_entropy();
    splitmix64(if x == 0 { 0x9e37_79b9_7f4a_7c15 } else { x })
}

/// `hash/crc64` with the ECMA polynomial, as used by `crc64.MakeTable(crc64.ECMA)`.
fn crc64_update(seed: u64, data: &[u8]) -> u64 {
    // Reflected ECMA-182 polynomial (0x42F0E1EBA9EA3693), reversed.
    const POLY: u64 = 0xC96C_5795_D787_0F42;
    let mut crc = seed;
    for &byte in data {
        crc ^= byte as u64;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (POLY & mask);
        }
    }
    crc
}

/// Port of the `SSBSKDF` seed derivation in `ReadTCPResponse`:
/// `crc32.ChecksumIEEE(hmac_sha256("SSBSKDF", key))`.
///
/// This is the *client* side of the same mitigation: the response reader derives
/// the drain budget from the pre-shared key, so it is stable per deployment.
pub fn response_behavior_seed(key: &[u8]) -> u64 {
    // Reuses the crate-local HMAC from `persist`; `hmac`/`sha2` are not direct
    // dependencies of this crate and `Cargo.toml` is off-limits.
    let digest = crate::persist::hmac_sha256(b"SSBSKDF", key);
    crc32_ieee(&digest) as u64
}

/// `hash/crc32.ChecksumIEEE`.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

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

#[cfg(test)]
mod tests;
