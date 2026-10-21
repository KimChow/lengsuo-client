//! 排空预算的持有者：`BehaviorSeedLimitedDrainer`。
//!
//! 参考实现对应 Xray `common/drain/drainer.go` 的 `BehaviorSeedLimitedDrainer`
//! 及其 `AcknowledgeReceive` / `Drain` / `WithError` 三个方法。

use std::io::{self, Read};

use super::error::DrainError;
use super::go_rand::GoRand;

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
    /// the `int64` cast is part of the port and lives in [`super::BehaviorSeedSource`].
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
        state = super::os_entropy().max(1);
    }
    GLOBAL.store(super::splitmix64(state), Ordering::Relaxed);
    (super::splitmix64(state) >> 11) as usize % n
}
