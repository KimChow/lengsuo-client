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
//!
//! 模块按职责拆成子文件：排空预算在 [`drainer`]，错误类型在 [`error`]，
//! 种子派生在 [`seed`]，进程级随机源在 [`random`]，Go `math/rand` 的逐位移植
//! 在 [`go_rand`]，常量表在 [`rng_cooked`]。对外的公开路径保持不变。

mod drainer;
mod error;
pub mod go_rand;
mod random;
mod rng_cooked;
mod seed;

pub use drainer::{
    BehaviorSeedLimitedDrainer, DRAIN_FOUNDATION, MAX_BASE_DRAIN_SIZE, MAX_RAND_DRAIN, SALT_LEN,
    SLOW_READ_GRACE, SLOW_READ_MIN_BYTES_PER_SEC,
};
pub use error::{DrainError, HandshakeError};
pub use go_rand::GoRand;
pub use seed::{response_behavior_seed, BehaviorSeedSource};

pub(crate) use random::{os_entropy, splitmix64};

#[cfg(test)]
mod tests;
