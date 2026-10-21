//! 行为种子（behavior seed）的来源与派生。
//!
//! 种子必须是**部署期固定**的：它由预共享密钥派生，认证通过的字节会被退回
//! 预算（[`super::BehaviorSeedLimitedDrainer::acknowledge_receive`]），于是错口令
//! 与对口令付出同样的代价，探针无法据此区分。
//!
//! 参考实现对应 `proxy/shadowsocks/validator.go` 的 `Validator.GetBehaviorSeed`
//! 与 `Add(user)`，以及 `ReadTCPResponse` 里的 `SSBSKDF` 派生。

use super::{os_entropy, splitmix64};

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
pub(crate) fn crc32_ieee(data: &[u8]) -> u32 {
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
