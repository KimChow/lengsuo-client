//! Bit-exact port of Go's `math/rand` source (the Go 1 `rngSource`), which
//! backs `dice.NewDeterministicDice` in the reference.
//!
//! This exists because the drain budget must be *reproducible* for a given
//! deployment seed while still looking random to a prober. A home-grown PRNG
//! would satisfy the first property but silently diverge from the reference the
//! moment either side changes, so we port the generator instead.
//!
//! Layout mirrors `rng.go`: a 607-entry feedback register with tap 273, seeded
//! by the `seedrand` LCG XOR-ed with the `rngCooked` table.

use super::rng_cooked::RNG_COOKED;

const RNG_LEN: usize = 607;
const RNG_TAP: usize = 273;
const RNG_MASK: i64 = i64::MAX;
const INT32_MAX: i64 = (1 << 31) - 1;

/// Port of `rngSource`.
///
/// The reference uses `int64` words; Go relies on `int64` wrap-around in the
/// feedback sum, so every add here is `wrapping_add`.
#[derive(Debug, Clone)]
pub struct GoRand {
    tap: usize,
    feed: usize,
    vec: [i64; RNG_LEN],
}

impl GoRand {
    /// Port of `rand.NewSource(seed)` → `rngSource.Seed(seed)`.
    pub fn new(seed: i64) -> Self {
        let mut r = Self {
            tap: 0,
            feed: RNG_LEN - RNG_TAP,
            vec: [0; RNG_LEN],
        };
        r.seed(seed);
        r
    }

    /// Port of `(*rngSource).Seed`.
    fn seed(&mut self, seed: i64) {
        self.tap = 0;
        self.feed = RNG_LEN - RNG_TAP;

        let mut seed = seed % INT32_MAX;
        if seed < 0 {
            seed += INT32_MAX;
        }
        if seed == 0 {
            seed = 89482311;
        }

        let mut x = seed as i32;
        for i in -20i64..RNG_LEN as i64 {
            x = seedrand(x);
            if i >= 0 {
                let mut u = (x as i64) << 40;
                x = seedrand(x);
                u ^= (x as i64) << 20;
                x = seedrand(x);
                u ^= x as i64;
                u ^= RNG_COOKED[i as usize];
                self.vec[i as usize] = u;
            }
        }
    }

    /// Port of `(*rngSource).Uint64`.
    fn next_u64(&mut self) -> u64 {
        self.tap = if self.tap == 0 {
            RNG_LEN - 1
        } else {
            self.tap - 1
        };
        self.feed = if self.feed == 0 {
            RNG_LEN - 1
        } else {
            self.feed - 1
        };

        let x = self.vec[self.feed].wrapping_add(self.vec[self.tap]);
        self.vec[self.feed] = x;
        x as u64
    }

    /// Port of `(*rngSource).Int63`: `int64(Uint64() & rngMask)`.
    fn int63(&mut self) -> i64 {
        (self.next_u64() & RNG_MASK as u64) as i64
    }

    /// Port of `(*Rand).Int31`: `int32(Int63() >> 32)`.
    fn int31(&mut self) -> i32 {
        (self.int63() >> 32) as i32
    }

    /// Port of `(*Rand).Int31n` (and therefore `Intn` for `n < 2^31`).
    pub fn intn(&mut self, n: u64) -> u64 {
        assert!(n > 0, "invalid argument to Intn");
        let n32 = n as i32;
        if n32 & (n32 - 1) == 0 {
            // n is a power of two, can mask.
            return (self.int31() & (n32 - 1)) as u32 as u64;
        }
        let max = (1i64 << 31) - 1 - (1i64 << 31) % n as i64;
        let mut v = self.int31() as i64;
        while v > max {
            v = self.int31() as i64;
        }
        (v % n as i64) as u64
    }

    /// Port of `DeterministicDice.Roll`: `0` when `n == 1`, else `Intn(n)`.
    pub fn roll(&mut self, n: usize) -> usize {
        if n == 1 {
            return 0;
        }
        self.intn(n as u64) as usize
    }
}

/// Port of `seedrand(x)`: a Lehmer LCG in `int32` arithmetic.
fn seedrand(x: i32) -> i32 {
    const A: i32 = 48271;
    const Q: i32 = 44488;
    const R: i32 = 3399;

    let hi = x / Q;
    let lo = x % Q;
    let mut x = A.wrapping_mul(lo).wrapping_sub(R.wrapping_mul(hi));
    if x < 0 {
        // Go: `x += int32max` where `int32max = (1<<31) - 1`, all in `int32`.
        // The addition itself can wrap in Go's two's-complement `int32`, and the
        // reference relies on that: using `(1<<31)` here (as a naive "add 2^31"
        // reading suggests) shifts the whole stream by one step.
        x = x.wrapping_add(INT32_MAX as i32);
    }
    x
}
