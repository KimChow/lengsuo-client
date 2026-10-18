//! Adversarial verification of the LBST recovery-metadata codec.
//! Independent of tests/contract.rs; hand-computed bytes, exhaustive
//! mutations, fixed-seed fuzz. These are self-owned roundtrip/mutation
//! cases only — they do NOT prove interoperability with any other
//! implementation.

use lengsuo_browser_state::*;

const ENV: &str = "env-1";

fn snap(environment: &str, generation: u64, was_running: bool) -> Snapshot {
    Snapshot {
        environment: environment.into(),
        generation,
        was_running,
    }
}

/// Canonical encoding of snap(ENV, 7, true), built byte-by-byte here
/// without calling encode(), to independently verify the layout.
fn hand_canonical() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"LBST");
    v.push(1u8); // version
    v.push(5u8); // env length
    v.extend_from_slice(b"env-1");
    v.extend_from_slice(&7u64.to_be_bytes());
    v.push(1u8); // was_running = true
    v
}

#[test]
fn hand_written_big_endian_layout_matches_codec() {
    let hand = hand_canonical();
    assert_eq!(hand.len(), 4 + 1 + 1 + 5 + 8 + 1);
    assert_eq!(encode(&snap(ENV, 7, true)).unwrap(), hand);
    // Generation byte order is big-endian: MSB first.
    assert_eq!(&hand[11..19], &[0, 0, 0, 0, 0, 0, 0, 7]);
}

#[test]
fn generation_u64_max_is_big_endian_and_roundtrips() {
    let mut v = Vec::new();
    v.extend_from_slice(b"LBST\x01\x05env-1");
    v.extend_from_slice(&[0xFFu8; 8]); // u64::MAX, all-ones big-endian
    v.push(0);
    let got = decode(&v, ENV, 0).unwrap();
    assert_eq!(got.snapshot.generation, u64::MAX);
    assert!(!got.snapshot.was_running);
    assert_eq!(got.action, RecoveryAction::NeedsReconciliation);
    assert_eq!(encode(&snap(ENV, u64::MAX, true)).unwrap(), {
        let mut x = v.clone();
        *x.last_mut().unwrap() = 1;
        x
    });
}

#[test]
fn generation_big_endian_distinguishes_byte_orders() {
    // generation = 0x0102_0304_0506_0708 as 8 distinct MSB-first bytes.
    let mut v = Vec::new();
    v.extend_from_slice(b"LBST\x01\x05env-1");
    v.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    v.push(1);
    let got = decode(&v, ENV, 0).unwrap();
    assert_eq!(got.snapshot.generation, 0x0102_0304_0506_0708);
    // Same bytes read little-endian would be a different value: reject LE.
    assert_ne!(
        got.snapshot.generation,
        u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8])
    );
}

#[test]
fn env_length_one_and_64_roundtrip_65_fails() {
    for len in [1usize, 64] {
        let env = "a".repeat(len);
        let s = snap(&env, 3, true);
        let b = encode(&s).unwrap();
        assert_eq!(b[5] as usize, len);
        assert_eq!(decode(&b, &env, 0).unwrap().snapshot, s);
    }
    let env65 = "a".repeat(65);
    assert_eq!(encode(&snap(&env65, 3, false)), Err(StateError::Invalid));
    // A hand-made 65-byte env payload must be Invalid at decode, too.
    let mut v = Vec::new();
    v.extend_from_slice(b"LBST\x01\x41"); // env_len = 65
    v.extend_from_slice(env65.as_bytes());
    v.extend_from_slice(&1u64.to_be_bytes());
    v.push(0);
    assert_eq!(decode(&v, &env65, 0), Err(StateError::Invalid));
}

#[test]
fn non_ascii_env_rejected_at_encode_and_decode() {
    // "é" is two UTF-8 bytes (0xC3, 0xA9); must never be accepted.
    assert!(encode(&snap("é", 3, false)).is_err());
    let mut v = Vec::new();
    v.extend_from_slice(b"LBST\x01\x02");
    v.extend_from_slice("é".as_bytes());
    v.extend_from_slice(&1u64.to_be_bytes());
    v.push(0);
    assert_eq!(decode(&v, "é", 0), Err(StateError::Invalid));
    // Non-ASCII byte in env position with an ASCII caller env → Invalid,
    // not WrongEnvironment: shape is validated before binding.
    let mut v2 = hand_canonical();
    v2[7] = 0x80;
    assert_eq!(decode(&v2, ENV, 0), Err(StateError::Invalid));
    // Control bytes NUL/newline in env payload → Invalid.
    for bad in [0u8, b'\n', b'/', b'.', b' ', b'#'] {
        let mut v3 = hand_canonical();
        v3[6] = bad;
        assert_eq!(decode(&v3, ENV, 0), Err(StateError::Invalid));
    }
}

#[test]
fn every_prefix_of_canonical_is_rejected() {
    let b = hand_canonical();
    for n in 0..b.len() {
        assert!(decode(&b[..n], ENV, 0).is_err(), "prefix len {n} accepted");
    }
}

#[test]
fn every_trailing_extension_is_rejected() {
    let b = hand_canonical();
    for extra in [0u8, 1, 0xFF] {
        for n in 1..=4usize {
            let mut v = b.clone();
            v.extend(std::iter::repeat_n(extra, n));
            assert!(decode(&v, ENV, 0).is_err(), "{n} trailing {extra} accepted");
        }
    }
    // Over MAX_BYTES (79): 64-byte env canonical is 79; append until 80+.
    let env = "a".repeat(64);
    let mut big = encode(&snap(&env, 9, false)).unwrap();
    assert_eq!(big.len(), 79);
    big.push(0);
    assert!(decode(&big, &env, 0).is_err());
}

#[test]
fn all_version_and_flag_values_enumerated() {
    for version in 0u8..=255 {
        let mut v = hand_canonical();
        v[4] = version;
        if version == 1 {
            assert!(decode(&v, ENV, 0).is_ok());
        } else {
            assert_eq!(
                decode(&v, ENV, 0),
                Err(StateError::Invalid),
                "version {version}"
            );
        }
    }
    for flag in 0u8..=255 {
        let mut v = hand_canonical();
        let last = v.len() - 1;
        v[last] = flag;
        if flag <= 1 {
            let got = decode(&v, ENV, 0).unwrap();
            assert_eq!(got.snapshot.was_running, flag == 1);
        } else {
            assert_eq!(decode(&v, ENV, 0), Err(StateError::Invalid), "flag {flag}");
        }
    }
}

#[test]
fn every_single_byte_flip_still_never_panics_or_grants() {
    let b = hand_canonical();
    for i in 0..b.len() {
        for bit in 0..8 {
            let mut v = b.clone();
            v[i] ^= 1 << bit;
            let r = decode(&v, ENV, 0);
            if let Ok(got) = &r {
                // Generation/flag mutations can remain valid metadata.
                // Independently check their actual bytes, never grant authority.
                assert_eq!(got.snapshot.environment, ENV);
                assert_eq!(
                    got.snapshot.generation,
                    u64::from_be_bytes(v[11..19].try_into().unwrap())
                );
                assert_eq!(got.snapshot.was_running, v[19] == 1);
                assert_eq!(got.action, RecoveryAction::NeedsReconciliation);
            }
        }
    }
}

#[test]
fn generation_zero_rejected_whole_and_split() {
    // All-zero generation field.
    assert!(hand_canonical()[11..19].iter().any(|&x| x != 0));
    let mut v = Vec::new();
    v.extend_from_slice(b"LBST\x01\x05env-1");
    v.extend_from_slice(&0u64.to_be_bytes());
    v.push(1);
    assert_eq!(
        decode(&v, ENV, 0),
        Err(StateError::Invalid),
        "generation 0 must fail before stale floor"
    );
    assert_eq!(encode(&snap(ENV, 0, true)), Err(StateError::Invalid));
    // Zero with minimum_generation 0 must not pass either.
    assert_eq!(decode(&v, ENV, 0), Err(StateError::Invalid));
}

#[test]
fn cross_environment_and_stale_are_exact_variants() {
    let b = hand_canonical(); // generation 7
    assert_eq!(decode(&b, "env-2", 0), Err(StateError::WrongEnvironment));
    assert_eq!(decode(&b, "", 0), Err(StateError::WrongEnvironment));
    assert_eq!(decode(&b, "env-1x", 0), Err(StateError::WrongEnvironment));
    assert_eq!(decode(&b, ENV, 8), Err(StateError::Stale));
    assert_eq!(decode(&b, ENV, u64::MAX), Err(StateError::Stale));
    assert!(decode(&b, ENV, 7).is_ok());
    assert!(decode(&b, ENV, 6).is_ok());
    // Stale must be checked after the environment binding, not before:
    // a stale payload from another env is WrongEnvironment first.
    assert_eq!(
        decode(&b, "other-env", 100),
        Err(StateError::WrongEnvironment)
    );
    // Valid env bytes but caller requests same-string env of length 1..64 boundary.
    let env = "x";
    let e = encode(&snap(env, 5, false)).unwrap();
    assert_eq!(decode(&e, ENV, 0), Err(StateError::WrongEnvironment));
    assert!(decode(&e, env, 5).is_ok());
}

#[test]
fn was_running_true_never_grants_and_always_needs_reconciliation() {
    for gen in [1u64, 7, u64::MAX] {
        let b = encode(&snap(ENV, gen, true)).unwrap();
        let got = decode(&b, ENV, 0).unwrap();
        assert!(got.snapshot.was_running);
        assert_eq!(got.action, RecoveryAction::NeedsReconciliation);
    }
    // was_running=false must NOT flip to a granted/running action.
    let b = encode(&snap(ENV, 4, false)).unwrap();
    let got = decode(&b, ENV, 0).unwrap();
    assert!(!got.snapshot.was_running);
    assert_eq!(got.action, RecoveryAction::NeedsReconciliation);
    // There is exactly one action variant; nothing else is expressible.
    let all: [RecoveryAction; 1] = [RecoveryAction::NeedsReconciliation];
    assert_eq!(all[0], got.action);
}

/// Fixed-seed xorshift64*: deterministic, no external deps.
struct Xorshift64Star(u64);
impl Xorshift64Star {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
}

#[test]
fn fixed_seed_many_inputs_never_panic() {
    let mut rng = Xorshift64Star(0x9E37_79B9_85EB_51EB); // fixed seed
    let canonical = hand_canonical();
    for case in 0..4096u32 {
        let mut v: Vec<u8> = Vec::new();
        match case % 4 {
            0 => {
                let len = (rng.next() % 90) as usize;
                for _ in 0..len {
                    v.push(rng.byte());
                }
            }
            1 => {
                v = canonical.clone();
                let n = 1 + (rng.next() % 4) as usize;
                for _ in 0..n {
                    let i = (rng.next() % v.len() as u64) as usize;
                    v[i] = rng.byte();
                }
            }
            2 => {
                v = canonical.clone();
                let cut = (rng.next() % v.len() as u64) as usize;
                v.truncate(cut);
            }
            _ => {
                v = canonical.clone();
                let tail = (rng.next() % 8) as u8;
                v.push(tail);
            }
        }
        let envs = [ENV, "", "env-2", &"a".repeat(64), "x"];
        for e in envs {
            // Must never panic; every outcome is one of the declared results.
            let r = std::panic::catch_unwind(|| decode(&v, e, 0));
            let res = r.unwrap_or_else(|_| panic!("decode panicked, case {case}"));
            match res {
                Ok(got) => {
                    assert_eq!(got.action, RecoveryAction::NeedsReconciliation);
                    assert_eq!(got.snapshot.environment.as_str(), e);
                }
                Err(StateError::Invalid)
                | Err(StateError::WrongEnvironment)
                | Err(StateError::Stale) => {}
            }
        }
    }
}

// Test-only free function: integration tests cannot add inherent impls.
fn environment_of_via_decode(bytes: &[u8], env: &str) -> String {
    decode(bytes, env, 0)
        .map(|r| r.snapshot.environment)
        .unwrap_or_default()
}

#[test]
fn decoded_snapshot_environment_is_the_bound_caller_env() {
    let b = hand_canonical();
    let got = decode(&b, ENV, 0).unwrap();
    assert_eq!(environment_of_via_decode(&b, ENV), ENV.to_string());
    assert_eq!(got.snapshot.environment, ENV);
}
