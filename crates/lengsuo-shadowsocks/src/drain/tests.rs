//! `drain` 的单元测试。
//!
//! 关键是 `go_rand` 的**黄金向量**：数值由 Go 1.22.2
//! `rand.New(rand.NewSource(seed)).Intn(n)` 直接产出，用来钉住与参考
//! `dice.NewDeterministicDice` 的逐位一致，而不是自家 roundtrip。

use std::io::Cursor;

use super::seed::crc32_ieee;
use super::*;

#[test]
fn go_rand_matches_reference_vectors() {
    // Golden values produced by Go 1.22.2 `rand.New(rand.NewSource(seed)).Intn(n)`.
    let cases: &[(i64, [usize; 6])] = &[
        (0, [402, 628, 159, 1794, 1847, 790]),
        (1, [1801, 827, 891, 3131, 2221, 2654]),
        (42, [889, 385, 340, 3152, 2697, 3251]),
        (89482311, [402, 628, 159, 1794, 1847, 790]),
        (1234567890123, [1373, 2790, 2154, 22, 3048, 1380]),
        (0xdeadbeef, [3257, 1595, 3037, 3260, 1421, 462]),
    ];
    for (seed, want) in cases {
        let mut r = GoRand::new(*seed);
        for (i, w) in want.iter().enumerate() {
            assert_eq!(r.roll(3266), *w, "seed {seed} draw {i}");
        }
    }
}

#[test]
fn go_rand_roll_64_matches_reference() {
    // A *fresh* `NewSource(seed)`, six `Intn(64)` draws. 64 is a power of
    // two, so this exercises `Int31n`'s mask branch rather than the
    // rejection loop.
    let cases: &[(i64, [usize; 6])] = &[
        (0, [58, 18, 57, 42, 59, 32]),
        (1, [33, 15, 7, 59, 1, 6]),
        (42, [49, 11, 4, 62, 31, 33]),
        (0xdeadbeef, [25, 55, 63, 36, 61, 38]),
    ];
    for (seed, want) in cases {
        let mut r = GoRand::new(*seed);
        for (i, w) in want.iter().enumerate() {
            assert_eq!(r.roll(64), *w, "seed {seed} draw {i}");
        }
    }
}

#[test]
fn roll_of_one_is_zero_without_consuming_entropy() {
    let mut a = GoRand::new(7);
    let mut b = GoRand::new(7);
    assert_eq!(a.roll(1), 0);
    assert_eq!(a.roll(1000), b.roll(1000));
}

#[test]
fn seed_is_stable_for_a_deployment() {
    let mut a = GoRand::new(42);
    let mut b = GoRand::new(42);
    for n in [2usize, 7, 3266, 64, 1000] {
        assert_eq!(a.roll(n), b.roll(n), "roll({n}) must be reproducible");
    }
}

#[test]
fn drain_budget_stays_within_reference_bounds() {
    for seed in [0i64, 1, 42, -7, i64::MIN, i64::MAX] {
        let d = BehaviorSeedLimitedDrainer::new_shadowsocks(seed);
        assert!(d.drain_size >= DRAIN_FOUNDATION as i64, "seed {seed}");
        assert!(
            d.drain_size < (DRAIN_FOUNDATION + MAX_BASE_DRAIN_SIZE + MAX_RAND_DRAIN) as i64,
            "seed {seed}"
        );
    }
}

#[test]
fn drain_budget_is_a_fixed_function_of_the_seed() {
    // The base component must be reproducible; the extra roll is global, so
    // only the deterministic half of the sum is pinned here.
    for seed in [0i64, 1, 42, 1234567890123] {
        let a = BehaviorSeedLimitedDrainer::new_shadowsocks(seed);
        let b = BehaviorSeedLimitedDrainer::new_shadowsocks(seed);
        assert!(
            (a.drain_size - b.drain_size).abs() < MAX_RAND_DRAIN as i64,
            "seed {seed}"
        );
    }
}

#[test]
fn acknowledge_receive_credits_budget() {
    let mut d = BehaviorSeedLimitedDrainer { drain_size: 100 };
    d.acknowledge_receive(32);
    assert_eq!(d.drain_size, 68);
    d.acknowledge_receive(1000);
    assert_eq!(d.drain_size, -932);
}

#[test]
fn drain_noop_when_budget_exhausted() {
    let d = BehaviorSeedLimitedDrainer { drain_size: 0 };
    let mut src = Cursor::new(vec![7u8; 128]);
    assert!(d.drain(&mut src).is_ok());
    assert_eq!(src.position(), 0, "must not consume bytes once satisfied");
}

#[test]
fn drain_reports_drained_when_peer_supplies_budget() {
    let d = BehaviorSeedLimitedDrainer { drain_size: 64 };
    let mut src = Cursor::new(vec![7u8; 64]);
    assert!(matches!(d.drain(&mut src), Err(DrainError::Drained)));
    assert_eq!(src.position(), 64);
}

#[test]
fn drain_reports_unable_when_peer_goes_away() {
    let d = BehaviorSeedLimitedDrainer { drain_size: 1024 };
    let mut src = Cursor::new(vec![7u8; 10]);
    assert!(matches!(
        d.drain(&mut src),
        Err(DrainError::UnableToDrain(_))
    ));
}

#[test]
fn with_error_returns_origin_when_drain_satisfied() {
    let d = BehaviorSeedLimitedDrainer { drain_size: 0 };
    let mut src = Cursor::new(vec![7u8; 8]);
    let e = d.with_error(&mut src, DrainError::Handshake(HandshakeError::NoUser));
    assert!(matches!(e, DrainError::Handshake(HandshakeError::NoUser)));
}

#[test]
fn with_error_nests_drain_failure() {
    let d = BehaviorSeedLimitedDrainer { drain_size: 512 };
    let mut src = Cursor::new(vec![7u8; 512]);
    let e = d.with_error(&mut src, DrainError::Handshake(HandshakeError::ShortHeader));
    match e {
        DrainError::Nested { drain, origin } => {
            assert!(matches!(*drain, DrainError::Drained));
            assert!(matches!(
                *origin,
                DrainError::Handshake(HandshakeError::ShortHeader)
            ));
        }
        other => panic!("expected nesting, got {other}"),
    }
}

#[test]
fn slow_read_penalty_flags_zero_byte_idlers() {
    let d = BehaviorSeedLimitedDrainer { drain_size: 10 };
    assert!(!d.slow_read_penalty(0, std::time::Duration::from_millis(10)));
    assert!(d.slow_read_penalty(0, std::time::Duration::from_millis(600)));
    assert!(d.slow_read_penalty(1, std::time::Duration::from_secs(1)));
    assert!(!d.slow_read_penalty(1 << 20, std::time::Duration::from_millis(1)));
}

#[test]
fn behavior_seed_is_latched_and_never_zero() {
    let mut s = BehaviorSeedSource::new();
    assert!(!s.is_fused());
    let first = s.get_behavior_seed();
    assert_ne!(first, 0, "a zero seed would disable the mitigation");
    assert!(s.is_fused());
    assert_eq!(
        s.get_behavior_seed(),
        first,
        "seed must latch per deployment"
    );
    assert_eq!(s.get_behavior_seed_i64() as u64, first);
}

#[test]
fn response_behavior_seed_is_stable_per_key() {
    let k1 = [0x11u8; 32];
    let k2 = [0x22u8; 32];
    assert_eq!(response_behavior_seed(&k1), response_behavior_seed(&k1));
    assert_ne!(response_behavior_seed(&k1), response_behavior_seed(&k2));
}

#[test]
fn crc32_ieee_matches_known_vectors() {
    assert_eq!(crc32_ieee(b""), 0);
    assert_eq!(crc32_ieee(b"123456789"), 0xcbf4_3926);
}
