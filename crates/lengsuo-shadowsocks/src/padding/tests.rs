//! `padding` 的单元测试。
//!
//! 覆盖 flags 高半字节的往返、编解码的 fail-closed 边界，以及策略的
//! 可复现性与随机性。

use std::io;

use super::policy::random_bytes;
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
