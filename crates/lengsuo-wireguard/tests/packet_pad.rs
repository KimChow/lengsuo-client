//! IP 包填充 / 分片 / 重组矩阵。
//!
//! 期望值逐字节对齐 wireguard-go `calculatePaddingSize`
//! （`device/send.go:419`），常数 `PaddingMultiple = 16`。

use lengsuo_wireguard::packet_pad::{
    calculate_padding_size, fragment, pad, reassemble, unpad, PadError, MAX_IP_PACKET,
    PADDING_MULTIPLE,
};

const MTU: usize = 1280;

#[test]
fn padding_multiple_is_16() {
    assert_eq!(PADDING_MULTIPLE, 16);
}

#[test]
fn calc_padding_boundary_matrix() {
    // (packet_size, mtu, expected) —— 手工按 Go 公式推得。
    let cases = [
        (0usize, MTU, 0usize),
        (1, MTU, 15),
        (15, MTU, 1),
        (16, MTU, 0),
        (17, MTU, 15),
        (31, MTU, 1),
        (32, MTU, 0),
        (1279, MTU, 1),  // round_up(1279)=1280
        (1280, MTU, 0),  // 恰好整 MTU
        (1281, MTU, 15), // 1281%1280=1 → round_up=16 → 15
        (2559, MTU, 1),  // 2559%1280=1279 → round_up=1280 → 1
        (2560, MTU, 0),  // 2560%1280=0
    ];
    for (size, mtu, expected) in cases {
        assert_eq!(
            calculate_padding_size(size, mtu),
            expected,
            "size={size} mtu={mtu}"
        );
    }
}

#[test]
fn calc_padding_mtu_zero_means_no_cap() {
    assert_eq!(calculate_padding_size(0, 0), 0);
    assert_eq!(calculate_padding_size(1, 0), 15);
    assert_eq!(calculate_padding_size(16, 0), 0);
    assert_eq!(calculate_padding_size(17, 0), 15);
    assert_eq!(calculate_padding_size(4097, 0), 15);
}

#[test]
fn calc_padding_is_always_bounded_by_mtu() {
    // 参考公式的固有性质：填充量恒 < 16，且封顶后 lastUnit+padding <= mtu。
    for size in 1..=MTU * 3 {
        let p = calculate_padding_size(size, MTU);
        assert!(p < 16, "padding {p} for size={size} exceeds multiple");
        let last = if size > MTU { size % MTU } else { size };
        assert!(
            last + p <= MTU,
            "lastUnit({last}) + padding({p}) exceeds mtu for size={size}"
        );
    }
}

#[test]
fn pad_produces_zero_bytes_and_multiple_of_16() {
    for size in [0usize, 1, 15, 16, 17, MTU - 1, MTU] {
        let input = vec![0xabu8; size];
        let out = pad(&input, MTU);
        assert_eq!(out.len(), size + calculate_padding_size(size, MTU));
        if size <= MTU {
            assert_eq!(out.len() % 16, 0, "size={size}");
        }
        // 填充字节必须是 0，原载荷不变。
        assert_eq!(&out[..size], &input[..]);
        assert!(out[size..].iter().all(|&b| b == 0));
    }
}

#[test]
fn pad_byte_exact_for_size_17() {
    let input: Vec<u8> = (0..17).collect();
    let out = pad(&input, MTU);
    assert_eq!(out.len(), 32);
    let mut expected: Vec<u8> = (0..17).collect();
    expected.extend_from_slice(&[0u8; 15]);
    assert_eq!(out, expected);
}

#[test]
fn pad_byte_exact_for_size_16_unchanged() {
    let input: Vec<u8> = (0..16).collect();
    let out = pad(&input, MTU);
    assert_eq!(out, input); // 已是 16 倍数，无填充
}

#[test]
fn pad_byte_exact_for_size_15_gets_one_zero() {
    let input: Vec<u8> = (0..15).collect();
    let out = pad(&input, MTU);
    assert_eq!(out.len(), 16);
    assert_eq!(out[15], 0);
    assert_eq!(&out[..15], &input[..]);
}

#[test]
fn pad_size_zero_stays_empty() {
    let out = pad(&[], MTU);
    assert!(out.is_empty());
}

#[test]
fn unpad_strips_padding_by_length_field() {
    let payload = vec![0x11u8; 17];
    let padded = pad(&payload, MTU);
    assert_eq!(padded.len(), 32);
    let recovered = unpad(&padded, payload.len()).unwrap();
    assert_eq!(recovered, &payload[..]);
}

#[test]
fn unpad_rejects_length_field_zero() {
    let padded = pad(&[1, 2, 3], MTU);
    assert!(unpad(&padded, 0).is_none());
}

#[test]
fn unpad_rejects_length_beyond_buffer() {
    let padded = pad(&[1, 2, 3], MTU);
    assert!(unpad(&padded, padded.len() + 1).is_none());
}

#[test]
fn unpad_rejects_nonzero_trailing_padding() {
    let mut padded = pad(&[1, 2, 3], MTU);
    let last = padded.len() - 1;
    padded[last] = 0xff; // 破坏填充
    assert!(unpad(&padded, 3).is_none());
}

#[test]
fn fragment_splits_by_mtu() {
    let packet = vec![0u8; MTU * 2 + 7];
    let frags = fragment(&packet, MTU).unwrap();
    assert_eq!(frags.len(), 3);
    assert_eq!(frags[0].len(), MTU);
    assert_eq!(frags[1].len(), MTU);
    assert_eq!(frags[2].len(), 7);
}

#[test]
fn fragment_exactly_mtu_is_single_fragment() {
    let packet = vec![0u8; MTU];
    let frags = fragment(&packet, MTU).unwrap();
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].len(), MTU);
}

#[test]
fn fragment_rejects_empty_packet_and_zero_mtu() {
    assert_eq!(fragment(&[], MTU), Err(PadError::EmptyPacket));
    assert_eq!(fragment(&[1, 2, 3], 0), Err(PadError::InvalidMtu));
}

#[test]
fn fragment_rejects_oversized_packet() {
    let packet = vec![0u8; MAX_IP_PACKET + 1];
    assert_eq!(fragment(&packet, MTU), Err(PadError::PacketTooLarge));
}

#[test]
fn reassemble_roundtrips_fragments() {
    let packet: Vec<u8> = (0..1000).map(|i| (i % 251) as u8).collect();
    let frags = fragment(&packet, 128).unwrap();
    let joined = reassemble(&frags).unwrap();
    assert_eq!(joined, packet);
}

#[test]
fn reassemble_rejects_empty_and_oversized() {
    assert_eq!(reassemble(&[]), Err(PadError::EmptyPacket));
    let a = vec![0u8; MAX_IP_PACKET];
    let b = vec![0u8; 1];
    assert_eq!(reassemble(&[&a, &b]), Err(PadError::PacketTooLarge));
}

#[test]
fn reassemble_rejects_empty_fragment() {
    let empty: &[u8] = &[];
    assert_eq!(
        reassemble(&[&[1, 2][..], empty]),
        Err(PadError::EmptyPacket)
    );
}
