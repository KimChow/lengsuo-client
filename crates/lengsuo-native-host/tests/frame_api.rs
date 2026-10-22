//! 管道帧编解码的 API 级用例。
//!
//! 覆盖派卡要求的重点：
//! - 帧头恰好 4 字节，长度前缀是**本机字节序**；
//! - 帧头任一字节位置被改 ⇒ **不得**还原出原载荷；
//! - 字节序写反 ⇒ **解不出来**（专门的用例）；
//! - 声明长度差一（多一 / 少一）⇒ 不交付、不凑帧；
//! - 分片：1 字节一段、2 字节一段、半个帧头、整帧 + 半帧；
//! - 多帧：一次喂 2 帧 + 半帧 ⇒ 2 帧出、半帧留；
//! - 上限：编码侧超限报错（不截断）、解码侧长度头超限报错（不巨量分配）。

use lengsuo_native_host::frame::{
    decode_frame, encode_frame, FrameDecoder, FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD_LEN,
};
use lengsuo_native_host::FrameError;

/// 按**本机字节序**写一个长度头。
fn native_header(len: u32) -> [u8; FRAME_HEADER_LEN] {
    len.to_ne_bytes()
}

/// 按**相反于本机**的字节序写一个长度头。
fn opposite_header(len: u32) -> [u8; FRAME_HEADER_LEN] {
    if cfg!(target_endian = "little") {
        len.to_be_bytes()
    } else {
        len.to_le_bytes()
    }
}

/// 用本机字节序拼一帧。
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = native_header(payload.len() as u32).to_vec();
    out.extend_from_slice(payload);
    out
}

// ---------------------------------------------------------------- 帧头形状

#[test]
fn header_is_exactly_four_bytes() {
    assert_eq!(FRAME_HEADER_LEN, 4);

    // 0..=3 字节都不足以切帧：都报 incomplete，且 `needed` 恒为 4。
    for available in 0..FRAME_HEADER_LEN {
        let err = decode_frame(&vec![0u8; available]).expect_err("帧头不全必须报错");
        assert_eq!(
            err,
            FrameError::Incomplete {
                needed: FRAME_HEADER_LEN,
                available
            }
        );
    }

    // 恰好 4 字节（声明长度 0）就够切出一个空帧。
    let empty_frame = native_header(0);
    let (payload, consumed) = decode_frame(&empty_frame).expect("空帧必须能切");
    assert!(payload.is_empty());
    assert_eq!(consumed, FRAME_HEADER_LEN);
}

#[test]
fn length_prefix_is_native_endian() {
    // 长度 1 的本机字节序编码必须被读成 1。
    let encoded = encode_frame(b"z").expect("编码");
    assert_eq!(&encoded[..FRAME_HEADER_LEN], &native_header(1)[..]);

    let (payload, consumed) = decode_frame(&encoded).expect("解码");
    assert_eq!(payload, b"z");
    assert_eq!(consumed, 5);
}

#[test]
fn byte_swapped_header_does_not_decode() {
    // ⭐ 派卡点名：把期望头写成「反字节序」再解，应当**解不出来**。
    // 载荷 2 字节；反序头无论在小端还是大端主机上，
    // 按本机读出来都是 0x0200_0000 = 33,554,432 > 1 MiB。
    let mut swapped = Vec::from(opposite_header(2));
    swapped.extend_from_slice(&[0x7b, 0x7d]);

    let err = decode_frame(&swapped).expect_err("反字节序的帧头必须解不出来");
    assert_eq!(
        err,
        FrameError::FrameTooLong {
            declared: 0x0200_0000,
            limit: MAX_FRAME_PAYLOAD_LEN,
        }
    );

    // 反过来核对：用本机字节序写的同一帧必须解得出来。
    let ok = frame(&[0x7b, 0x7d]);
    let (payload, _) = decode_frame(&ok).expect("本机字节序必须解得出来");
    assert_eq!(payload, &[0x7b, 0x7d]);
}

#[test]
fn mutating_any_header_byte_cannot_yield_the_original_payload() {
    let payload = b"abcd";
    let original = frame(payload);

    for (offset, byte) in original.iter().take(FRAME_HEADER_LEN).enumerate() {
        let mut mutated = original.clone();
        // 翻转该字节的最低位：长度必然与原值不同。
        mutated[offset] ^= 0x01;
        assert_ne!(byte, &mutated[offset]);

        // 头部被改后仍可能「切成」某个帧（例如长度改小），
        // 但绝不能还原出原载荷；报错同样算「解不出来」。
        if let Ok((decoded, _)) = decode_frame(&mutated) {
            assert_ne!(
                decoded, payload,
                "帧头第 {} 字节被改后竟然还原出了原载荷",
                offset
            );
        }
    }
}

#[test]
fn declared_length_off_by_one_is_not_papered_over() {
    // 少一：头说 1，实际给了 2 字节 ⇒ 只交付 1 字节，剩 1 字节留着。
    let mut short = Vec::from(native_header(1));
    short.extend_from_slice(&[0x7b, 0x7d]);
    let (payload, consumed) = decode_frame(&short).expect("头说 1 就切 1");
    assert_eq!(payload, &[0x7b]);
    assert_eq!(consumed, 5);
    assert_eq!(short.len() - consumed, 1, "剩余 1 字节必须留给调用方");

    // 多一：头说 3，实际只有 2 字节载荷 ⇒ 等更多数据，不按实际长度凑帧。
    let mut long = Vec::from(native_header(3));
    long.extend_from_slice(&[0x7b, 0x7d]);
    let err = decode_frame(&long).expect_err("载荷不够必须报错");
    assert_eq!(
        err,
        FrameError::Incomplete {
            needed: 7,
            available: 6
        }
    );
}

// ---------------------------------------------------------------- 分片

#[test]
fn decoder_handles_one_byte_at_a_time() {
    let payload = b"{\"type\":0}";
    let whole = frame(payload);

    let mut decoder = FrameDecoder::new();
    for (index, byte) in whole.iter().enumerate() {
        let frames = decoder.feed(&[*byte]).expect("逐字节喂入不应报错");
        if index + 1 == whole.len() {
            assert_eq!(frames, vec![payload.to_vec()], "最后一字节应交付整帧");
            assert_eq!(decoder.pending(), 0);
        } else {
            assert!(frames.is_empty(), "第 {} 字节还不该交付", index);
            assert_eq!(decoder.pending(), index + 1);
        }
    }
}

#[test]
fn decoder_handles_two_byte_chunks() {
    let payload = b"hello";
    let whole = frame(payload);

    let mut decoder = FrameDecoder::new();
    let mut got = Vec::new();
    for chunk in whole.chunks(2) {
        got.extend(decoder.feed(chunk).expect("两字节一段不应报错"));
    }
    assert_eq!(got, vec![payload.to_vec()]);
    assert_eq!(decoder.pending(), 0);
}

#[test]
fn decoder_handles_half_a_header() {
    let payload = b"xy";
    let whole = frame(payload);

    let mut decoder = FrameDecoder::new();
    assert!(decoder.feed(&whole[..2]).expect("半个头").is_empty());
    assert_eq!(decoder.pending(), 2);

    let frames = decoder.feed(&whole[2..]).expect("剩下的部分");
    assert_eq!(frames, vec![payload.to_vec()]);
    assert_eq!(decoder.pending(), 0);
}

#[test]
fn decoder_keeps_half_frame_after_whole_frames() {
    // 整帧 + 半帧。
    let payload = b"ok";
    let whole = frame(payload);

    let mut feed = whole.clone();
    feed.extend_from_slice(&whole[..3]);

    let mut decoder = FrameDecoder::new();
    let frames = decoder.feed(&feed).expect("整帧 + 半帧");
    assert_eq!(frames, vec![payload.to_vec()]);
    assert_eq!(decoder.pending(), 3, "半帧必须留在缓冲里");

    // 补齐剩下 3 字节 ⇒ 交付第二帧。
    let frames = decoder.feed(&whole[3..]).expect("补齐");
    assert_eq!(frames, vec![payload.to_vec()]);
    assert_eq!(decoder.pending(), 0);
}

#[test]
fn decoder_returns_all_complete_frames_from_a_single_feed() {
    // 一次喂 2 整帧 + 半帧 ⇒ 取出 2 帧、剩半帧。
    let whole = frame(b"{}");
    let mut feed = Vec::new();
    feed.extend_from_slice(&whole);
    feed.extend_from_slice(&whole);
    feed.extend_from_slice(&whole[..2]);

    let mut decoder = FrameDecoder::new();
    let frames = decoder.feed(&feed).expect("多帧粘包是常态");
    assert_eq!(frames, vec![b"{}".to_vec(), b"{}".to_vec()]);
    assert_eq!(decoder.pending(), 2);
}

// ---------------------------------------------------------------- 上限

#[test]
fn encoding_over_limit_errors_instead_of_truncating() {
    let payload = vec![0u8; MAX_FRAME_PAYLOAD_LEN + 1];
    let err = encode_frame(&payload).expect_err("超限必须报错");
    assert_eq!(
        err,
        FrameError::PayloadTooLong {
            declared: MAX_FRAME_PAYLOAD_LEN + 1,
            limit: MAX_FRAME_PAYLOAD_LEN,
        }
    );
}

#[test]
fn encoding_exactly_at_limit_is_accepted() {
    let payload = vec![0x5au8; MAX_FRAME_PAYLOAD_LEN];
    let encoded = encode_frame(&payload).expect("恰好 1 MiB 必须合法");
    assert_eq!(encoded.len(), FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD_LEN);
    assert_eq!(&encoded[..FRAME_HEADER_LEN], &native_header(1_048_576)[..]);

    // 解回来必须还是整整 1 MiB。
    let (decoded, consumed) = decode_frame(&encoded).expect("恰好 1 MiB 必须能解");
    assert_eq!(decoded.len(), MAX_FRAME_PAYLOAD_LEN);
    assert_eq!(consumed, encoded.len());
}

#[test]
fn decoding_over_limit_header_errors_without_allocating() {
    // 只有 4 字节长度头，声明 1 MiB + 1 ⇒ 立刻报错，绝不按它申请内存。
    let header = native_header((MAX_FRAME_PAYLOAD_LEN + 1) as u32);
    let err = decode_frame(&header).expect_err("超限长度头必须报错");
    assert_eq!(
        err,
        FrameError::FrameTooLong {
            declared: (MAX_FRAME_PAYLOAD_LEN + 1) as u64,
            limit: MAX_FRAME_PAYLOAD_LEN,
        }
    );

    // u32::MAX 同理。
    let err = decode_frame(&native_header(u32::MAX)).expect_err("u32::MAX 必须报错");
    assert!(matches!(
        err,
        FrameError::FrameTooLong {
            declared: 4_294_967_295,
            ..
        }
    ));
}

#[test]
fn decoder_propagates_limit_error_and_keeps_its_buffer() {
    let header = native_header((MAX_FRAME_PAYLOAD_LEN + 10) as u32);
    let mut decoder = FrameDecoder::new();

    let err = decoder
        .feed(&header)
        .expect_err("超限长度头必须让 feed 失败");
    assert!(matches!(err, FrameError::FrameTooLong { .. }));
    // 坏数据不算帧，也不被悄悄丢掉。
    assert_eq!(decoder.pending(), FRAME_HEADER_LEN);
}

// ---------------------------------------------------------------- 空载荷

#[test]
fn empty_payload_roundtrips() {
    let encoded = encode_frame(&[]).expect("空载荷合法");
    assert_eq!(encoded, vec![0, 0, 0, 0]);
    let (payload, consumed) = decode_frame(&encoded).expect("空帧可解");
    assert!(payload.is_empty());
    assert_eq!(consumed, 4);
}
