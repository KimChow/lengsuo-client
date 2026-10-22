//! 管道帧的固定向量回放：合法帧 / 分片 / 非法帧 / 两个上限。

use crate::support::{
    assert_has_entries, entries, entry, from_hex, header_to_native, str_field, to_native, u64_field,
};
use lengsuo_native_host::error::FrameError;
use lengsuo_native_host::frame::{decode_frame, encode_frame, FrameDecoder, FRAME_HEADER_LEN};

// ---------------------------------------------------------------- 合法帧回放

#[test]
fn legal_frames_reproduce_expected_bytes() {
    for item in entries("legal_frames") {
        let name = str_field(item, "name");
        let payload = from_hex(&str_field(item, "payload_hex"));
        let expected_prefix = from_hex(&str_field(item, "length_prefix_hex"));
        let expected_frame = from_hex(&str_field(item, "frame_hex"));

        // 向量自身必须自洽。
        assert_eq!(
            payload.len(),
            u64_field(item, "payload_len") as usize,
            "{}：payload 长度与 payload_len 不符",
            name
        );
        assert_eq!(
            expected_prefix.len(),
            FRAME_HEADER_LEN,
            "{}：长度前缀必须是 4 字节",
            name
        );
        assert_eq!(
            expected_frame.len(),
            u64_field(item, "frame_len") as usize,
            "{}：frame_hex 长度与 frame_len 不符",
            name
        );
        assert_eq!(
            expected_frame.len(),
            FRAME_HEADER_LEN + payload.len(),
            "{}：整帧长度必须是 4 + len",
            name
        );
        assert_eq!(
            &expected_frame[..FRAME_HEADER_LEN],
            &expected_prefix[..],
            "{}：frame_hex 的头部必须与 length_prefix_hex 一致",
            name
        );

        // ⭐ 核心断言：编码结果与**独立手算的期望字节**逐字节相同。
        let encoded = encode_frame(&payload).expect("合法向量必须能编码");
        assert_eq!(
            to_native(&expected_frame),
            encoded,
            "{}：编码结果与向量期望字节不一致",
            name
        );

        // 解码必须还原出同样的载荷。
        let (decoded, consumed) = decode_frame(&encoded).expect("合法向量必须能解码");
        assert_eq!(decoded, payload.as_slice(), "{}：解出的载荷不符", name);
        assert_eq!(consumed, encoded.len(), "{}：已消费字节数不对", name);
    }
}

#[test]
fn legal_frames_cover_empty_short_and_multibyte_payloads() {
    assert_has_entries(
        "legal_frames",
        &[
            "V_LEN_0",
            "V_LEN_1",
            "V_LEN_2_EMPTY_JSON",
            "V_LEN_255",
            "V_LEN_256",
            "V_JSON_ASCII",
            "V_UTF8_CJK",
        ],
    );
    // 多字节 UTF-8 那条必须真的含非 ASCII 字节。
    let cjk = entry("legal_frames", "V_UTF8_CJK");
    let payload = from_hex(&str_field(cjk, "payload_hex"));
    assert!(
        payload.iter().any(|b| *b > 0x7f),
        "V_UTF8_CJK 必须含非 ASCII 字节"
    );
}

// ---------------------------------------------------------------- 分片回放

#[test]
fn fragmented_frames_replay_chunk_by_chunk() {
    for item in entries("fragmented_frames") {
        let name = str_field(item, "name");
        let payload = from_hex(&str_field(item, "payload_hex"));
        let expected_frame = to_native(&from_hex(&str_field(item, "frame_hex")));

        let mut decoder = FrameDecoder::new();
        for chunk in item["chunks"].as_array().expect("chunks 必须是数组") {
            let bytes = from_hex(&str_field(chunk, "hex"));
            let frames = decoder.feed(&bytes).expect("分片喂入不应报错");
            let expect_frames: Vec<String> = chunk["expect_frames"]
                .as_array()
                .expect("expect_frames 必须是数组")
                .iter()
                .map(|v| {
                    v.as_str()
                        .expect("expect_frames 的元素必须是字符串")
                        .to_owned()
                })
                .collect();
            let expect_pending =
                chunk["expect_pending"].as_u64().expect("缺 expect_pending") as usize;

            let got: Vec<String> = frames.iter().map(hex::encode).collect();
            assert_eq!(got, expect_frames, "{}：本段取出的帧不对", name);
            assert_eq!(
                decoder.pending(),
                expect_pending,
                "{}：本段剩余字节数不对",
                name
            );
        }

        // 全部喂完后，残留必须与向量写的一致
        // （`V_FRAG_TWO_FRAMES_AND_HALF` 故意停在半帧上 ⇒ 残留 2）。
        let expect_final = u64_field(item, "expect_final_pending") as usize;
        assert_eq!(
            decoder.pending(),
            expect_final,
            "{}：喂完后的残留字节数不对",
            name
        );

        // 拼起来的字节必须正好等于向量记录的全部输入。
        let mut whole = Vec::new();
        for chunk in item["chunks"].as_array().expect("chunks 必须是数组") {
            whole.extend_from_slice(&from_hex(&str_field(chunk, "hex")));
        }
        assert_eq!(
            hex::encode(&whole),
            str_field(item, "concat_hex"),
            "{}：分片拼起来与向量记录不符",
            name
        );
        assert_eq!(payload.len(), expected_frame.len() - FRAME_HEADER_LEN);
    }
}

#[test]
fn fragmented_frames_cover_byte_half_multi_and_n_chunks() {
    assert_has_entries(
        "fragmented_frames",
        &[
            "V_FRAG_BYTE_BY_BYTE",
            "V_FRAG_HALF_HEADER_THEN_REST",
            "V_FRAG_TWO_FRAMES_AND_HALF",
            "V_FRAG_CHUNK_SIZE_3",
        ],
    );
}

// ---------------------------------------------------------------- 非法帧回放

#[test]
fn illegal_frames_fail_with_expected_category() {
    for item in entries("illegal_frames") {
        let name = str_field(item, "name");
        let input = from_hex(&str_field(item, "input_hex"));
        let expected = &item["error"];

        let error = decode_frame(&input).expect_err("非法向量必须解码失败");
        match str_field(item, "category").as_str() {
            "frame_too_long" => match error {
                FrameError::FrameTooLong { declared, limit } => {
                    assert_eq!(declared, expected["declared"].as_u64().unwrap(), "{}", name);
                    assert_eq!(
                        limit as u64,
                        expected["limit"].as_u64().unwrap(),
                        "{}",
                        name
                    );
                }
                other => panic!("{}：期望 frame_too_long，实际 {:?}", name, other),
            },
            "incomplete" => match error {
                FrameError::Incomplete { needed, available } => {
                    assert_eq!(
                        needed as u64,
                        expected["needed"].as_u64().unwrap(),
                        "{}",
                        name
                    );
                    assert_eq!(
                        available as u64,
                        expected["available"].as_u64().unwrap(),
                        "{}",
                        name
                    );
                }
                other => panic!("{}：期望 incomplete，实际 {:?}", name, other),
            },
            other => panic!("{}：未知失败类别 {}", name, other),
        }
    }
}

// ---------------------------------------------------------------- 上限回放

#[test]
fn limit_cases_enforce_the_two_one_mib_caps() {
    for item in entries("limit_cases") {
        let name = str_field(item, "name");
        let expected = &item["error"];
        match str_field(item, "op").as_str() {
            "encode" => {
                let payload_len = u64_field(item, "payload_len") as usize;
                let payload = vec![0x5au8; payload_len];
                match str_field(item, "expect").as_str() {
                    "ok" => {
                        let encoded = encode_frame(&payload).expect("上限之内的载荷必须能编码");
                        assert_eq!(encoded.len(), FRAME_HEADER_LEN + payload_len, "{}", name);
                    }
                    "payload_too_long" => {
                        let error = encode_frame(&payload).expect_err("超限必须报错");
                        match error {
                            FrameError::PayloadTooLong { declared, limit } => {
                                assert_eq!(
                                    declared as u64,
                                    expected["declared"].as_u64().unwrap(),
                                    "{}",
                                    name
                                );
                                assert_eq!(
                                    limit as u64,
                                    expected["limit"].as_u64().unwrap(),
                                    "{}",
                                    name
                                );
                            }
                            other => panic!("{}：期望 payload_too_long，实际 {:?}", name, other),
                        }
                    }
                    other => panic!("{}：未知期望 {}", name, other),
                }
            }
            "decode_header" => {
                let header = header_to_native(&from_hex(&str_field(item, "length_header_hex")));
                let error = decode_frame(&header).expect_err("只有长度头的缓冲必然不完整或超限");
                match str_field(item, "expect").as_str() {
                    "incomplete" => match error {
                        FrameError::Incomplete { needed, available } => {
                            assert_eq!(
                                needed as u64,
                                expected["needed"].as_u64().unwrap(),
                                "{}",
                                name
                            );
                            assert_eq!(
                                available as u64,
                                expected["available"].as_u64().unwrap(),
                                "{}",
                                name
                            );
                        }
                        other => panic!("{}：期望 incomplete，实际 {:?}", name, other),
                    },
                    "frame_too_long" => match error {
                        FrameError::FrameTooLong { declared, limit } => {
                            assert_eq!(
                                declared,
                                expected["declared"].as_u64().unwrap(),
                                "{}",
                                name
                            );
                            assert_eq!(
                                limit as u64,
                                expected["limit"].as_u64().unwrap(),
                                "{}",
                                name
                            );
                        }
                        other => panic!("{}：期望 frame_too_long，实际 {:?}", name, other),
                    },
                    other => panic!("{}：未知期望 {}", name, other),
                }
            }
            other => panic!("{}：未知调用目标 {}", name, other),
        }
    }
}
