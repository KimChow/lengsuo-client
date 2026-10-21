//! 维护者工具：**重新生成**向量 JSON。
//!
//! 默认跳过（`#[ignore]`）：它只做打印，不参与断言。用
//! `cargo test -p lengsuo-link-core --test vectors_main -- --ignored --nocapture`
//! 实跑，把输出贴回 `session_vectors.rs` / `error_vectors.rs` 的常量里。
//!
//! ⚠️ 生成器**重算**每个字节（不读旧常量）⇒ 输出的就是「按当前实现应得的
//! 期望字节」。仓内的常量必须与生成器输出**逐字节相同**（由
//! `session_vectors_json_is_canonical` / `every_session_vector_is_reproducible`
//! 这两条用例守住）。

use super::json::{arr, n, obj, render, s};
use super::rebuild::{rebuild_handshake, rebuild_link};
use super::session_vectors::{
    FrameVector, LinkMaterial, LinkVector, MessageVector, RoundVector, TransportKeys,
};
use super::{from_hex, to_hex, DIR_I2R, DIR_R2I};

/// 链路 A 的密钥材料（测试专用假密钥）。
fn link_a_material() -> LinkMaterial {
    LinkMaterial {
        initiator_static_private: [0x11; 32],
        initiator_static_public: super::key32(
            "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13",
        ),
        responder_static_private: [0x22; 32],
        responder_static_public: super::key32(
            "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20",
        ),
    }
}

/// 链路 B 的密钥材料（测试专用假密钥，与链路 A **不共用**）。
fn link_b_material() -> LinkMaterial {
    LinkMaterial {
        initiator_static_private: [0x33; 32],
        initiator_static_public: super::key32(
            "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14",
        ),
        responder_static_private: [0x44; 32],
        responder_static_public: super::key32(
            "ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b",
        ),
    }
}

/// 一条链路的骨架（帧的**明文/类型/序号**是手工设计的，字节由生成器重算）。
fn link_a() -> LinkVector {
    LinkVector {
        name: "link-a".to_string(),
        material: link_a_material(),
        rounds: vec![
            RoundVector {
                round: 1,
                initiator_index: 0x1111_1111,
                responder_index: 0x2222_2222,
                initiator_seed: [0xA1; 32],
                responder_seed: [0xA2; 32],
                generation: 0,
                initiation: empty_message(),
                response: empty_message(),
                transport_keys: empty_keys(),
                frames: vec![
                    frame("i2r-data-ascii", DIR_I2R, "data", 1, b"helloACP"),
                    frame("r2i-data-reply", DIR_R2I, "data", 1, b"pong"),
                    frame("i2r-control", DIR_I2R, "control", 2, &[0x00, 0xff, 0x10]),
                    frame("r2i-keepalive", DIR_R2I, "keepalive", 2, &[]),
                ],
            },
            RoundVector {
                round: 2,
                initiator_index: 0x3333_3333,
                responder_index: 0x4444_4444,
                initiator_seed: [0xA3; 32],
                responder_seed: [0xA4; 32],
                generation: 1,
                initiation: empty_message(),
                response: empty_message(),
                transport_keys: empty_keys(),
                frames: vec![
                    frame("i2r-data-reconnect", DIR_I2R, "data", 3, b"afterReconnect"),
                    frame("r2i-data-reconnect-reply", DIR_R2I, "data", 3, b"ok"),
                ],
            },
        ],
    }
}

/// 链路 B 的骨架（只做一轮握手，验证「不同密钥 ⇒ 不同派生」）。
fn link_b() -> LinkVector {
    LinkVector {
        name: "link-b".to_string(),
        material: link_b_material(),
        rounds: vec![RoundVector {
            round: 1,
            initiator_index: 0x5555_5555,
            responder_index: 0x6666_6666,
            initiator_seed: [0xB1; 32],
            responder_seed: [0xB2; 32],
            generation: 0,
            initiation: empty_message(),
            response: empty_message(),
            transport_keys: empty_keys(),
            frames: vec![frame(
                "i2r-data-binary",
                DIR_I2R,
                "data",
                1,
                &[0x00, 0xff, 0x80, 0x7f, 0x01, 0xfe],
            )],
        }],
    }
}

/// 造一条帧向量骨架（字节留空，由生成器填）。
fn frame(name: &str, direction: &str, frame_type: &str, seq: u64, plaintext: &[u8]) -> FrameVector {
    FrameVector {
        name: name.to_string(),
        direction: direction.to_string(),
        frame_type: super::frame_type_from_name(frame_type),
        seq,
        counter: 0,
        plaintext: plaintext.to_vec(),
        frame: Vec::new(),
    }
}

/// 空的握手报文向量骨架。
fn empty_message() -> MessageVector {
    MessageVector {
        volatile_ranges: Vec::new(),
        volatile_layout: String::new(),
        canonical: Vec::new(),
    }
}

/// 空的传输密钥骨架。
fn empty_keys() -> TransportKeys {
    TransportKeys {
        initiator_send: [0u8; 32],
        initiator_receive: [0u8; 32],
        responder_send: [0u8; 32],
        responder_receive: [0u8; 32],
    }
}

/// 重新生成会话向量 JSON（维护者用）。
#[test]
#[ignore = "仅用于重新生成向量 JSON"]
fn regenerate_session_vectors_json() {
    let links = vec![link_a(), link_b()];
    let mut rendered_links = Vec::new();
    for link in &links {
        let rebuilt = rebuild_link(link);
        let mut rounds = Vec::new();
        for (index, round) in link.rounds.iter().enumerate() {
            let (initiation, response, keys) = rebuild_handshake(&link.material, round);
            let outcome = &rebuilt[index];
            // 计数器：每个方向各自从 0 起。
            let mut i2r_counter = 0u64;
            let mut r2i_counter = 0u64;
            let mut frames = Vec::new();
            for frame in &round.frames {
                let counter = if frame.direction == DIR_I2R {
                    let value = i2r_counter;
                    i2r_counter += 1;
                    value
                } else {
                    let value = r2i_counter;
                    r2i_counter += 1;
                    value
                };
                let actual = &outcome.frames[frames.len()];
                frames.push(obj(vec![
                    ("name", s(&frame.name)),
                    ("direction", s(&frame.direction)),
                    ("frame_type", s(super::frame_type_name(frame.frame_type))),
                    ("seq", n(frame.seq)),
                    ("counter", n(counter)),
                    ("plaintext_hex", s(&to_hex(&frame.plaintext))),
                    ("frame_hex", s(&to_hex(actual))),
                ]));
            }
            let initiation_ranges =
                super::parse_ranges(super::session_vectors::INITIATION_VOLATILE);
            let response_ranges = super::parse_ranges(super::session_vectors::RESPONSE_VOLATILE);
            rounds.push(obj(vec![
                ("round", n(round.round)),
                ("initiator_index", n(u64::from(round.initiator_index))),
                ("responder_index", n(u64::from(round.responder_index))),
                (
                    "initiator_ephemeral_seed_hex",
                    s(&to_hex(&round.initiator_seed)),
                ),
                (
                    "responder_ephemeral_seed_hex",
                    s(&to_hex(&round.responder_seed)),
                ),
                ("generation", n(round.generation)),
                (
                    "initiation",
                    obj(vec![
                        (
                            "volatile_ranges",
                            s(&super::render_ranges(&initiation_ranges)),
                        ),
                        (
                            "volatile_layout",
                            s(super::session_vectors::INITIATION_VOLATILE_LAYOUT),
                        ),
                        (
                            "canonical_hex",
                            s(&to_hex(&super::zero_ranges(
                                &initiation,
                                &initiation_ranges,
                            ))),
                        ),
                    ]),
                ),
                (
                    "response",
                    obj(vec![
                        (
                            "volatile_ranges",
                            s(&super::render_ranges(&response_ranges)),
                        ),
                        (
                            "volatile_layout",
                            s(super::session_vectors::RESPONSE_VOLATILE_LAYOUT),
                        ),
                        (
                            "canonical_hex",
                            s(&to_hex(&super::zero_ranges(&response, &response_ranges))),
                        ),
                    ]),
                ),
                (
                    "transport_keys",
                    obj(vec![
                        ("initiator_send_hex", s(&to_hex(&keys.initiator_send))),
                        ("initiator_receive_hex", s(&to_hex(&keys.initiator_receive))),
                        ("responder_send_hex", s(&to_hex(&keys.responder_send))),
                        ("responder_receive_hex", s(&to_hex(&keys.responder_receive))),
                    ]),
                ),
                ("frames", arr(frames)),
            ]));
        }
        rendered_links.push(obj(vec![
            ("name", s(&link.name)),
            (
                "initiator_static_private_hex",
                s(&to_hex(&link.material.initiator_static_private)),
            ),
            (
                "initiator_static_public_hex",
                s(&to_hex(&link.material.initiator_static_public)),
            ),
            (
                "responder_static_private_hex",
                s(&to_hex(&link.material.responder_static_private)),
            ),
            (
                "responder_static_public_hex",
                s(&to_hex(&link.material.responder_static_public)),
            ),
            ("rounds", arr(rounds)),
        ]));
    }
    let document = obj(vec![
        ("format", s(super::session_vectors::FORMAT)),
        ("version", n(super::session_vectors::VERSION)),
        ("spec", s(super::session_vectors::SPEC)),
        ("links", arr(rendered_links)),
    ]);
    let text = render(&document);
    // 自检：生成的文本必须能被自己解析回来。
    let _ = super::json::parse(&text);
    println!("{text}");
    // 供 `from_hex` 的死代码告警闭嘴（生成器也用它做自检）。
    assert!(from_hex("00").len() == 1);
}
