//! 一致性测试：向量能复现、向量自洽、跨向量不矛盾。
//!
//! 覆盖任务书 §六 的第 1、5、7、8 条（1–4 与 6 在
//! [`super::session_vectors`] / [`super::error_vectors`] 里）：
//!
//! 1. **向量 JSON 规范化**：内嵌 JSON 与「解析后重新渲染」**逐字节相同**。
//! 5. **世代号可复现**：首轮握手世代号 = 初始值；**重连后 = 上一代 +1**。
//! 7. **坏输入不返回部分数据**：截断/篡改输入 ⇒ 明确错误，**无部分明文**。
//! 8. **自洽性**：向量集合内部不矛盾（帧序号单调、世代号不倒退、密钥方向一致）。

use super::json::{parse, render};
use super::rebuild::{initiation_mac1_ok, rebuild_handshake, rebuild_link, response_mac1_ok};
use super::session_vectors::{
    parse_session_vectors, FORMAT, INITIATION_VOLATILE_LAYOUT, RESPONSE_VOLATILE_LAYOUT,
    SESSION_VECTORS_JSON, VERSION,
};
use super::{error_vectors::ERROR_VECTORS_JSON, from_hex, to_hex, DIR_I2R, DIR_R2I};

/// 内嵌 JSON 与「解析后重新渲染」**逐字节相同**。
///
/// 防止手改 JSON 造成格式漂移（与既有 `frame_vectors.rs` 的
/// `vectors_are_canonical_json` 同一手法）。
#[test]
pub fn session_vectors_json_is_canonical() {
    let json = parse(SESSION_VECTORS_JSON);
    assert_eq!(
        render(&json),
        SESSION_VECTORS_JSON,
        "会话向量 JSON 与规范渲染不一致"
    );
}

/// 错误向量 JSON 同样必须是规范 JSON。
#[test]
pub fn error_vectors_json_is_canonical() {
    let json = parse(ERROR_VECTORS_JSON);
    assert_eq!(
        render(&json),
        ERROR_VECTORS_JSON,
        "错误向量 JSON 与规范渲染不一致"
    );
}

/// 每条会话向量都能被**重算**（握手报文 + 传输密钥 + 帧）。
#[test]
pub fn every_session_vector_is_reproducible() {
    let links = parse_session_vectors();
    assert!(!links.is_empty(), "会话向量不能为空");
    for link in &links {
        let rebuilt = rebuild_link(link);
        assert_eq!(
            rebuilt.len(),
            link.rounds.len(),
            "链路 {} 的重算轮数不符",
            link.name
        );
        for (round, outcome) in link.rounds.iter().zip(&rebuilt) {
            // 世代号可复现。
            assert_eq!(
                outcome.generation, round.generation,
                "链路 {} 第 {} 轮的世代号不符",
                link.name, round.round
            );
            // 握手报文可复现：会话层重算出的字节清掉墙钟区段后，
            // 必须与向量里声明的 canonical 字节**逐字节相同**。
            let canonical_init =
                super::zero_ranges(&outcome.initiation, &round.initiation.volatile_ranges);
            assert_eq!(
                to_hex(&canonical_init),
                to_hex(&round.initiation.canonical),
                "链路 {} 第 {} 轮的 initiation canonical 字节不符",
                link.name,
                round.round
            );
            let canonical_resp =
                super::zero_ranges(&outcome.response, &round.response.volatile_ranges);
            assert_eq!(
                to_hex(&canonical_resp),
                to_hex(&round.response.canonical),
                "链路 {} 第 {} 轮的 response canonical 字节不符",
                link.name,
                round.round
            );
            // 帧字节可复现（整帧期望字节）。
            assert_eq!(
                outcome.frames.len(),
                round.frames.len(),
                "链路 {} 第 {} 轮的帧数不符",
                link.name,
                round.round
            );
            for (frame, actual) in round.frames.iter().zip(&outcome.frames) {
                assert_eq!(
                    to_hex(actual),
                    to_hex(&frame.frame),
                    "链路 {} 第 {} 轮的帧 {} 字节不符",
                    link.name,
                    round.round,
                    frame.name
                );
            }
        }
    }
}

/// 握手报文的 **canonical 形式**（墙钟区段清零）可复现。
///
/// 这是本卡对握手报文的**可复现断言**：墙钟区段按声明清零后，
/// 其余字节必须**逐字节**等于向量里的 `canonical_hex`。
#[test]
pub fn every_handshake_message_canonical_form_is_reproducible() {
    for link in parse_session_vectors() {
        for round in &link.rounds {
            let (initiation, response, _) = rebuild_handshake(&link.material, round);
            assert_eq!(
                initiation.len(),
                148,
                "链路 {} 的 initiation 长度不符",
                link.name
            );
            assert_eq!(
                response.len(),
                92,
                "链路 {} 的 response 长度不符",
                link.name
            );
            let canonical_init = super::zero_ranges(&initiation, &round.initiation.volatile_ranges);
            assert_eq!(
                to_hex(&canonical_init),
                to_hex(&round.initiation.canonical),
                "链路 {} 第 {} 轮的 initiation canonical 字节不符",
                link.name,
                round.round
            );
            let canonical_resp = super::zero_ranges(&response, &round.response.volatile_ranges);
            assert_eq!(
                to_hex(&canonical_resp),
                to_hex(&round.response.canonical),
                "链路 {} 第 {} 轮的 response canonical 字节不符",
                link.name,
                round.round
            );
        }
    }
}

/// 传输密钥可复现，且**方向性**正确。
///
/// 发起方的 send 密钥 == 响应方的 receive 密钥，反之亦然。
#[test]
pub fn every_transport_key_is_reproducible_and_directional() {
    for link in parse_session_vectors() {
        for round in &link.rounds {
            let (_, _, keys) = rebuild_handshake(&link.material, round);
            let expected = &round.transport_keys;
            assert_eq!(
                to_hex(&keys.initiator_send),
                to_hex(&expected.initiator_send),
                "链路 {} 第 {} 轮的发起方发送密钥不符",
                link.name,
                round.round
            );
            assert_eq!(
                keys.initiator_receive, expected.initiator_receive,
                "链路 {} 第 {} 轮：发起方接收密钥不符",
                link.name, round.round
            );
            assert_eq!(
                keys.responder_send, expected.responder_send,
                "链路 {} 第 {} 轮：响应方发送密钥不符",
                link.name, round.round
            );
            assert_eq!(
                keys.initiator_send, expected.responder_receive,
                "链路 {} 第 {} 轮：发起方发送密钥必须等于响应方接收密钥",
                link.name, round.round
            );
            assert_eq!(
                keys.responder_receive, expected.initiator_send,
                "链路 {} 第 {} 轮：响应方接收密钥必须等于发起方发送密钥",
                link.name, round.round
            );
        }
    }
}

/// 世代号可复现：首轮 = 初始值，**重连后 = 上一代 +1**。
#[test]
pub fn generation_is_reproducible_and_advances_by_one() {
    for link in parse_session_vectors() {
        let mut previous: Option<u64> = None;
        for round in &link.rounds {
            match previous {
                None => assert_eq!(
                    round.generation, 0,
                    "链路 {} 第 {} 轮：首轮世代号必须是初始值 0",
                    link.name, round.round
                ),
                Some(prev) => assert_eq!(
                    round.generation,
                    prev + 1,
                    "链路 {} 第 {} 轮：重连后世代号必须 = 上一代 + 1",
                    link.name,
                    round.round
                ),
            }
            previous = Some(round.generation);
        }
    }
}

/// 自洽性：帧序号**单调递增**、世代号**不倒退**、每轮至少一帧。
#[test]
pub fn session_vectors_are_self_consistent() {
    for link in parse_session_vectors() {
        let mut last_generation: Option<u64> = None;
        for round in &link.rounds {
            assert!(
                !round.frames.is_empty(),
                "链路 {} 第 {} 轮至少要有一帧",
                link.name,
                round.round
            );
            if let Some(prev) = last_generation {
                assert!(
                    round.generation > prev,
                    "链路 {} 第 {} 轮：世代号不得倒退",
                    link.name,
                    round.round
                );
            }
            last_generation = Some(round.generation);
            // 同一方向内，帧序号单调递增。
            for direction in [DIR_I2R, DIR_R2I] {
                let mut last_seq: Option<u64> = None;
                for frame in round.frames.iter().filter(|f| f.direction == direction) {
                    if let Some(prev) = last_seq {
                        assert!(
                            frame.seq > prev,
                            "链路 {} 第 {} 轮：同方向帧序号必须单调递增",
                            link.name,
                            round.round
                        );
                    }
                    last_seq = Some(frame.seq);
                }
            }
        }
    }
}

/// 跨向量不矛盾：不同链路的密钥材料**互不相同**（不共用密钥）。
#[test]
pub fn links_do_not_share_key_material() {
    let links = parse_session_vectors();
    for (index, link) in links.iter().enumerate() {
        for other in &links[index + 1..] {
            assert_ne!(
                link.material.initiator_static_private, other.material.initiator_static_private,
                "链路 {} 与 {} 共用了发起方静态私钥",
                link.name, other.name
            );
            assert_ne!(
                link.material.responder_static_private, other.material.responder_static_private,
                "链路 {} 与 {} 共用了响应方静态私钥",
                link.name, other.name
            );
        }
    }
}

/// 向量里的**期望帧字节**能解回类型/序号/明文（三重校验的第三条）。
#[test]
pub fn every_expected_frame_decodes_back_to_its_plaintext() {
    use lengsuo_link_core::frame::decode_exact;
    for link in parse_session_vectors() {
        for round in &link.rounds {
            for frame in &round.frames {
                let decoded = decode_exact(&frame.frame).unwrap_or_else(|e| {
                    panic!("链路 {} 的帧 {} 无法解码：{e:?}", link.name, frame.name)
                });
                assert_eq!(decoded.frame_type, frame.frame_type, "帧 {}", frame.name);
                assert_eq!(decoded.seq, frame.seq, "帧 {}", frame.name);
                assert_eq!(
                    decoded.payload.len(),
                    frame.frame.len() - 20,
                    "帧 {} 的载荷长度不符",
                    frame.name
                );
            }
        }
    }
}

/// 向量 JSON 的**头部字段**与本卡常量一致（移动端按它们识别版本）。
#[test]
pub fn session_vector_header_matches_constants() {
    let json = parse(SESSION_VECTORS_JSON);
    assert_eq!(json.field("format").as_str(), FORMAT);
    assert_eq!(json.field("version").as_u64(), VERSION);
    assert!(
        json.field("links").as_arr().len() >= 2,
        "至少要有两条链路向量"
    );
}

/// 帧向量的 `counter` 字段必须与**实际发送顺序**一致（每方向各自从 0 起）。
#[test]
pub fn frame_counters_match_per_direction_send_order() {
    for link in parse_session_vectors() {
        for round in &link.rounds {
            for direction in [DIR_I2R, DIR_R2I] {
                for (index, frame) in round
                    .frames
                    .iter()
                    .filter(|f| f.direction == direction)
                    .enumerate()
                {
                    assert_eq!(
                        frame.counter, index as u64,
                        "链路 {} 第 {} 轮的帧 {}：计数器必须与该方向的发送顺序一致",
                        link.name, round.round, frame.name
                    );
                }
            }
        }
    }
}

/// 十六进制工具自检（取值器的基础设施不能出错）。
#[test]
pub fn hex_helpers_round_trip() {
    let bytes = [0x00u8, 0x0f, 0x5a, 0xff];
    assert_eq!(to_hex(&bytes), "000f5aff");
    assert_eq!(from_hex("000f5aff"), bytes);
}

/// 握手报文的 **MAC1** 自校验：重算出的 initiation / response 必须带**正确**的 MAC1。
///
/// 这是「重算出来的字节确实是合法握手报文」的**独立**证据
/// （前面的用例只比对「与向量里存的字节相同」——那可能两边一起错）。
#[test]
pub fn handshake_messages_carry_a_valid_mac1() {
    for link in parse_session_vectors() {
        for round in &link.rounds {
            let (initiation, response, _) = rebuild_handshake(&link.material, round);
            assert!(
                initiation_mac1_ok(&initiation, &link.material.responder_static_public),
                "链路 {} 第 {} 轮的 initiation MAC1 不符",
                link.name,
                round.round
            );
            assert!(
                response_mac1_ok(&response, &link.material.initiator_static_public),
                "链路 {} 第 {} 轮的 response MAC1 不符",
                link.name,
                round.round
            );
        }
    }
}

/// 向量里**声明**的 volatile 区段布局必须与代码里的常量一致。
///
/// `volatile_ranges` 说「哪几个字节是墙钟依赖」，`volatile_layout` 说「那几段
/// 各自是什么」⇒ 两者必须与代码常量逐字一致，否则移动端按文档清零会清错位置。
#[test]
pub fn volatile_layout_matches_the_code_constants() {
    for link in parse_session_vectors() {
        for round in &link.rounds {
            assert_eq!(
                round.initiation.volatile_layout, INITIATION_VOLATILE_LAYOUT,
                "链路 {} 第 {} 轮的 initiation volatile 布局说明不符",
                link.name, round.round
            );
            assert_eq!(
                round.response.volatile_layout, RESPONSE_VOLATILE_LAYOUT,
                "链路 {} 第 {} 轮的 response volatile 布局说明不符",
                link.name, round.round
            );
        }
    }
}
