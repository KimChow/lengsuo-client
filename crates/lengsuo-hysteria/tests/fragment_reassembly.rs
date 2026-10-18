//! [`Defragger`] 分支与 [`frag_udp_message`] 判据的补充覆盖。
//!
//! 参考实现为 apernet/hysteria 完整 commit
//! `ca8fbd874fd6ca82413948de6dc5924405e103e1` 的 `core/internal/frag/frag.go`。
//! `tests/fragment_reference.rs` 逐条移植了参考自己的用例表；本文件补足参考表
//! **没有走到**的分支与边界：乱序到齐、`fragCount` 变化丢弃、`fragCount == 0`
//! 直通怪癖、`uint8` 条数上限（255 正例 / 256 拒绝）、单片长度不足、
//! 以及「`Debug` 不泄漏地址与载荷」的隐私约束。
//!
//! 期望值全部按参考源码语义（或参考的 `// wtf is this?` 类注释）手工推导，
//! 不是从本 crate 的实现结果回填。真实 QUIC/HTTP3 与原生服务端互通仍未验收。

use lengsuo_hysteria::fragment::{
    frag_udp_message, CompleteMessage, DefragOutput, Defragger, FragmentError, MAX_FRAGMENTS,
};
use lengsuo_hysteria::udp::UdpMessage;
use lengsuo_hysteria::Error;

/// 1 字节地址 ⇒ 头部 = 8 定宽 + 1 varint + 1 地址 = 10 字节。
const ADDR: &[u8] = b"a";
const HEADER: usize = 10;

/// 最小载荷长度：单片长度上限恰好等于头部时 `maxPayloadSize <= 0`。
const MIN_MAX_SIZE: usize = HEADER + 1;

fn message<'a>(
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    data: &'a [u8],
) -> UdpMessage<'a> {
    UdpMessage {
        session_id: 7,
        packet_id,
        fragment_id,
        fragment_count,
        address: ADDR,
        data,
    }
}

/// 收齐时返回完整报文，否则 panic 提示（多数用例只关心最终结果）。
fn complete<'a>(output: DefragOutput<'a>, case: &str) -> CompleteMessage<'a> {
    match output {
        DefragOutput::Complete(m) => m,
        DefragOutput::Pending => panic!("{case}: 期望交付完整报文，实际返回 Pending"),
    }
}

fn pending(output: DefragOutput<'_>, case: &str) {
    assert_eq!(output, DefragOutput::Pending, "{case}: 参考此处返回 nil");
}

#[test]
fn unfragmented_message_passes_through_unchanged() {
    // 参考第 48-50 行：FragCount <= 1 直接返回入参本身，字段一律不改写。
    let mut d = Defragger::new();
    let m = message(1, 0, 1, b"hello");
    let out = complete(d.feed(&m), "fragCount=1");
    assert_eq!(out.fragment_id, 0);
    assert_eq!(out.fragment_count, 1);
    assert_eq!(out.data.as_ref(), b"hello");
    assert_eq!(out.address, ADDR);
    assert_eq!(out.session_id, 7);
    assert_eq!(out.packet_id, 1);
    // 直通不占缓冲：参考同样没有落到 d.frags。
    assert!(d.is_empty());
    assert_eq!(d.current_packet_id(), 0);
    assert_eq!(d.current_fragment_count(), 0);
}

#[test]
fn zero_fragment_count_passes_through_as_reference_does() {
    // 参考判据是 `FragCount <= 1`，所以 fragCount == 0（wire 上合法的怪癖值）
    // 走直通，且 fragID >= fragCount 的检查在直通之后，不会把它判非法。
    // 直通时也不改写 fragID/fragCount —— 原样交回。
    let mut d = Defragger::new();
    let out = complete(d.feed(&message(3, 5, 0, b"x")), "fragCount=0");
    assert_eq!(out.fragment_id, 5);
    assert_eq!(out.fragment_count, 0);
    assert_eq!(out.data.as_ref(), b"x");
    assert!(d.is_empty(), "直通路径不得改动缓冲");
}

#[test]
fn out_of_order_fragments_assemble_by_fragment_id() {
    // 参考第 66-77 行按 d.frags 下标（即 fragID）升序拼接，与到达顺序无关。
    let mut d = Defragger::new();
    pending(d.feed(&message(11, 2, 3, b"27")), "fragID 2 先到");
    pending(d.feed(&message(11, 0, 3, b"deco")), "fragID 0");
    let out = complete(d.feed(&message(11, 1, 3, b"*")), "fragID 1 补齐");
    assert_eq!(
        out.data.as_ref(),
        b"deco*27",
        "必须按 fragID 升序，不是到达顺序"
    );
    assert_eq!(out.fragment_id, 0);
    assert_eq!(out.fragment_count, 1);
    assert_eq!(out.packet_id, 11);
}

#[test]
fn duplicate_fragment_is_neither_counted_nor_overwritten() {
    // 参考第 62 行 `else if d.frags[m.FragID] == nil`：槽位非空则整条落空，
    // 既不覆盖内容也不增加 d.count。
    let mut d = Defragger::new();
    pending(d.feed(&message(21, 0, 2, b"AA")), "第一片");
    assert_eq!(d.current_fragments_received(), 1);
    assert_eq!(d.current_bytes(), 2);
    pending(d.feed(&message(21, 0, 2, b"ZZ")), "重复片（内容不同）");
    assert_eq!(d.current_fragments_received(), 1, "重复片不得计数");
    assert_eq!(d.current_bytes(), 2, "重复片不得累加字节");
    let out = complete(d.feed(&message(21, 1, 2, b"BB")), "补齐");
    assert_eq!(
        out.data.as_ref(),
        b"AABB",
        "重复片的内容绝不能顶掉已登记内容"
    );
}

#[test]
fn new_packet_id_discards_previous_state() {
    // 参考第 36-39 行注释 + 第 55-61 行：一次只处理一个 packet ID，
    // 新包到达即丢弃旧状态（不但丢弃、还以本片重开）。
    let mut d = Defragger::new();
    pending(d.feed(&message(31, 0, 2, b"AAAA")), "包 31 的第一片");
    pending(d.feed(&message(32, 0, 2, b"BBBB")), "包 32 抢占了缓冲");
    assert_eq!(d.current_packet_id(), 32, "缓冲必须换到新包");
    assert_eq!(d.current_bytes(), 4, "旧包的字节计数必须清零后重开");
    // 包 31 的补齐片现在被当作「新包 31」重开，不会与包 32 的状态混拼。
    pending(d.feed(&message(31, 1, 2, b"CCCC")), "回到包 31 视为重开");
    assert_eq!(d.current_packet_id(), 31);
    assert_eq!(d.current_fragments_received(), 1);
    // 只有再补一次 fragID 0 才能拼出「新状态」的报文，且内容来自最后一次登记。
    let out = complete(d.feed(&message(31, 0, 2, b"DDDD")), "包 31 重开后补齐");
    assert_eq!(out.data.as_ref(), b"DDDDCCCC", "旧包 31 的 AAAA 已被丢弃");
}

#[test]
fn changed_fragment_count_restarts_the_buffer() {
    // 参考第 55 行的第二个条件 `m.FragCount != uint8(len(d.frags))`：
    // 同包号但条数变了 ⇒ 丢弃旧状态重开。
    let mut d = Defragger::new();
    pending(d.feed(&message(41, 0, 3, b"1")), "包 41 期望 3 片");
    pending(d.feed(&message(41, 1, 3, b"2")), "第二片");
    assert_eq!(d.current_fragment_count(), 3);
    pending(d.feed(&message(41, 0, 2, b"X")), "同包号但改成 2 片 ⇒ 重开");
    assert_eq!(d.current_fragment_count(), 2, "缓冲必须按新的条数重建");
    assert_eq!(d.current_fragments_received(), 1);
    assert_eq!(d.current_bytes(), 1);
    let out = complete(d.feed(&message(41, 1, 2, b"Y")), "2 片补齐");
    assert_eq!(out.data.as_ref(), b"XY", "先前 3 片状态里的 1/2 必须已丢弃");
}

#[test]
fn fragment_id_not_less_than_count_is_rejected() {
    // 参考第 51-54 行 `if m.FragID >= m.FragCount { return nil }`（// wtf is this?）。
    let mut d = Defragger::new();
    pending(d.feed(&message(51, 0, 2, b"ok")), "先建立包 51 的状态");
    assert_eq!(d.current_fragments_received(), 1);
    // fragID == fragCount（越界一格）与 fragID > fragCount 都必须在登记前被拒。
    pending(d.feed(&message(51, 2, 2, b"bad")), "fragID == fragCount");
    pending(d.feed(&message(51, 255, 2, b"bad")), "fragID = 255");
    assert_eq!(d.current_fragments_received(), 1, "非法片不得进任何槽位");
    assert_eq!(d.current_bytes(), 2, "非法片的载荷不得累加");
    let out = complete(d.feed(&message(51, 1, 2, b"!!")), "补齐");
    assert_eq!(out.data.as_ref(), b"ok!!");
}

#[test]
fn completion_clears_nothing_so_resends_are_ignored() {
    // 参考第 66-77 行交付后**不**重置 d.frags/d.count，因此同分片集的再到达
    // 一律走「槽位非空 ⇒ 忽略」，不会重复交付，也不会把已交付报文二次拼装。
    let mut d = Defragger::new();
    pending(d.feed(&message(61, 0, 2, b"AB")), "第一片");
    let first = complete(d.feed(&message(61, 1, 2, b"CD")), "第二片补齐");
    assert_eq!(first.data.as_ref(), b"ABCD");
    assert_eq!(d.current_fragments_received(), 2, "交付后缓冲保持满状态");
    pending(d.feed(&message(61, 0, 2, b"AB")), "重发第一片");
    pending(d.feed(&message(61, 1, 2, b"CD")), "重发第二片");
    pending(d.feed(&message(61, 0, 2, b"ZZ")), "重发但内容不同");
    // 只有换个包号才能重新开始。
    pending(d.feed(&message(62, 0, 2, b"ZZ")), "换包号重开");
    let second = complete(d.feed(&message(62, 1, 2, b"YY")), "新包补齐");
    assert_eq!(second.data.as_ref(), b"ZZYY");
}

#[test]
fn fragment_count_two_hundred_fifty_five_is_the_hard_limit() {
    // 条数上限的判据来自 wire：fragCount/fragID 都是 uint8（参考第 18 行
    // `(len + maxPayload - 1) / maxPayload` 向上取整后塞进 uint8）。
    let payload: Vec<u8> = (0..MAX_FRAGMENTS as u32).map(|v| v as u8).collect();
    assert_eq!(payload.len(), 255);
    let m = message(1, 0, 1, &payload);
    // max_size = 头部 + 1 ⇒ 每片 1 字节 ⇒ 恰好 255 片，合法正例。
    let frags = frag_udp_message(&m, MIN_MAX_SIZE).expect("255 片必须可分片");
    assert_eq!(frags.len(), MAX_FRAGMENTS);
    assert!(frags.iter().all(|f| f.fragment_count == 255));
    for (index, f) in frags.iter().enumerate() {
        assert_eq!(usize::from(f.fragment_id), index);
        assert_eq!(f.data.len(), 1);
    }
    // 256 片必须 fail-closed，而不是像参考那样 uint8 截断后越界 panic。
    let too_long: Vec<u8> = (0..=MAX_FRAGMENTS as u32).map(|v| v as u8).collect();
    let m2 = message(1, 0, 1, &too_long);
    let err = frag_udp_message(&m2, MIN_MAX_SIZE).expect_err("256 片必须失败");
    assert_eq!(
        err,
        FragmentError::TooManyFragments {
            needed: 256,
            max: MAX_FRAGMENTS
        }
    );
}

#[test]
fn two_hundred_fifty_five_fragments_reassemble_in_reverse_arrival() {
    let payload: Vec<u8> = (0..MAX_FRAGMENTS as u32).map(|v| v as u8).collect();
    let m = message(900, 0, 1, &payload);
    let frags = frag_udp_message(&m, MIN_MAX_SIZE).expect("可分片");
    let mut d = Defragger::new();
    // 逆序喂：最后到的是 fragID 0，交付的载荷仍必须升序。
    let mut out = None;
    for f in frags.iter().rev() {
        if let DefragOutput::Complete(c) = d.feed(f) {
            out = Some(c);
        }
    }
    let completed = out.expect("255 片逆序也必须交付");
    assert_eq!(completed.data.as_ref(), payload.as_slice());
    assert_eq!(completed.fragment_count, 1);
    assert_eq!(completed.fragment_id, 0);
    assert_eq!(completed.packet_id, 900);
    // 完整报文可以原样重新编码并解回同一载荷（与 udp.rs 的字节层闭环）。
    let bytes = completed.encode().expect("重编码");
    let parsed = UdpMessage::decode(&bytes).expect("重解码");
    assert_eq!(parsed.data, payload.as_slice());
    assert_eq!(parsed.address, ADDR);
    assert_eq!(parsed.fragment_id, 0);
    assert_eq!(parsed.fragment_count, 1);
}

#[test]
fn round_trip_of_shuffled_fragments_equals_original_payload() {
    // 固定「交错」置换（不依赖随机源）：偶数下标先、奇数下标后。
    let payload: Vec<u8> = (0..40u32).map(|v| (v % 13) as u8 + b'a').collect();
    let m = message(777, 0, 1, &payload);
    // max_size = 头部 + 2 ⇒ 每片 2 字节 ⇒ 20 片。
    let frags = frag_udp_message(&m, HEADER + 2).expect("可分片");
    assert_eq!(frags.len(), 20);
    let mut order: Vec<usize> = (0..frags.len()).step_by(2).collect();
    order.extend((1..frags.len()).step_by(2));
    let mut d = Defragger::new();
    let mut delivered = Vec::new();
    for index in order {
        if let DefragOutput::Complete(c) = d.feed(&frags[index]) {
            delivered.push(c);
        }
    }
    assert_eq!(delivered.len(), 1, "只应在最后一片交付一次");
    assert_eq!(delivered[0].data.as_ref(), payload.as_slice());
    // 每片长度都不得超过调用方给定的上限（发送侧判据的可观测约束）。
    for f in &frags {
        assert!(f.encoded_len().unwrap() <= HEADER + 2);
    }
}

#[test]
fn max_size_not_above_header_plus_one_fails_closed() {
    let payload = vec![b'x'; 8];
    let m = message(1, 0, 1, &payload);
    // 恰好等于头部 ⇒ 参考 `maxPayloadSize <= 0` ⇒ 无法分片。
    for max_size in [HEADER, HEADER - 1, 0] {
        let err = frag_udp_message(&m, max_size).expect_err("必须失败");
        assert_eq!(
            err,
            FragmentError::MaxSizeTooSmall {
                max_size,
                header_len: HEADER
            }
        );
    }
    // 边界另一侧：头部 + 1 可行（每片 1 字节 ⇒ 8 片）。
    let frags = frag_udp_message(&m, MIN_MAX_SIZE).expect("可行");
    assert_eq!(frags.len(), 8);
    // 恰好不必分片：Size() == maxSize ⇒ 参考返回原消息本身。
    let exactly = frag_udp_message(&m, HEADER + 8).expect("不分片");
    assert_eq!(exactly.len(), 1);
    assert_eq!(exactly[0].fragment_count, 1);
    assert_eq!(exactly[0].data, payload.as_slice());
}

#[test]
fn oversized_address_surfaces_the_codec_error() {
    // 分片路径先做长度检查：地址超过 2048 必须在写入任何字节前失败。
    let long_addr = vec![b'z'; 2049];
    let m = UdpMessage {
        session_id: 1,
        packet_id: 1,
        fragment_id: 0,
        fragment_count: 1,
        address: &long_addr,
        data: b"hi",
    };
    let err = frag_udp_message(&m, 4096).expect_err("地址超限必须失败");
    assert_eq!(
        err,
        FragmentError::Message(Error::TooLong {
            field: "address",
            len: 2049,
            max: 2048
        })
    );
}

#[test]
fn debug_output_leaks_no_address_or_payload() {
    // 隐私策略：错误与 Debug 只输出长度/整数元数据。
    let secret_payload: &[u8] = b"TOPSECRET-DATA";
    let secret_addr: &[u8] = b"SECRET-HOST:1234";
    let m = UdpMessage {
        session_id: 1,
        packet_id: 1,
        fragment_id: 0,
        fragment_count: 2,
        address: secret_addr,
        data: secret_payload,
    };
    let mut d = Defragger::new();
    pending(d.feed(&m), "第一片");
    let state = format!("{d:?}");
    assert!(
        !state.contains("SECRET"),
        "Defragger Debug 不得含地址: {state}"
    );
    assert!(!state.contains("TOPSECRET"), "Defragger Debug 不得含载荷");
    assert!(state.contains("packet_id"), "Debug 仍要有整数元数据");
    // 本片头部 = 8 定宽 + 1 varint + 16 地址 = 25；上限 25 + 4 ⇒ 每片 4 字节
    // ⇒ 14 字节载荷切成 4 片。
    let secret_header = 8 + 1 + secret_addr.len();
    let frags = frag_udp_message(&m, secret_header + 4).expect("可分片");
    assert_eq!(frags.len(), 4);
    let fragment_debug = format!("{:?}", frags[0]);
    assert!(!fragment_debug.contains("TOPSECRET"));
    let out = complete(
        d.feed(&UdpMessage {
            fragment_id: 1,
            ..m
        }),
        "补齐",
    );
    let completed_debug = format!("{out:?}");
    assert!(!completed_debug.contains("SECRET"));
    assert!(!completed_debug.contains("TOPSECRET"));
    assert!(completed_debug.contains("data_len"));
}
