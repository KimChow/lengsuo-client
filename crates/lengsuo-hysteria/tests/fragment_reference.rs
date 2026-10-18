//! 参考 `frag_test.go` 的逐条移植：`TestDefragger` 用例表 + `TestFragUDPMessage`
//! 用例表。
//!
//! 参考实现为 apernet/hysteria 完整 commit
//! `ca8fbd874fd6ca82413948de6dc5924405e103e1` 的
//! `core/internal/frag/frag.go` 与其 `frag_test.go`。本文件把两张表**原样**搬进
//! Rust：同一条 [`Defragger`] 按表内顺序逐行喂入（参考也是同一个 `d`），
//! `want == nil` 对应 [`DefragOutput::Pending`]，`want` 为非空消息对应
//! [`DefragOutput::Complete`] 且逐字段比对。
//!
//! 期望值不是从本 crate 的实现结果回填的，而是照抄参考测试文件里的字面量
//! （`SessionID: 123`、`Addr: "test:123"`、各片 `Data` 与拼接结果）。
//!
//! 只覆盖分片状态机与切片判据：不涉及 QUIC、HTTP/3、datagram 中继。本文件
//! 证明与参考在构造样本上语义一致，**不**证明与原生服务端的真实互通。

use lengsuo_hysteria::fragment::{frag_udp_message, DefragOutput, Defragger};
use lengsuo_hysteria::udp::UdpMessage;

/// 参考用例表里的地址常量（Go 侧 `Addr: "test:123"`，8 字节）。
const ADDR: &[u8] = b"test:123";

/// 参考 `frag_test.go` 里 `TestFragUDPMessage` 使用的 8 字节载荷 `"abcdefgh"`。
const ABCDEFGH: &[u8] = b"abcdefgh";

/// 构造一条与参考表字段一一对应的报文；`sessionID` 固定 123（参考两张表同值）。
fn frag<'a>(packet_id: u16, fragment_id: u8, fragment_count: u8, data: &'a [u8]) -> UdpMessage<'a> {
    UdpMessage {
        session_id: 123,
        packet_id,
        fragment_id,
        fragment_count,
        address: ADDR,
        data,
    }
}

/// 参考 `want` 的两种取值：`nil` 与一条完整消息（载荷借用，避免所有权噪音）。
#[derive(Debug, PartialEq, Eq)]
enum Want<'a> {
    Nil,
    Full {
        session_id: u32,
        packet_id: u16,
        fragment_id: u8,
        fragment_count: u8,
        address: &'a [u8],
        data: &'a [u8],
    },
}

/// 断言一次喂入的结果与参考期望一致。`Complete` 时逐字段（含地址与载荷字节）比对。
fn check(case: &str, output: DefragOutput<'_>, want: Want<'_>) {
    match want {
        Want::Nil => assert_eq!(
            output,
            DefragOutput::Pending,
            "{case}: 参考 Feed 返回 nil，本实现必须返回 Pending"
        ),
        Want::Full {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            address,
            data,
        } => match output {
            DefragOutput::Complete(m) => {
                assert_eq!(m.session_id, session_id, "{case}: sessionID");
                assert_eq!(m.packet_id, packet_id, "{case}: packetID");
                assert_eq!(m.fragment_id, fragment_id, "{case}: fragID");
                assert_eq!(m.fragment_count, fragment_count, "{case}: fragCount");
                assert_eq!(m.address, address, "{case}: 地址字节");
                assert_eq!(m.data.as_ref(), data, "{case}: 拼接后的载荷字节");
            }
            DefragOutput::Pending => {
                panic!("参考 Feed 对「{case}」返回非 nil，本实现返回了 Pending")
            }
        },
    }
}

/// 参考表里 `want` 非 nil 的通用形状：`sessionID` 固定 123，收齐后 fragID/fragCount
/// 归一为 `0 / 1`，地址不变。
fn want_full<'a>(packet_id: u16, data: &'a [u8]) -> Want<'a> {
    Want::Full {
        session_id: 123,
        packet_id,
        fragment_id: 0,
        fragment_count: 1,
        address: ADDR,
        data,
    }
}

/// 参考 `TestDefragger`：**同一个** `Defragger{}` 按表顺序喂入 11 行。
///
/// 表内容与 `frag_test.go` 第 149-330 行的 `tests` 切片逐行对应，包括用例名。
#[test]
fn defragger_matches_reference_case_table() {
    let mut d = Defragger::new();

    // "no frag"：FragCount 1 ⇒ 原样返回同一条消息。
    check(
        "no frag",
        d.feed(&frag(987, 0, 1, b"hello")),
        want_full(987, b"hello"),
    );

    // "frag 0 - 1/2"：只到第一片 ⇒ nil。
    check(
        "frag 0 - 1/2",
        d.feed(&frag(987, 0, 2, b"hello ")),
        Want::Nil,
    );

    // "frag 0 - 2/2"：第二片到齐 ⇒ 按 fragID 升序拼接 "hello " + "moto"。
    check(
        "frag 0 - 2/2",
        d.feed(&frag(987, 1, 2, b"moto")),
        want_full(987, b"hello moto"),
    );

    // "frag 1 - 1/3"：FragCount 由 2 变 3 ⇒ 丢弃旧状态重开 ⇒ nil。
    check("frag 1 - 1/3", d.feed(&frag(987, 0, 3, b"deco")), Want::Nil);

    // "frag 1 - 2/3" ⇒ nil（仍在等待第 3 片）。
    check("frag 1 - 2/3", d.feed(&frag(987, 1, 3, b"*")), Want::Nil);

    // "frag 1 - 3/3" ⇒ 拼接 "deco" + "*" + "27"。
    check(
        "frag 1 - 3/3",
        d.feed(&frag(987, 2, 3, b"27")),
        want_full(987, b"deco*27"),
    );

    // "frag 2 - 1/2"：新 packetID 233，且**先到的是 fragID 1** ⇒ nil。
    check(
        "frag 2 - 1/2",
        d.feed(&frag(233, 1, 2, b"shinsekai")),
        Want::Nil,
    );

    // "frag 3 - 2/2"：packetID 244 变化 ⇒ 丢弃 233 的半截状态 ⇒ nil。
    check(
        "frag 3 - 2/2",
        d.feed(&frag(244, 1, 2, b"what???")),
        Want::Nil,
    );

    // "frag 2 - 2/2"：packetID 回到 233 ⇒ 又丢弃 244 的状态，只登记本片 ⇒ nil。
    check(
        "frag 2 - 2/2",
        d.feed(&frag(233, 1, 2, b" annaijo")),
        Want::Nil,
    );

    // "invalid id"：fragID 88 >= fragCount 2 ⇒ nil（// wtf is this?）。
    check(
        "invalid id",
        d.feed(&frag(233, 88, 2, b"shinsekai")),
        Want::Nil,
    );

    // "frag 2 - 1/2 re"：补上 fragID 0 ⇒ 与先前登记的 fragID 1 拼成完整报文。
    // 参考此处证明「丢弃 244 后 233 的重开状态」仍保留着 " annaijo"，且
    // "invalid id" 那一片没有污染槽位。
    check(
        "frag 2 - 1/2 re",
        d.feed(&frag(233, 0, 2, b"shinsekai")),
        want_full(233, b"shinsekai annaijo"),
    );
}

/// 参考 `TestDefragger` 的逐行断言之外，再确认「重复片不覆盖不计数」与
/// 「交付后槽位仍在」这两条参考行为（参考靠同一张表间接覆盖，这里显式固定）。
#[test]
fn duplicate_fragment_does_not_overwrite_or_resend() {
    let mut d = Defragger::new();
    check("first", d.feed(&frag(7, 0, 2, b"AA")), Want::Nil);
    // 同 fragID 再来一片、内容不同：参考 `d.frags[0] != nil` ⇒ 忽略，不覆盖。
    check("dup", d.feed(&frag(7, 0, 2, b"ZZ")), Want::Nil);
    // 补齐第二片：拼接必须用**先到的** "AA"，不是重复片 "ZZ"。
    check(
        "second",
        d.feed(&frag(7, 1, 2, b"BB")),
        want_full(7, b"AABB"),
    );
    // 交付后缓冲未清空 ⇒ 再喂任何一片都只会被忽略，绝不重复交付。
    check("resend frag0", d.feed(&frag(7, 0, 2, b"AA")), Want::Nil);
    check("resend frag1", d.feed(&frag(7, 1, 2, b"BB")), Want::Nil);
}

/// 参考 `TestFragUDPMessage`："no frag" 一行：`Size() <= maxSize` ⇒ 单元素结果，
/// 且**不改写** fragID / fragCount / 载荷。
#[test]
fn frag_no_frag_matches_reference() {
    let m = frag(123, 0, 1, b"hello");
    let frags = frag_udp_message(&m, 100).expect("可分片");
    assert_eq!(frags.len(), 1);
    assert_eq!(frags[0].fragment_id, 0);
    assert_eq!(frags[0].fragment_count, 1);
    assert_eq!(frags[0].data, b"hello");
    assert_eq!(frags[0].address, ADDR);
    assert_eq!(frags[0].packet_id, 123);
    assert_eq!(frags[0].session_id, 123);
}

/// 参考 `TestFragUDPMessage`："2 frags" 一行。头部 17 字节（8 定宽 + varint(8)
/// + 8 地址），`maxSize 20` ⇒ 每片载荷 3 字节 ⇒ `"hel"` / `"lo"`，共 2 片。
#[test]
fn frag_two_fragments_matches_reference() {
    let m = frag(123, 0, 1, b"hello");
    let frags = frag_udp_message(&m, 20).expect("可分片");
    let expected: [(&[u8], u8, u8); 2] = [(b"hel", 0, 2), (b"lo", 1, 2)];
    assert_eq!(frags.len(), expected.len());
    for (got, (data, id, count)) in frags.iter().zip(expected) {
        assert_eq!(got.data, data);
        assert_eq!(got.fragment_id, id);
        assert_eq!(got.fragment_count, count);
        assert_eq!(got.address, ADDR);
        assert_eq!(got.session_id, 123);
        assert_eq!(got.packet_id, 123);
    }
}

/// 参考 `TestFragUDPMessage`："4 frags" 一行。`maxSize 19` ⇒ 每片载荷 2 字节
/// ⇒ `"ab"` / `"cd"` / `"ef"` / `"gh"`，共 4 片，`fragID` 从 0 递增。
#[test]
fn frag_four_fragments_matches_reference() {
    let m = frag(123, 0, 1, ABCDEFGH);
    let frags = frag_udp_message(&m, 19).expect("可分片");
    let expected: [&[u8]; 4] = [b"ab", b"cd", b"ef", b"gh"];
    assert_eq!(frags.len(), 4);
    for (index, got) in frags.iter().enumerate() {
        assert_eq!(got.data, expected[index], "fragID {index} 的载荷");
        assert_eq!(got.fragment_id, index as u8);
        assert_eq!(got.fragment_count, 4);
    }
}

/// 参考两张表的闭环：`frag_udp_message` 的分片结果喂进 `Defragger` 必须还原原文。
/// 参考测试没有这条，但它同时约束两个判据（每片长度与条数）互相自洽。
#[test]
fn reference_frag_cases_reassemble_to_original() {
    for (max_size, payload) in [(20usize, &b"hello"[..]), (19, ABCDEFGH), (18, &b"x"[..])] {
        let m = frag(9, 0, 1, payload);
        let frags = frag_udp_message(&m, max_size).expect("可分片");
        let mut d = Defragger::new();
        let mut last = None;
        for f in &frags {
            if let DefragOutput::Complete(completed) = d.feed(f) {
                last = Some(completed);
            }
        }
        let completed = last.expect("分片全部到齐必须交付完整报文");
        assert_eq!(completed.data.as_ref(), payload);
        assert_eq!(completed.fragment_id, 0);
        assert_eq!(completed.fragment_count, 1);
        assert_eq!(completed.address, ADDR);
        assert_eq!(completed.packet_id, 9);
    }
}
