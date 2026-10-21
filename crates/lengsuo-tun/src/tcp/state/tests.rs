//! 单连接状态机的内部单元测试（握手 / 交付 / 乱序 / FIN / RST / 回绕）。

use super::*;
use crate::session::Clock;
use crate::tcp::segment::{self, Flags, Segment};

const NOW: Clock = 0;

/// 经 `segment::build` 生成真字节再 `parse` 回来，用例走生产解析入口。
fn seg<'a>(b: &'a mut Vec<u8>, seq: u32, ack: u32, f: Flags, pl: &[u8]) -> Segment<'a> {
    *b = segment::build(1, 2, seq, ack, f, 1024, &[], pl, &[0u8; 12]).unwrap();
    segment::parse(b).unwrap()
}
fn sent(o: Outcome) -> SendSegment {
    match o {
        Outcome::SendSegment(s) => s,
        other => panic!("应回段，实得 {other:?}"),
    }
}
fn conn(win: u16, slots: usize) -> Connection {
    Connection::new(Config {
        receive_window: win,
        reorder_slots: slots,
        iss_seed: 0,
    })
}
/// 建连：返回连接与对端下一序号（服务端 rcv_nxt）。
fn est(win: u16, slots: usize) -> (Connection, u32) {
    let (mut b, mut c) = (Vec::new(), conn(win, slots));
    c.listen();
    let syn = sent(c.advance(&seg(&mut b, 1000, 0, Flags::SYN, &[]), NOW));
    let rcv = c.rcv_nxt();
    let third = seg(&mut b, rcv, syn.seq.wrapping_add(1), Flags::ACK, &[]);
    c.advance(&third, NOW);
    assert_eq!(c.state(), State::Established);
    (c, rcv)
}

#[test]
fn handshake_duplicate_syn_and_bad_ack() {
    let (mut b, mut c) = (Vec::new(), conn(4096, 4));
    c.listen();
    let s = sent(c.advance(&seg(&mut b, 5000, 0, Flags::SYN, &[]), NOW));
    assert_eq!((s.seq, s.ack, s.flags), (0, 5001, Flags::SYN | Flags::ACK));
    // 重复 SYN 重发同一 ISN；确认号不合规则丢弃且状态不变。
    assert_eq!(
        sent(c.advance(&seg(&mut b, 5000, 0, Flags::SYN, &[]), NOW)).seq,
        0
    );
    let bad = seg(&mut b, 5001, 9, Flags::ACK, &[]);
    assert_eq!(
        c.advance(&bad, NOW),
        Outcome::Discard(DiscardReason::Unexpected)
    );
    assert_eq!(c.state(), State::SynReceived);
    let ok = seg(&mut b, 5001, 1, Flags::ACK, &[]);
    c.advance(&ok, NOW);
    assert_eq!(c.state(), State::Established);
}

#[test]
fn delivery_duplicate_reorder_and_overflow() {
    let (mut c, rcv) = est(4096, 2);
    let mut b = Vec::new();
    let d = seg(&mut b, rcv, 0, Flags::ACK | Flags::PSH, b"abc");
    assert_eq!(c.advance(&d, NOW), Outcome::Deliver(b"abc".to_vec()));
    // 重复段不重复交付。
    let dup = seg(&mut b, rcv, 0, Flags::ACK, b"abc");
    assert_eq!(
        c.advance(&dup, NOW),
        Outcome::Discard(DiscardReason::Duplicate)
    );
    assert_eq!((c.rcv_nxt(), c.delivered_bytes()), (rcv + 3, 3));
    // 乱序：后段入缓冲，前段到达后按序一次交付。
    let base = c.rcv_nxt();
    let lo = seg(&mut b, base + 3, 0, Flags::ACK, b"def");
    assert!(matches!(c.advance(&lo, NOW), Outcome::SendSegment(_)));
    assert_eq!(c.rcv_nxt(), base);
    let hi = seg(&mut b, base, 0, Flags::ACK, b"ghi");
    assert_eq!(c.advance(&hi, NOW), Outcome::Deliver(b"ghidef".to_vec()));
    // 乱序槽位（2）满后第三段丢弃；窗口外段丢弃。
    for at in [base + 8, base + 9] {
        let s = seg(&mut b, at, 0, Flags::ACK, b"x");
        assert!(matches!(c.advance(&s, NOW), Outcome::SendSegment(_)));
    }
    let over = seg(&mut b, base + 10, 0, Flags::ACK, b"y");
    assert_eq!(
        c.advance(&over, NOW),
        Outcome::Discard(DiscardReason::ReorderFull)
    );
    let far = seg(&mut b, c.rcv_nxt() + 4096, 0, Flags::ACK, b"z");
    assert_eq!(
        c.advance(&far, NOW),
        Outcome::Discard(DiscardReason::OutOfWindow)
    );
    // 重复 1 + 乱序满 1 + 窗口外 1。
    assert_eq!(c.discarded_segments(), 3);
}

#[test]
fn zero_window_and_window_update() {
    let (mut b, mut c) = (Vec::new(), conn(4, 2));
    c.listen();
    let s = sent(c.advance(&seg(&mut b, 100, 0, Flags::SYN, &[]), NOW));
    assert_eq!(s.window, 4);
    let third = seg(&mut b, 101, s.seq.wrapping_add(1), Flags::ACK, &[]);
    c.advance(&third, NOW);
    let data = seg(&mut b, 101, 0, Flags::ACK, b"wxyz");
    assert_eq!(c.advance(&data, NOW), Outcome::Deliver(b"wxyz".to_vec()));
    // 接收缓冲用尽后窗口更新通告 0。
    let upd = seg(&mut b, 105, 0, Flags::ACK, &[]);
    let u = sent(c.advance(&upd, NOW));
    assert_eq!((u.window, u.ack), (0, 105));
}

#[test]
fn fin_close_wait_and_final_ack() {
    let (mut c, rcv) = est(4096, 2);
    let mut b = Vec::new();
    // 载荷与 FIN 同到：先交付载荷。
    let tail = seg(&mut b, rcv, 0, Flags::FIN | Flags::ACK, b"tail");
    assert_eq!(c.advance(&tail, NOW), Outcome::Deliver(b"tail".to_vec()));
    let fin = seg(&mut b, rcv + 4, 0, Flags::FIN | Flags::ACK, &[]);
    assert!(matches!(c.advance(&fin, NOW), Outcome::SendSegment(_)));
    assert_eq!((c.state(), c.rcv_nxt()), (State::CloseWait, rcv + 5));
    // 重复 FIN 不再推进 rcv_nxt。
    let again = seg(&mut b, rcv + 4, 0, Flags::FIN | Flags::ACK, &[]);
    assert!(matches!(c.advance(&again, NOW), Outcome::SendSegment(_)));
    assert_eq!(c.rcv_nxt(), rcv + 5);
    // 关写端 → LastAck；最终 ACK → Closed。
    let f = sent(c.close());
    assert_eq!(
        (f.flags, c.state()),
        (Flags::FIN | Flags::ACK, State::LastAck)
    );
    let last = seg(&mut b, rcv + 5, f.seq.wrapping_add(1), Flags::ACK, &[]);
    assert_eq!(c.advance(&last, NOW), Outcome::None);
    assert_eq!((c.state(), c.close()), (State::Closed, Outcome::None));
}

#[test]
fn rst_and_unknown_quadruple() {
    let mut b = Vec::new();
    for target in [
        State::Listen,
        State::SynReceived,
        State::Established,
        State::CloseWait,
    ] {
        let mut c = conn(4096, 2);
        c.listen();
        if target != State::Listen {
            let s = sent(c.advance(&seg(&mut b, 1, 0, Flags::SYN, &[]), NOW));
            if target != State::SynReceived {
                let t = seg(&mut b, 2, s.seq.wrapping_add(1), Flags::ACK, &[]);
                c.advance(&t, NOW);
                if target == State::CloseWait {
                    let f = seg(&mut b, 2, 0, Flags::FIN | Flags::ACK, &[]);
                    c.advance(&f, NOW);
                }
            }
        }
        assert_eq!(c.state(), target);
        let rst = seg(&mut b, 77, 0, Flags::RST, &[]);
        assert_eq!(c.advance(&rst, NOW), Outcome::None);
        assert_eq!(c.state(), State::Closed);
        let _ = c.advance(&seg(&mut b, 78, 0, Flags::ACK, b"x"), NOW);
        assert_eq!(c.state(), State::Closed);
    }
    // Closed 收 SYN 回 RST，确认号 = 对端序号 + 1（SYN 占一位）。
    let mut c = conn(4096, 2);
    let rst = sent(c.advance(&seg(&mut b, 42, 0, Flags::SYN, &[]), NOW));
    assert_eq!((rst.flags, rst.seq, rst.ack), (Flags::RST, 0, 43));
    // Listen 收 ACK / 无标志段回 RST，状态保持 Listen。
    for f in [Flags::ACK, Flags::NONE] {
        let mut l = conn(4096, 2);
        l.listen();
        let bad = seg(&mut b, 9, 5, f, &[]);
        assert_eq!(sent(l.advance(&bad, NOW)).flags, Flags::RST);
        assert_eq!(l.state(), State::Listen);
    }
}

#[test]
fn wraparound_helpers_and_hostile_inputs() {
    let (mut c, _) = est(4096, 2);
    let mut b = Vec::new();
    c.rcv_nxt = u32::MAX - 1;
    let wrap = seg(&mut b, u32::MAX - 1, 0, Flags::ACK, b"abcd");
    assert_eq!(c.advance(&wrap, NOW), Outcome::Deliver(b"abcd".to_vec()));
    assert_eq!(c.rcv_nxt(), 2, "序号必须回绕到 2 而不是溢出");
    // 回绕安全比较；跨度超 2^31 时按有符号语义取一端。
    assert!(seq_lt(u32::MAX, 0) && seq_ge(0, u32::MAX) && !seq_lt(1, 0));
    assert!(seq_in(0, u32::MAX, 1) && !seq_in(2, u32::MAX, 1));
    assert!(seq_lt(0x8000_0000, 0));
    // 非法输入全轮询：全部标志组合、序号极值、超长载荷、RST/FIN 反复投喂。
    let mut c = conn(4096, 2);
    c.listen();
    for bits in 0u8..=0x1fu8 {
        let s = seg(&mut b, 1, 0, Flags::from_byte(bits), &[]);
        let _ = c.advance(&s, NOW);
    }
    for v in [0, 1, u32::MAX, u32::MAX - 1, 0x8000_0000] {
        let s = seg(&mut b, v, v, Flags::ACK, b"x");
        let _ = c.advance(&s, NOW);
    }
    let big = vec![0u8; 60];
    let _ = c.advance(&seg(&mut b, 0, 0, Flags::ACK, &big), NOW);
    let _ = c.advance(&seg(&mut b, 0, 0, Flags::RST, &[]), NOW);
    let _ = c.advance(&seg(&mut b, 0, 0, Flags::FIN, b"z"), NOW);
    assert!(c.is_closed());
}
