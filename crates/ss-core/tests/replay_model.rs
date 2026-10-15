//! 用独立 BTreeSet 参考模型与确定性伪随机序列，逐条比对 `Window` 的判定结果。
//!
//! 模型完全按「已收集合 + 窗口覆盖范围」重新实现，不复用被测位图，
//! 因此两侧一致只说明位图与语义模型等价，不说明与任何真实实现对端互通。
mod replay_support;
use replay_support::Lcg;
use ss_core::replay::Window;
use std::collections::BTreeSet;

const WINDOW: u64 = 8192;

/// 朴素参考模型：保存窗口内的已收计数器集合与最高计数器。
/// 判定按「先检查后写入」实现，拒绝时集合与最高值都不变——与 `Window` 同一约定。
struct Model {
    max_counter: u64,
    highest: Option<u64>,
    seen: BTreeSet<u64>,
}

impl Model {
    fn new(max_counter: u64) -> Self {
        Model {
            max_counter,
            highest: None,
            seen: BTreeSet::new(),
        }
    }
}

/// 返回 `true` 表示收下并更新状态；`false` 表示拒绝且状态不变。
fn model_accept(model: &mut Model, counter: u64) -> bool {
    // 注入上限优先，且不改动状态。
    if counter > model.max_counter {
        return false;
    }
    let Some(highest) = model.highest else {
        model.highest = Some(counter);
        model.seen.insert(counter);
        return true;
    };
    if counter > highest {
        if counter - highest >= WINDOW {
            // 大跨度跳跃：整窗清空，只记住新最高。
            model.seen.clear();
        }
        model.highest = Some(counter);
        model.seen.insert(counter);
        // 丢弃落出窗口 [highest-8191, highest] 的旧项。
        let floor = counter.saturating_sub(WINDOW - 1);
        model.seen = model.seen.split_off(&floor);
        return true;
    }
    if counter == highest {
        return false;
    }
    if highest - counter >= WINDOW {
        return false;
    }
    if model.seen.contains(&counter) {
        return false;
    }
    model.seen.insert(counter);
    true
}

#[test]
fn model_self_check_covers_the_four_outcomes() {
    // 先自检参考模型自身，避免把模型缺陷当成被测实现的失败。
    let mut model = Model::new(u64::MAX);
    assert!(model_accept(&mut model, 10));
    assert!(model_accept(&mut model, 4));
    assert!(!model_accept(&mut model, 10), "窗口内重复");
    assert!(model_accept(&mut model, 5));
    assert!(!model_accept(&mut model, 4), "4 已收");
    assert!(model_accept(&mut model, 10 + WINDOW), "跳跃 8192 清空窗口");
    assert!(!model_accept(&mut model, 10 + WINDOW), "新最高随即重复");
    assert!(!model_accept(&mut model, 4), "跳跃后 4 出窗");
    let mut capped = Model::new(50);
    assert!(!model_accept(&mut capped, 51), "超过注入上限");
    assert!(model_accept(&mut capped, 50));
    assert_eq!(capped.highest, Some(50), "上限拒绝不改状态");
}

#[test]
fn deterministic_mixed_sequence_matches_model() {
    // 固定种子的 LCG，序列完全确定；同一 seed 可逐字节重跑复现。
    // 计数器相对「当前最高」取样，保证同时命中窗口内乱序、窗口内重复、
    // 窗口外太旧与超上限四类结果，而不是绝大多数一步就出窗。
    for (seed, max_counter, base) in [
        (1u64, u64::MAX, 0u64),
        (7, 4_096, 100),
        (99, u64::MAX, 1_000_000),
        (1234, 20_000, 8_000),
        (u64::MAX, u64::MAX, 0),
    ] {
        let mut generator = Lcg::new(seed);
        let mut window = Window::new(max_counter);
        let mut model = Model::new(max_counter);
        let mut anchor = base;
        let mut accepted = 0usize;
        let mut forward = 0usize; // 前进接受
        let mut older = 0usize; // 窗口内旧值接受
        let mut rejected = 0usize; // 重复 / 出窗 / 超上限拒绝
        for step in 0..6_000usize {
            let counter = match step % 5 {
                // 窗口内乱序：高于锚点但跳跃 < 8192。
                0 => anchor.saturating_add(generator.below(WINDOW - 1)),
                // 窗口内回看：低于锚点且距离 < 8192。
                1 => anchor.saturating_sub(generator.below(WINDOW - 1)),
                // 单调推进，模拟正常连续发包，同时前移锚点。
                2 => anchor.saturating_add(1),
                // 窗口边缘与略出窗：恰好 8191/8192/8193 的旧距离。
                3 => anchor.saturating_sub(WINDOW - 2 + generator.below(4)),
                // 大跨度跳跃或恰好压在注入上限附近。
                _ => {
                    if max_counter < u64::MAX && generator.below(4) == 0 {
                        max_counter.saturating_add(generator.below(2))
                    } else {
                        anchor.saturating_add(WINDOW + generator.below(64))
                    }
                }
            };
            let before = model.highest;
            let expected = model_accept(&mut model, counter);
            let actual = window.accept_authenticated(counter).is_ok();
            assert_eq!(
                actual, expected,
                "seed={seed} step={step} counter={counter}：实现与模型判定不一致"
            );
            assert_eq!(
                window.highest(),
                model.highest,
                "seed={seed} step={step} counter={counter}：最高计数器漂移"
            );
            // 拒绝时模型状态必须完全不变，借此同时核对实现的不变式。
            if !expected {
                assert_eq!(before, model.highest, "拒绝不得改变最高计数器");
            }
            if expected {
                accepted += 1;
                if before.is_some_and(|highest| counter > highest) {
                    forward += 1;
                } else {
                    older += 1;
                }
            } else {
                rejected += 1;
            }
            anchor = model.highest.unwrap_or(anchor);
        }
        if max_counter == u64::MAX {
            assert!(accepted > 3_000, "seed={seed} 接受覆盖不足：{accepted}");
            assert!(forward > 500, "seed={seed} 前进覆盖不足：{forward}");
            assert!(older > 500, "seed={seed} 乱序覆盖不足：{older}");
        } else {
            // 小上限会耗尽；耗尽后必须持续拒绝，而不是追求接受数量。
            assert!(accepted > 0);
            assert_eq!(window.highest(), Some(max_counter));
            assert!(window.accept_authenticated(max_counter + 1).is_err());
        }
        assert!(rejected > 500, "seed={seed} 拒绝覆盖不足：{rejected}");
        assert_eq!(window.max_counter(), max_counter);
        assert_eq!(
            window.highest(),
            model.highest,
            "seed={seed} 结束状态不一致"
        );
    }
}

#[test]
fn dense_in_window_sequence_matches_model() {
    // 0..=8191 全量收满，然后逐一重复：应全部判重，且与模型一致。
    let mut window = Window::new(u64::MAX);
    let mut model = Model::new(u64::MAX);
    for counter in 0..WINDOW {
        assert_eq!(
            window.accept_authenticated(counter).is_ok(),
            model_accept(&mut model, counter)
        );
    }
    for counter in 0..WINDOW {
        assert_eq!(
            window.accept_authenticated(counter).is_ok(),
            model_accept(&mut model, counter)
        );
        assert!(
            window.accept_authenticated(counter).is_err(),
            "满窗内必判重"
        );
    }
    // 满窗后再前进 1：最低位 0 出窗，模型与实现同样处理。
    assert_eq!(
        window.accept_authenticated(WINDOW).is_ok(),
        model_accept(&mut model, WINDOW)
    );
    assert_eq!(
        window.accept_authenticated(0),
        Err(ss_core::replay::Error::TooOld {
            counter: 0,
            highest: WINDOW
        }),
        "0 距新最高恰好 8192"
    );
}

#[test]
fn window_around_the_high_counter_edge_matches_model() {
    // 靠近 u64::MAX 的窗口，验证没有回绕导致接受不该接受的旧计数器。
    let highest = u64::MAX - 3;
    let mut window = Window::new(u64::MAX);
    let mut model = Model::new(u64::MAX);
    assert!(window.accept_authenticated(highest).is_ok());
    assert!(model_accept(&mut model, highest));
    for offset in 0..(WINDOW + 8) {
        let counter = highest - offset;
        let actual = window.accept_authenticated(counter).is_ok();
        let expected = model_accept(&mut model, counter);
        assert_eq!(actual, expected, "偏移 {offset} 判定不一致");
        assert_eq!(window.highest(), model.highest, "偏移 {offset} 最高漂移");
    }
}
