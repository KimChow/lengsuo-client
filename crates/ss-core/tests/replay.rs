//! 重放窗口边界测试：初包、乱序、重复、8191/8192 边界、大跳跃、u64 边界、
//! 拒绝后状态不变，以及每个 peer/key epoch 独占窗口。
//! 这些测试只覆盖纯内存窗口，不代表 MAC 校验或任何真实对端行为。
use ss_core::replay::{Error, Window, WINDOW_BITS};

const MAX: u64 = u64::MAX;

#[test]
fn window_bits_is_the_contracted_8192() {
    assert_eq!(WINDOW_BITS, 8192);
}

#[test]
fn fresh_window_accepts_counter_zero_first() {
    let mut window = Window::new(MAX);
    assert_eq!(window.highest(), None);
    assert_eq!(window.accept_authenticated(0), Ok(()));
    assert_eq!(window.highest(), Some(0));
    assert_eq!(
        window.accept_authenticated(0),
        Err(Error::Duplicate { counter: 0 })
    );
    assert_eq!(window.accept_authenticated(1), Ok(()));
    assert_eq!(window.highest(), Some(1));
}

#[test]
fn fresh_window_can_start_at_any_in_range_counter() {
    // 首包不要求从 0 开始：空窗口直接以该计数器起窗。
    for first in [1u64, 7, 8191, 8192, 123_456_789] {
        let mut window = Window::new(MAX);
        assert_eq!(window.accept_authenticated(first), Ok(()), "首包 {first}");
        assert_eq!(window.highest(), Some(first));
        assert_eq!(
            window.accept_authenticated(first),
            Err(Error::Duplicate { counter: first })
        );
    }
}

#[test]
fn unordered_but_unseen_counters_inside_window_are_accepted() {
    let mut window = Window::new(MAX);
    let received = [5u64, 9, 3, 1, 8, 0, 4];
    for counter in received {
        assert_eq!(
            window.accept_authenticated(counter),
            Ok(()),
            "乱序 {counter}"
        );
    }
    assert_eq!(window.highest(), Some(9));
    // 已收过的逐一判重；未收过且仍在窗口内的（2、6、7）照常接受。
    for counter in received {
        assert_eq!(
            window.accept_authenticated(counter),
            Err(Error::Duplicate { counter }),
            "已收下 {counter} 必须判重"
        );
    }
    for counter in [2u64, 6, 7] {
        assert_eq!(
            window.accept_authenticated(counter),
            Ok(()),
            "{counter} 未收过且在窗口内"
        );
    }
    // 现在 0..=9 全部收过。
    for counter in 0..=9 {
        assert_eq!(
            window.accept_authenticated(counter),
            Err(Error::Duplicate { counter })
        );
    }
}

#[test]
fn boundary_delta_8191_older_accepted_8192_rejected() {
    let highest = 20_000u64;
    let mut window = Window::new(MAX);
    assert_eq!(window.accept_authenticated(highest), Ok(()));
    // 距最高 8191：仍在 8192 位窗口内。
    assert_eq!(window.accept_authenticated(highest - 8191), Ok(()));
    // 距最高 8192：出窗，拒绝。
    assert_eq!(
        window.accept_authenticated(highest - 8192),
        Err(Error::TooOld {
            counter: highest - 8192,
            highest
        })
    );
    // 出窗的计数器之后重复尝试仍是 TooOld（不会因窗口变化被放行）。
    assert_eq!(
        window.accept_authenticated(highest - 8192),
        Err(Error::TooOld {
            counter: highest - 8192,
            highest
        })
    );
    assert!(window.contains(highest - 8191));
    assert!(!window.contains(highest - 8192));
}

#[test]
fn forward_8191_keeps_history_forward_8192_clears_window() {
    // 前进 8191：位图整体移位，相对距离保留。旧最高 10 与新最高 8201 相距
    // 恰好 8191，仍落在窗口边缘，必须继续判重而不是放行。
    let mut window = Window::new(MAX);
    assert_eq!(window.accept_authenticated(10), Ok(()));
    assert_eq!(window.accept_authenticated(5), Ok(()));
    assert_eq!(window.accept_authenticated(10 + 8191), Ok(()));
    assert_eq!(
        window.accept_authenticated(10),
        Err(Error::Duplicate { counter: 10 }),
        "位移 8191 后窗口边缘的 10 必须仍判重"
    );
    // 5 距新最高 8196，已随移位出窗：按太旧拒绝。
    assert_eq!(
        window.accept_authenticated(5),
        Err(Error::TooOld {
            counter: 5,
            highest: 10 + 8191
        })
    );
    // 窗口 [10, 8201] 内未见过的计数器照常收下。
    assert_eq!(
        window.accept_authenticated(11),
        Ok(()),
        "11 未收过且在窗口内"
    );
    assert_eq!(
        window.accept_authenticated(10 + 8191 - 8192),
        Err(Error::TooOld {
            counter: 10 + 8191 - 8192,
            highest: 10 + 8191
        }),
        "窗口下沿之外"
    );
    assert_eq!(window.highest(), Some(10 + 8191));

    // 前进恰好 8192：位图清空。清空是无损的——旧已收计数器与新最高的距离
    // 本身就 >= 8192，全部落在新窗口之外，因此一律按太旧拒绝，不会被放行。
    let mut window = Window::new(MAX);
    assert_eq!(window.accept_authenticated(0), Ok(()));
    assert_eq!(window.accept_authenticated(1), Ok(()));
    assert_eq!(window.accept_authenticated(4096), Ok(()));
    assert_eq!(window.accept_authenticated(4096 + 8192), Ok(()));
    let highest = 4096 + 8192;
    assert_eq!(window.highest(), Some(highest));
    for counter in [0u64, 1, 4096] {
        assert_eq!(
            window.accept_authenticated(counter),
            Err(Error::TooOld { counter, highest }),
            "跳跃 8192 后旧计数器 {counter} 出窗，不得被重新接受"
        );
    }
    // 新窗口内未见过的计数器仍可收下，重复则判重。
    assert_eq!(window.accept_authenticated(highest - 8191), Ok(()));
    assert_eq!(
        window.accept_authenticated(highest - 8191),
        Err(Error::Duplicate {
            counter: highest - 8191
        })
    );
    assert_eq!(
        window.accept_authenticated(highest - 8192),
        Err(Error::TooOld {
            counter: highest - 8192,
            highest
        }),
        "窗口下沿之外"
    );
}

#[test]
fn larger_forward_jumps_leave_only_the_new_highest_remembered() {
    for jump in [8192u64, 8193, 100_000, 1 << 32] {
        let mut window = Window::new(MAX);
        assert_eq!(window.accept_authenticated(3), Ok(()));
        assert_eq!(window.accept_authenticated(7), Ok(()));
        let target = 7 + jump;
        assert_eq!(
            window.accept_authenticated(target),
            Ok(()),
            "跳跃到 {target}"
        );
        assert_eq!(window.highest(), Some(target));
        // 跳跃 >= 8192 后，旧窗口整体出窗：旧计数器按太旧拒绝。
        for counter in [3u64, 7] {
            assert_eq!(
                window.accept_authenticated(counter),
                Err(Error::TooOld {
                    counter,
                    highest: target
                }),
                "跳跃 {jump} 后 {counter} 出窗"
            );
        }
        // 新窗口 [target-8191, target] 内的未见计数器正常收下。
        assert_eq!(window.accept_authenticated(target - 8191), Ok(()));
        assert_eq!(window.accept_authenticated(target - 1), Ok(()));
        assert_eq!(
            window.accept_authenticated(target - 8192),
            Err(Error::TooOld {
                counter: target - 8192,
                highest: target
            })
        );
        assert_eq!(
            window.accept_authenticated(target),
            Err(Error::Duplicate { counter: target })
        );
    }
}
