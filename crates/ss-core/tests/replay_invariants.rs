//! 重放拒绝、窗口移动及实例隔离不变式。
use ss_core::replay::{Error, Window};
const MAX: u64 = u64::MAX;

#[test]
fn max_counter_is_injected_limit_not_protocol_constant() {
    // 上限来自未来 key 生命周期策略；本 crate 不声称它是 WireGuard 固定阈值。
    let mut window = Window::new(99);
    assert_eq!(window.max_counter(), 99);
    assert_eq!(window.accept_authenticated(99), Ok(()));
    assert_eq!(
        window.accept_authenticated(100),
        Err(Error::ExceedsMaxCounter {
            counter: 100,
            max_counter: 99
        })
    );
    // 空窗口上第一包就超上限也拒绝。
    let mut window = Window::new(0);
    assert_eq!(
        window.accept_authenticated(1),
        Err(Error::ExceedsMaxCounter {
            counter: 1,
            max_counter: 0
        })
    );
    assert_eq!(window.accept_authenticated(0), Ok(()));
    // 超上限的检查优先于太旧/重复检查。
    let mut window = Window::new(50);
    assert_eq!(window.accept_authenticated(50), Ok(()));
    assert_eq!(window.accept_authenticated(0), Ok(()), "0 在窗口内且未收过");
    assert_eq!(
        window.accept_authenticated(60),
        Err(Error::ExceedsMaxCounter {
            counter: 60,
            max_counter: 50
        }),
        "上限检查优先"
    );
    assert_eq!(
        window.accept_authenticated(50),
        Err(Error::Duplicate { counter: 50 }),
        "上限拒绝不改变状态"
    );
}

#[test]
fn u64_boundaries_do_not_overflow() {
    // 最高接近 u64::MAX 时的减法与窗口判定。
    let mut window = Window::new(MAX);
    assert_eq!(window.accept_authenticated(MAX), Ok(()));
    assert_eq!(window.accept_authenticated(MAX - 8191), Ok(()));
    assert_eq!(
        window.accept_authenticated(MAX - 8192),
        Err(Error::TooOld {
            counter: MAX - 8192,
            highest: MAX
        })
    );
    assert_eq!(
        window.accept_authenticated(0),
        Err(Error::TooOld {
            counter: 0,
            highest: MAX
        }),
        "u64::MAX 到 0 的距离远大于窗口，不得回绕成允许"
    );
    // 已在上游检查 counter <= MAX，因此不存在更小的上限被绕过的情形。
    let mut window = Window::new(MAX);
    assert_eq!(window.accept_authenticated(0), Ok(()));
    assert_eq!(
        window.accept_authenticated(MAX),
        Ok(()),
        "从 0 跳到 u64::MAX"
    );
    assert_eq!(window.highest(), Some(MAX));
    assert_eq!(
        window.accept_authenticated(0),
        Err(Error::TooOld {
            counter: 0,
            highest: MAX
        }),
        "清空后旧窗口的 0 已远远出窗"
    );
    // 新窗口 [MAX-8191, MAX] 内未见过的计数器照常收下。
    assert_eq!(window.accept_authenticated(MAX - 1), Ok(()));
    assert_eq!(window.accept_authenticated(MAX - 8191), Ok(()));
    assert_eq!(
        window.accept_authenticated(MAX - 8192),
        Err(Error::TooOld {
            counter: MAX - 8192,
            highest: MAX
        })
    );
    // max_counter 恰为 u64::MAX 时不因上限拒绝。
    let mut window = Window::new(MAX);
    assert_eq!(window.accept_authenticated(MAX), Ok(()));
    // 饱和的 max_counter=0 情形：只有 0 可用。
    let mut window = Window::new(0);
    assert_eq!(window.accept_authenticated(0), Ok(()));
    assert_eq!(
        window.accept_authenticated(0),
        Err(Error::Duplicate { counter: 0 })
    );
}

#[test]
fn rejection_leaves_window_state_unchanged() {
    // 用一个窗口跑「干净序列」，另一个在同样的成功调用之间穿插必定失败的调用，
    // 最后对同一组探针必须给出完全一致的结果。
    let clean = [90_000u64, 90_100, 90_050];
    let mut baseline = Window::new(1_000_000);
    for counter in clean {
        assert_eq!(baseline.accept_authenticated(counter), Ok(()));
    }
    let mut polluted = Window::new(1_000_000);
    for counter in clean {
        assert_eq!(polluted.accept_authenticated(counter), Ok(()));
        // 三类拒绝各来一次：超上限、重复、太旧。
        assert!(polluted.accept_authenticated(1_000_001).is_err());
        assert!(polluted.accept_authenticated(counter).is_err());
        assert!(polluted.accept_authenticated(1).is_err());
    }
    let probes = [
        1u64,
        89_999,
        90_000,
        90_049,
        90_050,
        90_051,
        90_099,
        90_100,
        90_101,
        90_100 - 8192,
        91_000,
        1_000_000,
        1_000_001,
    ];
    let probe = |window: &mut Window| -> Vec<(u64, bool)> {
        probes
            .iter()
            .map(|counter| (*counter, window.accept_authenticated(*counter).is_ok()))
            .collect()
    };
    assert_eq!(probe(&mut baseline), probe(&mut polluted));
    assert_eq!(probe(&mut baseline.clone()), probe(&mut polluted.clone()));
}

#[test]
fn each_peer_and_key_epoch_uses_its_own_window() {
    // 两个 peer 的窗口互不影响。
    let mut peer_a = Window::new(MAX);
    let mut peer_b = Window::new(MAX);
    assert_eq!(peer_a.accept_authenticated(0), Ok(()));
    assert_eq!(
        peer_b.accept_authenticated(0),
        Ok(()),
        "另一 peer 的首包不受影响"
    );
    assert_eq!(
        peer_a.accept_authenticated(0),
        Err(Error::Duplicate { counter: 0 })
    );

    // 密钥轮换：新 epoch 必须是新建的窗口，不复用旧窗口，也不得共享已收位。
    let mut old_epoch = Window::new(MAX);
    assert_eq!(old_epoch.accept_authenticated(42), Ok(()));
    assert_eq!(
        old_epoch.accept_authenticated(42),
        Err(Error::Duplicate { counter: 42 })
    );
    let mut new_epoch = Window::new(MAX);
    assert_eq!(
        new_epoch.accept_authenticated(42),
        Ok(()),
        "新 key epoch 的窗口必须独立"
    );
    // 旧窗口仍保持旧 epoch 的历史，未被新窗口影响。
    assert_eq!(old_epoch.highest(), Some(42));
    assert_eq!(
        old_epoch.accept_authenticated(42),
        Err(Error::Duplicate { counter: 42 })
    );
    assert_eq!(new_epoch.highest(), Some(42));
}

#[test]
fn window_debug_does_not_dump_bitmap_or_counters_sequence() {
    let mut window = Window::new(MAX);
    assert_eq!(window.accept_authenticated(4096), Ok(()));
    assert_eq!(window.accept_authenticated(4095), Ok(()));
    let rendered = format!("{window:?}");
    assert!(rendered.contains("Window"), "{rendered}");
    assert!(rendered.contains("window_bits: 8192"), "{rendered}");
    // 位图内容不进 Debug，避免把流量时序细节带进日志。
    assert!(!rendered.contains("words"), "{rendered}");
    assert!(!rendered.contains("4095"), "{rendered}");
}

#[test]
fn contains_is_a_read_only_probe() {
    let mut window = Window::new(MAX);
    assert_eq!(window.accept_authenticated(10), Ok(()));
    for _ in 0..5 {
        assert!(window.contains(10));
        assert!(!window.contains(0));
        assert!(!window.contains(11));
        assert!(!window.contains(u64::MAX), "窗口外的远处地址不算已记录");
    }
    assert_eq!(window.highest(), Some(10));
    assert_eq!(
        window.accept_authenticated(10),
        Err(Error::Duplicate { counter: 10 })
    );
}
