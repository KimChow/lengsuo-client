//! 空闲会话复用池测试：纯内存、确定性时钟，不涉及任何连接或套接字。
//! 对齐 anytls-go `proxy/session/client.go` 的 `getIdleSession`（LIFO 取用）、
//! dieHook（关闭注销）、`idleCleanupExpTime`（minIdleSession 保留 + 超时回收）
//! 以及 `NewClient` 的间隔夹取。
use lengsuo_anytls::pool::{IdleSessionPool, PoolError};

/// 1000 个 10 ms 刻度：间隔/超时都大于 5s 下限，不会被参考规则夹取。
const TICK: u64 = 10;
/// 间隔 = 超时 = 10 秒（1000 个 TICK）。
fn pool(min: usize, max: u64) -> IdleSessionPool {
    IdleSessionPool::new(1000 * TICK, 1000 * TICK, min, max).expect("合法配置")
}

#[test]
fn intervals_at_or_below_five_seconds_are_clamped_like_reference() {
    let clamped = IdleSessionPool::new(5_000, 1, 0, 4).expect("合法配置");
    assert_eq!(clamped.check_interval_ms(), 30_000);
    assert_eq!(clamped.idle_timeout_ms(), 30_000);
    let kept = IdleSessionPool::new(30_001, 6_001, 0, 4).expect("合法配置");
    assert_eq!(kept.check_interval_ms(), 30_001);
    assert_eq!(kept.idle_timeout_ms(), 6_001);
}

#[test]
fn zero_capacity_or_min_above_max_is_rejected() {
    assert_eq!(
        IdleSessionPool::new(1000, 1000, 0, 0).err(),
        Some(PoolError::InvalidConfig)
    );
    assert_eq!(
        IdleSessionPool::new(1000, 1000, 3, 2).err(),
        Some(PoolError::InvalidConfig)
    );
}

#[test]
fn acquire_is_lifo_so_the_most_recently_returned_session_wins() {
    let mut pool = pool(0, 4);
    for id in 1..=3 {
        pool.register(id, 0).expect("登记");
        pool.release(id, 0).expect("归还");
    }
    assert_eq!(pool.idle_len(), 3);
    // 参考取 SkipList 的第一个元素（键 = MaxUint64 - seq），即 seq 最大者。
    assert_eq!(pool.acquire(0).expect("取用"), Some(3));
    assert_eq!(pool.acquire(0).expect("取用"), Some(2));
    assert_eq!(pool.acquire(0).expect("取用"), Some(1));
    assert_eq!(pool.acquire(0).expect("取用"), None);
}

#[test]
fn a_taken_session_is_no_longer_idle_and_can_be_returned_again() {
    let mut pool = pool(0, 4);
    pool.register(7, 0).expect("登记");
    pool.release(7, 0).expect("归还");
    assert_eq!(pool.acquire(0).expect("取用"), Some(7));
    assert_eq!(pool.idle_len(), 0);
    assert_eq!(
        pool.acquire(0).expect("再次取用"),
        None,
        "已取走的会话仍活跃"
    );
    assert!(pool.contains(7), "取用不注销登记");
    pool.release(7, 10).expect("再次归还");
    assert_eq!(pool.acquire(10).expect("取用"), Some(7));
}

#[test]
fn duplicate_release_and_release_of_unknown_session_are_rejected() {
    let mut pool = pool(0, 4);
    pool.register(1, 0).expect("登记");
    pool.release(1, 0).expect("首次归还");
    assert_eq!(pool.release(1, 0), Err(PoolError::AlreadyIdle));
    assert_eq!(pool.release(2, 0), Err(PoolError::Closed), "未登记");
    assert_eq!(pool.register(0, 0), Err(PoolError::UnknownSession));
}

#[test]
fn pool_capacity_is_enforced_and_full_pool_rejects_new_idle_sessions() {
    let mut pool = pool(0, 2);
    for id in 1..=2 {
        pool.register(id, 0).expect("登记");
        pool.release(id, 0).expect("归还");
    }
    pool.register(3, 0).expect("登记");
    assert_eq!(
        pool.release(3, 0),
        Err(PoolError::InvalidConfig),
        "池满时调用方应改为关闭该会话"
    );
    // 取走一条后即可放回。
    assert_eq!(pool.acquire(0).expect("取用"), Some(2));
    pool.release(3, 1).expect("腾出空位后可入池");
    assert_eq!(pool.idle_len(), 2);
}

#[test]
fn closed_sessions_are_removed_from_the_idle_pool_and_registry() {
    let mut pool = pool(0, 4);
    for id in 1..=2 {
        pool.register(id, 0).expect("登记");
        pool.release(id, 0).expect("归还");
    }
    assert!(pool.on_session_closed(1), "关闭时应报告该会话此前在池中");
    assert_eq!(pool.idle_len(), 1);
    assert!(!pool.contains(1));
    assert_eq!(pool.acquire(0).expect("取用"), Some(2), "跳过关闭的 1");
    assert!(!pool.on_session_closed(1), "重复关闭报告未在池中");
    assert_eq!(
        pool.register(1, 5),
        Err(PoolError::Closed),
        "已关闭的编号不得重新登记"
    );
}

#[test]
fn cleanup_reclaims_expired_sessions_beyond_min_idle() {
    let mut pool = pool(1, 8);
    for id in 1..=4 {
        pool.register(id, 0).expect("登记");
        pool.release(id, 0).expect("归还");
    }
    // 在 1000 个 TICK (=超时 10s) 之后再结算，四条全部过期；
    // 遍历顺序 1,2,3,4（栈底→栈顶），activeCount 从 0 起：
    // 第 1 条因 activeCount < minIdle(1) 被续期保留，其余 3 条回收。
    let reclaimed = pool.cleanup_expired(2000 * TICK).expect("结算");
    assert_eq!(reclaimed, vec![2, 3, 4]);
    assert_eq!(pool.idle_len(), 1, "保留 minIdle 条");
    assert_eq!(pool.reclaimed(), &[2, 3, 4]);
}

#[test]
fn cleanup_keeps_young_sessions_and_does_not_reclaim_them() {
    let mut pool = pool(0, 8);
    pool.register(1, 0).expect("登记");
    pool.release(1, 0).expect("归还");
    // 推进 5 个 TICK（远小于 10s 超时）：尚未过期，一条都不回收。
    assert_eq!(
        pool.cleanup_expired(5 * TICK).expect("结算"),
        Vec::<u64>::new()
    );
    assert_eq!(pool.idle_len(), 1);
}

#[test]
fn cleanup_respects_the_check_interval() {
    let mut pool = pool(0, 8);
    pool.register(1, 0).expect("登记");
    pool.release(1, 0).expect("归还");
    assert!(pool.is_check_due(0));
    let _ = pool.cleanup_expired(100_000).expect("首次结算");
    // 首次结算后 next_check = 100000 + 1000*TICK；未到点前不再结算。
    assert!(!pool.is_check_due(100_000 + 500 * TICK));
    assert_eq!(
        pool.cleanup_expired(100_000 + 500 * TICK).expect("未到点"),
        Vec::<u64>::new()
    );
    assert!(pool.is_check_due(100_000 + 1000 * TICK));
}

#[test]
fn clock_going_backwards_is_rejected_without_mutating_state() {
    let mut pool = pool(0, 4);
    pool.register(1, 5_000).expect("登记");
    assert_eq!(pool.acquire(4_000), Err(PoolError::NonMonotonic));
    assert_eq!(pool.acquire(5_000).expect("取用"), None);
}

#[test]
fn close_all_drains_registry_and_idle_pool() {
    let mut pool = pool(0, 8);
    for id in 1..=3 {
        pool.register(id, 0).expect("登记");
        pool.release(id, 0).expect("归还");
    }
    assert_eq!(pool.close_all(), vec![1, 2, 3]);
    assert_eq!(pool.idle_len(), 0);
    assert_eq!(pool.registered_len(), 0);
    assert_eq!(pool.acquire(0).expect("取用"), None);
}

#[test]
fn concurrent_style_take_and_return_never_leaks_a_session() {
    // 多流共享一条隧道：交替取用/归还，验证不会把同一条会话交给两方。
    let mut pool = pool(0, 4);
    pool.register(9, 0).expect("登记");
    pool.release(9, 0).expect("归还");
    let first = pool.acquire(0).expect("取用");
    let second = pool.acquire(0).expect("取用");
    assert_eq!(first, Some(9));
    assert_eq!(second, None, "同一空闲会话不得被取用两次");
    pool.release(9, 1).expect("归还");
    assert_eq!(pool.acquire(1).expect("取用"), Some(9));
}
