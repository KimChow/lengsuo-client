//! 空闲会话复用池的生命周期语义：命中复用、超时回收、最小保留数、
//! 容量上限（fail-closed）、关闭注销、禁用复用。
//!
//! 对齐参考 anytls-go `proxy/session/client.go`：
//! - `getIdleSession`：命中空闲会话 ⇒ 复用同一 `session.seq`；
//! - `idleCleanupExpTime`：超时回收，且保留 `minIdleSession` 条；
//! - 会话 `dieHook`：`idleSession.Remove` + 从会话表删除；
//! - `disableReuse`（`-dr`）：只新建，不入池。
//!
//! 用合成单调时钟（毫秒计数）驱动，**不与生产用的 `monotonic_ms()` 混用**。

use lengsuo_anytls::client_pool::{ClientPool, PoolConfig, ReleaseOutcome};

/// 合成时钟：从 0 起单调递增的毫秒计数。
struct Clock(u64);

impl Clock {
    fn now(&self) -> u64 {
        self.0
    }

    fn advance(&mut self, millis: u64) {
        self.0 += millis;
    }
}

/// 构造池配置。
///
/// 间隔与超时都取 6s：**大于 5s**，故不会被参考 `NewClient` 的
/// 「`<= 5s → 30s`」夹取规则改动，结算时刻可精确控制。
fn config(min_idle: usize, max_idle: u64) -> PoolConfig {
    PoolConfig {
        check_interval_ms: 6_000,
        idle_timeout_ms: 6_000,
        min_idle,
        max_idle,
        reuse: true,
    }
}

#[test]
fn releasing_a_session_makes_the_next_acquire_hit_the_same_session_id() {
    let mut pool = ClientPool::new(config(0, 4)).expect("合法配置");
    let clock = Clock(0);

    let first = pool.acquire(clock.now()).expect("取用");
    assert!(!first.reused, "空池取用必须新建会话");
    assert_eq!(first.session_id, 1, "会话编号自 1 起单调递增");

    assert_eq!(
        pool.release(first.session_id, clock.now()).expect("归还"),
        ReleaseOutcome::Pooled
    );
    assert_eq!(pool.idle_len(), 1, "归还后应有一条空闲会话");

    let second = pool.acquire(clock.now()).expect("取用");
    assert!(second.reused, "命中空闲池必须复用，不得新建");
    assert_eq!(
        second.session_id, first.session_id,
        "复用必须命中同一个 session_id"
    );
    assert_eq!(pool.idle_len(), 0, "取用后空闲池应为空");
}

#[test]
fn acquiring_without_a_release_creates_a_new_session() {
    let mut pool = ClientPool::new(config(0, 4)).expect("合法配置");
    let clock = Clock(0);

    let first = pool.acquire(clock.now()).expect("取用");
    let second = pool.acquire(clock.now()).expect("取用");

    assert!(!second.reused, "没有归还过就没有可命中的空闲会话");
    assert_ne!(second.session_id, first.session_id, "未命中必须新建会话");
    assert_eq!(pool.idle_len(), 0);
    assert_eq!(pool.registered_len(), 2, "两条会话都在册");
}

#[test]
fn an_expired_session_is_reclaimed_and_never_handed_out_again() {
    let mut pool = ClientPool::new(config(0, 4)).expect("合法配置");
    let mut clock = Clock(0);

    let acquired = pool.acquire(clock.now()).expect("取用");
    pool.release(acquired.session_id, clock.now())
        .expect("归还");

    // 尚未到期：结算不回收。
    assert!(pool.cleanup(clock.now()).expect("结算").is_empty());
    assert_eq!(pool.idle_len(), 1);

    // 推进到超时之后：结算回收。
    clock.advance(6_001);
    let reclaimed = pool.cleanup(clock.now()).expect("结算");
    assert_eq!(reclaimed, vec![acquired.session_id], "超时会话必须被回收");
    assert_eq!(pool.idle_len(), 0, "回收后池内不得残留空闲会话");

    // 回收后不能再被取用：只能拿到一条全新会话。
    let next = pool.acquire(clock.now()).expect("取用");
    assert!(!next.reused, "回收的会话不得复活");
    assert_ne!(next.session_id, acquired.session_id);
    assert!(!pool.contains(acquired.session_id), "被回收的会话必须注销");
}

#[test]
fn the_idle_count_never_drops_below_min_idle() {
    let mut pool = ClientPool::new(config(2, 8)).expect("合法配置");
    let mut clock = Clock(0);

    // 先取三条**互不相同**的会话（取用会命中空闲池，故必须先取完再归还），
    // 再一次性归还，才能凑够 min_idle 以上的空闲会话。
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(pool.acquire(clock.now()).expect("取用").session_id);
    }
    for session_id in &ids {
        pool.release(*session_id, clock.now()).expect("归还");
    }
    assert_eq!(pool.idle_len(), 3);

    // 全部超时：结算后至少保留 min_idle(2) 条，其余才回收。
    clock.advance(6_001);
    let reclaimed = pool.cleanup(clock.now()).expect("结算");

    assert_eq!(reclaimed.len(), 1, "超出 min_idle 的才回收");
    assert_eq!(
        pool.idle_len(),
        2,
        "空闲数不得降到 min_idle 以下：{}",
        pool.idle_len()
    );
}

#[test]
fn a_full_pool_refuses_extra_sessions_and_unregisters_them() {
    let mut pool = ClientPool::new(config(0, 1)).expect("合法配置");
    let clock = Clock(0);

    let kept = pool.acquire(clock.now()).expect("取用");
    let extra = pool.acquire(clock.now()).expect("取用");
    assert_eq!(
        pool.release(kept.session_id, clock.now()).expect("归还"),
        ReleaseOutcome::Pooled
    );

    // 池已满：拒绝多余会话，并把它注销（fail-closed：调用方必须关闭它）。
    assert_eq!(
        pool.release(extra.session_id, clock.now()).expect("归还"),
        ReleaseOutcome::PoolFull,
        "池满必须 fail-closed 拒绝多余会话"
    );
    assert_eq!(pool.idle_len(), 1, "池内只能有一条空闲会话");
    assert!(
        !pool.contains(extra.session_id),
        "被拒会话必须注销，不得留在登记表里"
    );

    // 被拒的会话不得被取用。
    let next = pool.acquire(clock.now()).expect("取用");
    assert_eq!(next.session_id, kept.session_id, "只能取用池内那条会话");
}

#[test]
fn closing_a_session_unregisters_it_whether_it_is_idle_or_not() {
    let mut pool = ClientPool::new(config(0, 4)).expect("合法配置");
    let clock = Clock(0);

    let idle = pool.acquire(clock.now()).expect("取用");
    pool.release(idle.session_id, clock.now()).expect("归还");
    assert!(
        pool.session_closed(idle.session_id),
        "关闭钩子应报告它在池中"
    );
    assert!(!pool.contains(idle.session_id), "关闭后必须注销");

    let busy = pool.acquire(clock.now()).expect("取用");
    assert!(
        !pool.session_closed(busy.session_id),
        "不在池中的会话关闭钩子返回 false"
    );
    assert!(!pool.contains(busy.session_id));
}

#[test]
fn disabling_reuse_closes_instead_of_pooling() {
    let mut pool = ClientPool::new(PoolConfig {
        reuse: false,
        ..config(0, 4)
    })
    .expect("合法配置");
    let clock = Clock(0);

    let acquired = pool.acquire(clock.now()).expect("取用");
    assert_eq!(
        pool.release(acquired.session_id, clock.now())
            .expect("归还"),
        ReleaseOutcome::ReuseDisabled,
        "禁用复用时只关闭、不入池"
    );
    assert_eq!(pool.idle_len(), 0, "禁用复用时池内不得有空闲会话");
    assert!(!pool.contains(acquired.session_id), "会话必须注销");

    let next = pool.acquire(clock.now()).expect("取用");
    assert!(!next.reused);
    assert_ne!(
        next.session_id, acquired.session_id,
        "禁用复用时每次都是新会话"
    );
}

#[test]
fn closing_the_pool_deregisters_every_session() {
    let mut pool = ClientPool::new(config(0, 4)).expect("合法配置");
    let clock = Clock(0);

    pool.acquire(clock.now()).expect("取用");
    pool.acquire(clock.now()).expect("取用");

    let closed = pool.close_all();
    assert_eq!(closed, vec![1, 2], "关闭必须返回全部会话编号");
    assert_eq!(pool.registered_len(), 0);
    assert_eq!(pool.idle_len(), 0);
}

#[test]
fn the_check_due_flag_follows_the_configured_interval() {
    let pool = ClientPool::new(config(0, 4)).expect("合法配置");
    let mut clock = Clock(0);

    assert!(pool.is_check_due(clock.now()), "首次结算总是到期");
    clock.advance(6_001);
    assert!(pool.is_check_due(clock.now()), "越过间隔后应再次到期");
    assert_eq!(pool.check_interval_ms(), 6_000);
    assert_eq!(pool.idle_timeout_ms(), 6_000);
    assert_eq!(pool.min_idle(), 0);
    assert_eq!(pool.max_idle(), 4);
}

#[test]
fn multiple_pooled_sessions_are_handed_out_lifo_like_the_reference() {
    let mut pool = ClientPool::new(config(0, 4)).expect("合法配置");
    let clock = Clock(0);

    // 取三条互不相同的会话（取用会命中空闲池，须先取完再归还），
    // 再按编号顺序 1、2、3 依次归还。
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(pool.acquire(clock.now()).expect("取用").session_id);
    }
    for session_id in &ids {
        pool.release(*session_id, clock.now()).expect("归还");
    }
    assert_eq!(pool.idle_len(), 3);

    // 参考 getIdleSession 取 SkipList 首元素（键 = MaxUint64 - seq）
    // ⇒ 最近归还者先被取用（LIFO），持有层 ClientPool 与池语义一致。
    assert_eq!(pool.acquire(clock.now()).expect("取用").session_id, ids[2]);
    assert_eq!(pool.acquire(clock.now()).expect("取用").session_id, ids[1]);
    assert_eq!(pool.acquire(clock.now()).expect("取用").session_id, ids[0]);
}

#[test]
fn an_invalid_configuration_is_refused() {
    assert!(
        ClientPool::new(config(4, 2)).is_err(),
        "min_idle 大于 max_idle 必须拒绝"
    );
    assert!(ClientPool::new(config(0, 0)).is_err(), "容量为零必须拒绝");
}
