//! 回收驱动：有界定时器 + 池内结算，到期会话交给关闭回调。
//!
//! 对齐参考 anytls-go `proxy/session/client.go` 的
//! `util.StartRoutine(die, interval, c.idleCleanup)` —— 先等一个间隔再结算，
//! 结算后关闭超时会话（`session.Close()` ⇒ 会话 `dieHook` 注销）。
//!
//! ⚠️ 参考 `NewClient` 把 `<= 5s` 的间隔/超时一律拉回 30s，故这里取
//! `check_interval_ms = 6000`、`idle_timeout_ms = 5001`：两者都大于 5s，
//! 不会被夹取，结算时刻因此可预期。
//!
//! 驱动必须有超时上限、不得 busy-loop：既断言「到期前不回收」，也断言
//! 「回收后不重复回收」。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use lengsuo_anytls::client_pool::{monotonic_ms, spawn_cleanup_driver, ClientPool, PoolConfig};
use tokio::time::{sleep, timeout};

/// 驱动间隔（毫秒）：大于 5s ⇒ 不被参考的夹取规则改动。
const CHECK_INTERVAL_MS: u64 = 6_000;
/// 空闲超时（毫秒）：大于 5s ⇒ 不被夹取；比间隔短 ⇒ 首个结算点即到期。
const IDLE_TIMEOUT_MS: u64 = 5_001;

fn config() -> PoolConfig {
    PoolConfig {
        check_interval_ms: CHECK_INTERVAL_MS,
        idle_timeout_ms: IDLE_TIMEOUT_MS,
        min_idle: 0,
        max_idle: 4,
        reuse: true,
    }
}

/// 等待回调收集到至少 `count` 条，返回已收集的编号。
async fn wait_for_reclaimed(sink: &Arc<Mutex<Vec<u64>>>, count: usize) -> Vec<u64> {
    timeout(Duration::from_secs(30), async {
        loop {
            let ids = sink.lock().expect("锁").clone();
            if ids.len() >= count {
                return ids;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("驱动未在超时内回收会话")
}

#[tokio::test]
async fn the_driver_reclaims_expired_sessions_on_schedule_and_reports_each_one() {
    let pool = Arc::new(Mutex::new(ClientPool::new(config()).expect("合法配置")));
    let reclaimed: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&reclaimed);
    let handle = spawn_cleanup_driver(
        Arc::clone(&pool),
        Arc::new(move |session_id| sink.lock().expect("锁").push(session_id)),
    );

    // 登记并归还两条会话：此时开始计空闲超时。
    // 取用会命中空闲池，故必须**先取完再归还**，才能拿到两条互不相同的会话。
    let mut expected = Vec::new();
    {
        let mut guard = pool.lock().expect("锁");
        for _ in 0..2 {
            let acquired = guard.acquire(monotonic_ms()).expect("取用");
            expected.push(acquired.session_id);
        }
        for session_id in &expected {
            guard.release(*session_id, monotonic_ms()).expect("归还");
        }
    }
    assert_eq!(pool.lock().expect("锁").idle_len(), 2);

    // 间隔未到：不得提前回收（驱动不是 busy-loop，也不提前结算）。
    sleep(Duration::from_millis(500)).await;
    assert!(
        reclaimed.lock().expect("锁").is_empty(),
        "未到期不得回收会话"
    );

    // 到期后：驱动结算并把被回收的会话交给关闭回调。
    let ids = wait_for_reclaimed(&reclaimed, 2).await;
    assert_eq!(ids, expected, "被回收的会话编号必须交给关闭回调");

    // 回收即注销：被回收的会话不得留在登记表里，也不得再被取用。
    {
        let mut guard = pool.lock().expect("锁");
        assert_eq!(guard.idle_len(), 0, "回收后池内不得残留空闲会话");
        for session_id in &expected {
            assert!(
                !guard.contains(*session_id),
                "被回收的会话必须注销：{session_id}"
            );
        }
        let next = guard.acquire(monotonic_ms()).expect("取用");
        assert!(!next.reused, "回收的会话不得复活");
        assert!(
            !expected.contains(&next.session_id),
            "回收的会话不得再被取用"
        );
    }

    // 驱动不是 busy-loop：后续结算不得重复回收同一条会话。
    sleep(Duration::from_secs(1)).await;
    assert_eq!(
        reclaimed.lock().expect("锁").len(),
        2,
        "已回收的会话不得重复回收"
    );

    handle.abort();
}

/// 参考 `NewClient` 只在 `!disableReuse` 时 `util.StartRoutine(…, c.idleCleanup)`：
/// 禁用复用时驱动根本不启动，也就永远不会有会话被回收。
#[tokio::test]
async fn the_driver_does_not_run_when_reuse_is_disabled() {
    let pool = Arc::new(Mutex::new(
        ClientPool::new(PoolConfig {
            reuse: false,
            ..config()
        })
        .expect("合法配置"),
    ));
    let reclaimed: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&reclaimed);
    let handle = spawn_cleanup_driver(
        Arc::clone(&pool),
        Arc::new(move |session_id| sink.lock().expect("锁").push(session_id)),
    );

    // 驱动立即退出（不进入等待循环），因此不可能有回调。
    timeout(Duration::from_secs(5), handle)
        .await
        .expect("禁用复用时驱动应当立即结束")
        .expect("驱动任务不应 panic");

    assert!(
        reclaimed.lock().expect("锁").is_empty(),
        "禁用复用时不得回收任何会话"
    );
}
