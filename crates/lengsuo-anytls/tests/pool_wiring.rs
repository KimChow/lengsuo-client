//! 空闲复用池**接线状态**的引用断言（w4-anytls-idlepool-verify 孤岛判定锁）。
//!
//! 机器判定（基线 7d018eab，2026-10-24）：
//! `grep -rn "client_pool::\|IdleSessionPool\|PoolError\|ClientPool" crates/lengsuo-anytls/src/`
//! 排除 `client_pool.rs`/`pool.rs` 自身后**零命中**：池实现存在、语义回归锁齐备
//! （`tests/pool.rs`、`tests/idle_pool/`），但客户端会话链路没有任何代码引用它。
//!
//! 为什么不接线（按卡规则「无法在不改语义前提下接线 ⇒ 不接线」）：
//! `src/` 只有**单连接**纯状态机 —— `ClientState` 对应一条 TLS 连接，
//! `Tunnel` ≈ 参考 `session.Session`；而参考池在**客户端级**（`Client` 与池
//! 一一对应，位于会话之上）。链路里不存在「先取空闲、未命中再新建」的复用点，
//! 只接注销点会让池只看到它从未登记过的会话；补出复用点等于新建客户端级
//! 运行时组合层，即改语义。故本卡**不接线**，把现状如实锁在这里：
//! 池组件可用；会话链路源文件不含池的代码引用。未来接线卡落地时，
//! 应同步更新本断言与 `docs/anytls-status.md` 的「空闲复用池」章节。
use lengsuo_anytls::client_pool::{ClientPool, PoolConfig, ReleaseOutcome};

/// 客户端会话链路源文件：接线状态断言的对象。
const CLIENT_CHAIN: &[(&str, &str)] = &[
    ("client_state.rs", include_str!("../src/client_state.rs")),
    ("tunnel.rs", include_str!("../src/tunnel.rs")),
];

/// 池的**代码**引用标记：类型名与带路径形式。`client_state.rs` 模块文档里的
/// 「[`crate::client_pool`]」是文档链接而非代码引用，不含这些标记。
const POOL_CODE_TOKENS: &[&str] = &[
    "ClientPool",
    "IdleSessionPool",
    "PoolError",
    "client_pool::",
];

#[test]
fn the_pool_component_exists_but_the_client_chain_does_not_reference_it() {
    // 组件层存在且可用：参考默认配置可构造，取用/归还闭环成立。
    let mut pool = ClientPool::new(PoolConfig::reference_defaults()).expect("合法配置");
    let acquired = pool.acquire(0).expect("取用");
    assert!(!acquired.reused, "空池首取必新建");
    assert_eq!(
        pool.release(acquired.session_id, 0),
        Ok(ReleaseOutcome::Pooled),
        "归还必须成功入池"
    );
    assert_eq!(pool.idle_len(), 1);

    // 会话链路不引用池：孤岛现状的回归锁（零命中的机器断言形式）。
    for (file, source) in CLIENT_CHAIN {
        for token in POOL_CODE_TOKENS {
            assert!(
                !source.contains(token),
                "{file} 不应引用池（token = {token}）：池实现存在、客户端链路未接线"
            );
        }
    }
}
