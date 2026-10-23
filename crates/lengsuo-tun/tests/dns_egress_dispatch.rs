//! DNS 环境分流决策层测试：环境 → 登记上游 → 协议出口。
//!
//! # 性质（重要，勿误读）
//!
//! 本套件**不碰真实网卡、不建真实 socket、不做 DNS 互通**：出口运行时是内存假
//! 实现。证明的是决策层语义（目的地址只来自登记上游、会话隔离、换绑/撤绑/陈旧
//! 租约回收、失败不泄漏、任何 `Err` 都不转发），**不是**真机或真上游回程。
//!
//! 夹具在 [`support`]，与 `tests/egress_wiring/support.rs` 相互独立。

#[path = "dns_egress_dispatch/support.rs"]
mod support;

use lengsuo_tun::dns::dispatch::{DispatchError, DnsDispatcher};
use lengsuo_tun::egress::{DenyReason, OutboundProtocol};

use support::{
    attribution, key, key_to, selector, table, upstream, FixedAuthority, RecordingRuntime, DEVICE,
    ENV, ENV_B, NOW,
};

/// 一份任意 DNS 查询载荷（本层不解析内容，只要求逐字节投递）。
const QUERY: &[u8] =
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";

/// 一台默认设备 + 一个环境的标准布置。
fn setup(
    table_entries: &[(u64, std::net::SocketAddr)],
) -> DnsDispatcher<FixedAuthority, RecordingRuntime> {
    let authority = FixedAuthority::new().with_env(ENV, DEVICE, 1);
    let runtime = RecordingRuntime::with_device(DEVICE, OutboundProtocol::Trojan);
    DnsDispatcher::new(selector(authority, runtime, 16), table(table_entries))
}

fn dispatch(
    dispatcher: &mut DnsDispatcher<FixedAuthority, RecordingRuntime>,
    environment: u64,
    key: lengsuo_tun::session::SessionKey,
) -> Result<lengsuo_tun::egress::EgressHandle, DispatchError> {
    dispatcher.dispatch(
        environment,
        key,
        attribution(environment, DEVICE, 1),
        QUERY,
        NOW,
    )
}

#[test]
fn unbound_environment_sends_nothing_and_opens_no_session() {
    let mut dispatcher = setup(&[]);
    let error = dispatch(&mut dispatcher, ENV, key(40_001)).unwrap_err();
    assert!(matches!(error, DispatchError::UnboundEnvironment));
    let runtime = dispatcher.selector().runtime();
    assert!(runtime.opened.is_empty());
    assert!(runtime.forwarded.is_empty());
}

#[test]
fn bound_environment_dials_the_bound_upstream_only() {
    let mut dispatcher = setup(&[(ENV, upstream(5353))]);
    let handle = dispatch(&mut dispatcher, ENV, key(40_001)).expect("已登记环境应可分流");

    let runtime = dispatcher.selector().runtime();
    assert_eq!(
        runtime.opened,
        vec![(DEVICE, OutboundProtocol::Trojan, upstream(5353))]
    );
    assert_eq!(runtime.forwarded, vec![(handle.session.0, QUERY.to_vec())]);
}

#[test]
fn caller_supplied_key_destination_cannot_redirect_dns() {
    let mut dispatcher = setup(&[(ENV, upstream(5353))]);
    // 调用方把键的目的地址写成别的服务器：实际目的地址必须仍是登记上游。
    let conflicting = key_to(40_003, upstream(9));
    let handle = dispatch(&mut dispatcher, ENV, conflicting).expect("目的地址应被登记上游覆盖");

    let runtime = dispatcher.selector().runtime();
    assert_eq!(runtime.opened.len(), 1);
    assert_eq!(runtime.opened[0].2, upstream(5353));
    assert_eq!(runtime.forwarded, vec![(handle.session.0, QUERY.to_vec())]);
}

#[test]
fn attribution_environment_mismatch_is_rejected() {
    let mut dispatcher = setup(&[(ENV, upstream(5353))]);
    let error = dispatcher
        .dispatch(ENV, key(40_004), attribution(ENV_B, DEVICE, 1), QUERY, NOW)
        .unwrap_err();
    assert!(matches!(error, DispatchError::EnvironmentMismatch));
    let runtime = dispatcher.selector().runtime();
    assert!(runtime.opened.is_empty());
    assert!(runtime.forwarded.is_empty());
}

#[test]
fn same_key_two_environments_is_rejected_not_reused() {
    let authority = FixedAuthority::new()
        .with_env(ENV, DEVICE, 1)
        .with_env(ENV_B, DEVICE, 1);
    let runtime = RecordingRuntime::with_device(DEVICE, OutboundProtocol::Trojan);
    let mut dispatcher = DnsDispatcher::new(
        selector(authority, runtime, 16),
        table(&[(ENV, upstream(5353)), (ENV_B, upstream(5454))]),
    );

    let shared = key(40_005);
    let handle = dispatch(&mut dispatcher, ENV, shared).expect("环境 7 应成功");
    let error = dispatch(&mut dispatcher, ENV_B, shared).unwrap_err();
    assert!(matches!(error, DispatchError::KeyConflict));

    let runtime = dispatcher.selector().runtime();
    assert_eq!(runtime.opened.len(), 1, "不得为环境 8 另建连接");
    assert!(
        runtime.live.contains(&handle.session.0),
        "环境 7 的会话必须仍活着"
    );
    assert_eq!(runtime.forwarded.len(), 1);
}

#[test]
fn repeated_dispatch_same_env_reuses_session() {
    let mut dispatcher = setup(&[(ENV, upstream(5353))]);
    let first = dispatch(&mut dispatcher, ENV, key(40_006)).expect("第一次应成功");
    let second = dispatch(&mut dispatcher, ENV, key(40_006)).expect("第二次应复用");

    assert_eq!(first.session, second.session);
    let runtime = dispatcher.selector().runtime();
    assert_eq!(runtime.opened.len(), 1, "第二次必须命中 Reused，不得新建");
    assert_eq!(
        runtime.forwarded,
        vec![
            (first.session.0, QUERY.to_vec()),
            (first.session.0, QUERY.to_vec())
        ]
    );
}

#[test]
fn rebind_closes_old_session_and_next_dispatch_dials_new_upstream() {
    let mut dispatcher = setup(&[(ENV, upstream(5353))]);
    let old = dispatch(&mut dispatcher, ENV, key(40_007)).expect("首次应成功");
    let closed = dispatcher.rebind(ENV, upstream(5454));
    assert_eq!(closed, 1);

    {
        let runtime = dispatcher.selector().runtime();
        assert!(runtime.released.contains(&old.session.0));
        assert!(runtime.live.is_empty());
    }

    let new = dispatch(&mut dispatcher, ENV, key(40_007)).expect("换绑后应重拨");
    assert_ne!(new.session, old.session);
    let runtime = dispatcher.selector().runtime();
    assert_eq!(runtime.opened.len(), 2);
    assert_eq!(runtime.opened[1].2, upstream(5454));
}

#[test]
fn rebind_only_affects_target_environment() {
    let authority = FixedAuthority::new()
        .with_env(ENV, DEVICE, 1)
        .with_env(ENV_B, DEVICE, 1);
    let runtime = RecordingRuntime::with_device(DEVICE, OutboundProtocol::Trojan);
    let mut dispatcher = DnsDispatcher::new(
        selector(authority, runtime, 16),
        table(&[(ENV, upstream(5353)), (ENV_B, upstream(5454))]),
    );

    let seven = dispatch(&mut dispatcher, ENV, key(40_008)).expect("环境 7 应成功");
    let eight = dispatch(&mut dispatcher, ENV_B, key(40_009)).expect("环境 8 应成功");

    let closed = dispatcher.rebind(ENV, upstream(5555));
    assert_eq!(closed, 1);

    let runtime = dispatcher.selector().runtime();
    assert!(runtime.released.contains(&seven.session.0));
    assert!(
        !runtime.released.contains(&eight.session.0),
        "不得误伤环境 8"
    );
    assert!(
        runtime.live.contains(&eight.session.0),
        "环境 8 会话必须仍活着"
    );

    // 环境 8 再查询不应重拨（会话仍在）。
    dispatch(&mut dispatcher, ENV_B, key(40_009)).expect("环境 8 应继续复用");
    assert_eq!(dispatcher.selector().runtime().opened.len(), 2);
}

#[test]
fn unbind_closes_sessions_and_later_queries_fail_closed() {
    let mut dispatcher = setup(&[(ENV, upstream(5353))]);
    let handle = dispatch(&mut dispatcher, ENV, key(40_010)).expect("首次应成功");

    let closed = dispatcher.unbind(ENV);
    assert_eq!(closed, 1);
    assert!(dispatcher
        .selector()
        .runtime()
        .released
        .contains(&handle.session.0));

    let error = dispatch(&mut dispatcher, ENV, key(40_010)).unwrap_err();
    assert!(matches!(error, DispatchError::UnboundEnvironment));
    assert_eq!(
        dispatcher.selector().runtime().forwarded.len(),
        1,
        "撤绑后一条都不许外发"
    );
}

#[test]
fn stale_lease_closes_session_and_forces_redial() {
    let mut dispatcher = setup(&[(ENV, upstream(5353))]);
    let old = dispatch(&mut dispatcher, ENV, key(40_011)).expect("首次应成功");

    dispatcher.selector().authority().stale.set(true);
    let error = dispatch(&mut dispatcher, ENV, key(40_011)).unwrap_err();
    assert!(matches!(
        error,
        DispatchError::Denied(DenyReason::StaleLease)
    ));
    {
        let runtime = dispatcher.selector().runtime();
        assert!(runtime.released.contains(&old.session.0));
        assert!(runtime.live.is_empty());
    }
    assert_eq!(dispatcher.session_count(), 0);

    dispatcher.selector().authority().stale.set(false);
    let new = dispatch(&mut dispatcher, ENV, key(40_011)).expect("恢复后应重拨");
    assert_ne!(new.session, old.session);
    assert_eq!(dispatcher.selector().runtime().opened.len(), 2);
}

#[test]
fn protocol_unavailable_denies_without_forwarding() {
    let authority = FixedAuthority::new().with_env(ENV, DEVICE, 1);
    let runtime =
        RecordingRuntime::with_device(DEVICE, OutboundProtocol::Trojan).unavailable(DEVICE);
    let mut dispatcher = DnsDispatcher::new(
        selector(authority, runtime, 16),
        table(&[(ENV, upstream(5353))]),
    );

    let error = dispatch(&mut dispatcher, ENV, key(40_012)).unwrap_err();
    assert!(matches!(
        error,
        DispatchError::Denied(DenyReason::ProtocolUnavailable)
    ));
    let runtime = dispatcher.selector().runtime();
    assert!(runtime.forwarded.is_empty());
    assert!(runtime.opened.is_empty());
}

#[test]
fn dial_failure_denies_and_leaks_nothing() {
    let authority = FixedAuthority::new().with_env(ENV, DEVICE, 1);
    let runtime = RecordingRuntime::with_device(DEVICE, OutboundProtocol::Trojan).dial_fail(DEVICE);
    let mut dispatcher = DnsDispatcher::new(
        selector(authority, runtime, 16),
        table(&[(ENV, upstream(5353))]),
    );

    let error = dispatch(&mut dispatcher, ENV, key(40_016)).unwrap_err();
    assert!(matches!(
        error,
        DispatchError::Denied(DenyReason::DialFailed)
    ));
    let runtime = dispatcher.selector().runtime();
    assert!(runtime.forwarded.is_empty());
    assert!(runtime.live.is_empty());
    assert_eq!(dispatcher.session_count(), 0);
}

#[test]
fn forward_failure_closes_session_and_returns_error() {
    let mut dispatcher = setup(&[(ENV, upstream(5353))]);
    dispatcher.selector().runtime().fail_forward.set(true);

    let error = dispatch(&mut dispatcher, ENV, key(40_013)).unwrap_err();
    assert!(matches!(error, DispatchError::Forward(_)));
    {
        let runtime = dispatcher.selector().runtime();
        assert!(runtime.live.is_empty(), "失败会话必须被释放");
        assert_eq!(runtime.released.len(), 1);
        assert!(runtime.forwarded.is_empty());
    }
    assert_eq!(dispatcher.session_count(), 0);

    dispatcher.selector().runtime().fail_forward.set(false);
    dispatch(&mut dispatcher, ENV, key(40_013)).expect("恢复后应能重新建连");
    assert_eq!(dispatcher.selector().runtime().opened.len(), 2);
}

#[test]
fn capacity_full_denies_and_releases_new_session() {
    let authority = FixedAuthority::new().with_env(ENV, DEVICE, 1);
    let runtime = RecordingRuntime::with_device(DEVICE, OutboundProtocol::Trojan);
    let mut dispatcher = DnsDispatcher::new(
        selector(authority, runtime, 1),
        table(&[(ENV, upstream(5353))]),
    );

    let kept = dispatch(&mut dispatcher, ENV, key(40_014)).expect("第一条应成功");
    let error = dispatch(&mut dispatcher, ENV, key(40_015)).unwrap_err();
    assert!(matches!(error, DispatchError::Denied(DenyReason::Capacity)));

    let runtime = dispatcher.selector().runtime();
    assert_eq!(runtime.opened.len(), 2, "第二条确实尝试建连");
    assert_eq!(runtime.live.len(), 1, "刚建的出口必须被释放");
    assert!(runtime.live.contains(&kept.session.0));
    assert!(!runtime.released.contains(&kept.session.0));
}
