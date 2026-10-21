//! 会话与租约：复用同一出口 / 关闭释放 / 过期 GC / 无路由拒绝。

use lengsuo_tun::egress::{DenyReason, EgressSelector, OutboundProtocol};
use lengsuo_tun::session::SessionKey;

use super::support::{
    attribution, bound_router, info_of, select, selector, valid_packet, FakeRuntime, DEVICE, ENV,
    TIMEOUT, TTL,
};

/// 用例 6：同一会话键重复选路 ⇒ 复用同一出口句柄（**不重复建连**）。
#[tokio::test]
async fn repeated_selection_reuses_same_outbound() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let mut selector = selector(router, runtime);

        let info = info_of(&valid_packet());
        let key = SessionKey::from_info(info);
        let attribution = attribution(ENV, DEVICE, lease.epoch);

        let first = selector.select(&info, key, attribution, 1_000);
        let second = selector.select(&info, key, attribution, 1_001);
        let third = selector.select(&info, key, attribution, 1_002);

        let first_handle = first.handle().expect("首次应选中");
        assert_eq!(second.handle(), Some(first_handle), "必须复用同一出口句柄");
        assert_eq!(third.handle(), Some(first_handle));
        assert_eq!(selector.runtime().opens, 1, "不得重复建连");
        assert_eq!(selector.session_count(), 1, "会话表只应有一条条目");
    })
    .await
    .expect("用例超时");
}

/// 用例 7：关闭会话 ⇒ 出口被释放、运行时无残留会话（**不泄漏**）。
#[tokio::test]
async fn closing_session_releases_outbound() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let mut selector = selector(router, runtime);

        let info = info_of(&valid_packet());
        let key = SessionKey::from_info(info);
        let handle = select(&mut selector, lease.epoch, 1_000)
            .handle()
            .expect("应选中出口");
        assert_eq!(selector.runtime().live_count(), 1, "建连后有一条活会话");

        let closed = selector.close(key).expect("关闭应返回句柄");
        assert_eq!(closed, handle, "释放的应是那条出口");
        assert_eq!(selector.session_count(), 0, "会话表应已清空");
        assert_eq!(
            selector.runtime().live_count(),
            0,
            "出口必须被释放，不得泄漏"
        );
        assert_eq!(selector.runtime().released, vec![handle.session.0]);
    })
    .await
    .expect("用例超时");
}

/// 会话过期（TTL 到点）⇒ `gc` 释放出口，不泄漏。
#[tokio::test]
async fn expired_sessions_are_released_on_gc() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let mut selector = selector(router, runtime);

        assert!(select(&mut selector, lease.epoch, 1_000).handle().is_some());
        assert_eq!(selector.runtime().live_count(), 1);

        // 时钟推进过 TTL ⇒ 条目过期，gc 必须释放其出口。
        let reclaimed = selector.gc(1_000 + TTL + 1);
        assert_eq!(reclaimed, 1, "应回收一条过期会话");
        assert_eq!(selector.session_count(), 0);
        assert_eq!(
            selector.runtime().live_count(),
            0,
            "过期会话的出口必须被释放"
        );
    })
    .await
    .expect("用例超时");
}

/// 用例 8：路由表没覆盖目的地址 ⇒ 拒绝；**不走默认路由、不回落直连**。
#[tokio::test]
async fn missing_route_is_denied() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        // 空路由表：任何目的地址都查不到出接口。
        let mut selector = EgressSelector::new(
            super::support::RealAuthority::new(router),
            runtime,
            lengsuo_tun::tcp::connector::RouteTable::new(),
            16,
            TTL,
        );

        let decision = select(&mut selector, lease.epoch, 1_000);
        assert_eq!(decision.deny_reason(), Some(DenyReason::NoRoute));
        assert_eq!(decision.handle(), None);
        assert_eq!(selector.runtime().opens, 0, "无出接口不得建连");
    })
    .await
    .expect("用例超时");
}
