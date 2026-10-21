//! 选路与归属：归因命中 / 无归属 / 设备离线 / 协议不可用 / 换绑失效。

use std::net::IpAddr;

use lengsuo_environment::{DeviceId as EnvDeviceId, EnvironmentId as EnvEnvironmentId};
use lengsuo_tun::egress::{DenyReason, OutboundProtocol};
use lengsuo_tun::ingress::{EgressSink, SelectorSink};
use lengsuo_tun::session::SessionKey;

use super::support::{
    attribution, bound_router, info_of, packet_with_source_port, select, selector, valid_packet,
    ATTRIBUTION_MISSING, DEVICE, ENV, TIMEOUT,
};

/// 用例 1：正常路径——包归因到环境 A ⇒ 选中环境 A 的协议出口
///
/// 归因到环境 A ⇒ 选中环境 A 的出口：断言句柄（协议/设备/代次/出接口）与 reason。
#[tokio::test]
async fn attributed_packet_selects_that_environments_outbound() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = super::support::FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let mut selector = selector(router, runtime);

        let decision = select(&mut selector, lease.epoch, 1_000);
        let handle = decision.handle().expect("应选中出口");
        assert_eq!(decision.deny_reason(), None);
        assert_eq!(handle.binding.environment.0, ENV, "命中的环境");
        assert_eq!(handle.binding.device.0, DEVICE, "命中的设备");
        assert_eq!(handle.binding.epoch, lease.epoch, "命中的代次");
        assert_eq!(handle.protocol, OutboundProtocol::Vless, "选中的协议出口");
        assert_eq!(handle.interface_index, 7, "出接口由路由表选定");
        assert_eq!(handle.source, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(selector.session_count(), 1, "应持有一条出口会话");
    })
    .await
    .expect("用例超时");
}

/// 用例 2：归因不到环境 ⇒ 拒绝（**不得**回落到默认直连）；断言无出口、无建连、无直连。
#[tokio::test]
async fn unattributed_packet_is_denied_not_sent_direct() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, _lease) = bound_router(ENV, DEVICE);
        let runtime = super::support::FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let selector = selector(router, runtime);

        let packet = valid_packet();
        let info = info_of(&packet);
        let key = SessionKey::from_info(info);

        // 归因缺席：走 ingress 的 sink 侧——分类器返回 Ok(None) 时根本不进出口层。
        let mut sink = SelectorSink::new(selector, || 1_000u64);
        assert!(sink.deliver(&packet, &info, ATTRIBUTION_MISSING).is_err());

        // 直接问选择层：即便硬塞一个不存在的环境，也必须拒绝而不是直连。
        let decision = sink
            .selector_mut()
            .select(&info, key, attribution(999, DEVICE, 1), 1_000);
        assert_eq!(decision.deny_reason(), Some(DenyReason::UnknownEnvironment));
        assert_eq!(decision.handle(), None, "拒绝不得给出出口句柄");
        assert_eq!(sink.selector().session_count(), 0, "拒绝不得留下会话");
        assert_eq!(sink.selector().runtime().live_count(), 0, "拒绝不得建连");
    })
    .await
    .expect("用例超时");
}

/// 用例 3：设备下线后其绑定立即失效 ⇒ 拒绝；不得改走别的出口。
#[tokio::test]
async fn offline_device_is_denied() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = super::support::FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let mut selector = selector(router, runtime);

        // 先成功选一次，确认正常路径可用。
        assert!(select(&mut selector, lease.epoch, 1_000).handle().is_some());

        // 设备离线：权威路由撤销该设备名下的全部绑定。
        selector
            .authority_mut()
            .set_online(EnvDeviceId(DEVICE), false);

        // 新会话键（换源端口）⇒ 必须因设备离线被拒。
        let other = packet_with_source_port(40_001);
        let other_info = info_of(&other);
        let decision = selector.select(
            &other_info,
            SessionKey::from_info(other_info),
            attribution(ENV, DEVICE, lease.epoch),
            2_000,
        );
        assert_eq!(decision.deny_reason(), Some(DenyReason::UnknownEnvironment));
        assert_eq!(decision.handle(), None);
    })
    .await
    .expect("用例超时");
}

/// 用例 4：协议出口不可用 ⇒ 拒绝（**不静默降级**）；断言没有改用任何其它协议。
#[tokio::test]
async fn unavailable_protocol_is_denied_without_fallback() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        // 设备 70 配的是 vless，但此刻不可用（设备 71 配的是 trojan 且可用）。
        let runtime = super::support::FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless)
            .unavailable(DEVICE);
        let mut selector = selector(router, runtime);

        let decision = select(&mut selector, lease.epoch, 1_000);
        assert_eq!(
            decision.deny_reason(),
            Some(DenyReason::ProtocolUnavailable)
        );
        assert_eq!(decision.handle(), None, "不得给出任何出口句柄");
        assert_eq!(selector.session_count(), 0, "不得留下会话");
        assert_eq!(selector.runtime().opens, 0, "不得建连，更不得改用别的协议");
    })
    .await
    .expect("用例超时");
}

/// 设备**未配置任何协议** ⇒ 同样拒绝（不回落到直连，也不换协议）。
#[tokio::test]
async fn device_without_protocol_is_denied() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = super::support::FakeRuntime::default(); // 没有任何设备配置协议
        let mut selector = selector(router, runtime);

        let decision = select(&mut selector, lease.epoch, 1_000);
        assert_eq!(
            decision.deny_reason(),
            Some(DenyReason::ProtocolUnavailable)
        );
        assert_eq!(selector.runtime().opens, 0);
    })
    .await
    .expect("用例超时");
}

/// 用例 5：换绑（代次推进）后旧租约失效 ⇒ 复用路径必须拒绝，不得继续用旧出口。
#[tokio::test]
async fn stale_lease_is_denied_and_not_reused() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = super::support::FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let mut selector = selector(router, runtime);

        let info = info_of(&valid_packet());
        let key = SessionKey::from_info(info);

        // 第一次选中并建连。
        assert!(select(&mut selector, lease.epoch, 1_000).handle().is_some());
        assert_eq!(selector.runtime().opens, 1);

        // 换绑：同一环境改绑到另一台在线设备 ⇒ 代次推进，旧租约失效。
        selector.authority_mut().set_online(EnvDeviceId(71), true);
        let new_epoch = selector
            .authority_mut()
            .rebind(EnvEnvironmentId(ENV), EnvDeviceId(71));
        assert!(new_epoch > lease.epoch, "换绑必须推进代次，旧租约因此失效");

        // 同一会话键再选：旧租约已失效 ⇒ 拒绝，**不得**复用旧出口。
        let decision = selector.select(&info, key, attribution(ENV, DEVICE, lease.epoch), 2_000);
        assert_eq!(decision.deny_reason(), Some(DenyReason::StaleLease));
        assert_eq!(decision.handle(), None, "不得复用失效租约对应的旧出口");
        assert_eq!(selector.runtime().opens, 1, "拒绝时不得新建连接");
    })
    .await
    .expect("用例超时");
}

/// 归因的代次落后于权威绑定 ⇒ 拒绝（换绑前的旧归因不得继续用）。
#[tokio::test]
async fn stale_attribution_is_denied() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = super::support::FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let mut selector = selector(router, runtime);

        // 换绑推进代次。
        selector.authority_mut().set_online(EnvDeviceId(71), true);
        selector
            .authority_mut()
            .rebind(EnvEnvironmentId(ENV), EnvDeviceId(71));

        let decision = select(&mut selector, lease.epoch, 1_000);
        assert_eq!(decision.deny_reason(), Some(DenyReason::StaleAttribution));
        assert_eq!(selector.runtime().opens, 0, "拒绝不得建连");
    })
    .await
    .expect("用例超时");
}
