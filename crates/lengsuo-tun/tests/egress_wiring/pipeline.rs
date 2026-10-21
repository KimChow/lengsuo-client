//! ingress 管道接入：整链跑通、出口拒绝计入出口错误。

use std::collections::VecDeque;
use std::time::Duration;

use lengsuo_tun::egress::{Attribution, OutboundProtocol};
use lengsuo_tun::ingress::{Ingress, SelectorSink};
use lengsuo_tun::packet::PacketInfo;

use super::support::{
    attribution, bound_router, selector, valid_packet, FakeRuntime, DEVICE, ENV, TIMEOUT,
};

/// 用例 9：接进既有 Ingress<D, C, E> 的 sink 侧（**不重写** ingress）
///
/// 内存假设备：队列里逐个吐出报文，空了返回超时。
struct FakeSource {
    queue: VecDeque<Vec<u8>>,
}

impl FakeSource {
    fn with(packets: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            queue: packets.into_iter().collect(),
        }
    }
}

impl lengsuo_tun::ingress::PacketSource for FakeSource {
    type Error = String;

    fn receive(
        &mut self,
        _timeout: Duration,
    ) -> Result<lengsuo_tun::ingress::Receipt, Self::Error> {
        let receipt = self.queue.pop_front();
        Ok(receipt.map_or(
            lengsuo_tun::ingress::Receipt::Timeout,
            lengsuo_tun::ingress::Receipt::Packet,
        ))
    }
}

/// 分类器：按固定脚本给出归因或「无归属」。
struct ScriptedClassifier {
    script: VecDeque<Option<Attribution>>,
}

impl lengsuo_tun::ingress::Classifier for ScriptedClassifier {
    type Attribution = Attribution;
    type Error = String;

    fn classify(&mut self, _info: &PacketInfo) -> Result<Option<Self::Attribution>, Self::Error> {
        Ok(self.script.pop_front().unwrap_or(None))
    }
}

/// 出口选择层作为 `Ingress` 的 sink：**设备 → 分类 → 选出口**整链跑通，统计口径分列。
#[tokio::test]
async fn selector_sink_plugs_into_existing_ingress_pipeline() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        let runtime = FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless);
        let selector = selector(router, runtime);
        let attribution = attribution(ENV, DEVICE, lease.epoch);

        let mut ingress = Ingress::new(
            FakeSource::with([valid_packet(), valid_packet()]),
            ScriptedClassifier {
                script: VecDeque::from([Some(attribution), None]),
            },
            SelectorSink::new(selector, || 1_000u64),
        );

        // 第一步：分类命中 → 选出出口 → 投递成功。
        let step = ingress.step(Duration::from_millis(1));
        assert_eq!(step, lengsuo_tun::ingress::Step::Delivered);

        // 第二步：分类无归属 ⇒ 出口层根本不会被调用。
        let step = ingress.step(Duration::from_millis(1));
        assert!(matches!(step, lengsuo_tun::ingress::Step::Denied { .. }));

        let stats = ingress.stats();
        assert_eq!(stats.received, 2);
        assert_eq!(stats.delivered, 1, "只有归因命中的那一包被投递");
        assert_eq!(stats.denied_no_attribution, 1, "无归属必须计入拒绝");
        assert_eq!(stats.egress_errors, 0, "无归属不是出口错误");

        // 出口层确实建立并使用了一条会话，且载荷已投递。
        let sink = ingress.sink();
        assert_eq!(sink.selector().session_count(), 1);
        assert_eq!(sink.selector().runtime().opens, 1);
        let forwarded = &sink.selector().runtime().forwarded;
        assert_eq!(forwarded.len(), 1, "应有一条会话收到过载荷");
        assert_eq!(forwarded.values().next().map(Vec::len), Some(1));
    })
    .await
    .expect("用例超时");
}

/// 出口层拒绝（协议不可用）⇒ 计入 ingress 的 `egress_errors`，与「未归属」分列。
#[tokio::test]
async fn selector_denial_is_counted_as_egress_error_not_unattributed() {
    tokio::time::timeout(TIMEOUT, async {
        let (router, lease) = bound_router(ENV, DEVICE);
        // 协议不可用 ⇒ 出口层拒绝。
        let runtime =
            FakeRuntime::with_protocol(DEVICE, OutboundProtocol::Vless).unavailable(DEVICE);
        let selector = selector(router, runtime);
        let attribution = attribution(ENV, DEVICE, lease.epoch);

        let mut ingress = Ingress::new(
            FakeSource::with([valid_packet()]),
            ScriptedClassifier {
                script: VecDeque::from([Some(attribution)]),
            },
            SelectorSink::new(selector, || 1_000u64),
        );

        let step = ingress.step(Duration::from_millis(1));
        assert!(
            matches!(step, lengsuo_tun::ingress::Step::EgressFailed { .. }),
            "出口层拒绝应表现为出口失败：{step:?}"
        );

        let stats = ingress.stats();
        assert_eq!(stats.received, 1);
        assert_eq!(stats.delivered, 0, "拒绝不得投递");
        assert_eq!(stats.egress_errors, 1, "拒绝计入出口错误");
        assert_eq!(
            stats.denied_no_attribution, 0,
            "有归因但出口拒绝，不算未归属"
        );
    })
    .await
    .expect("用例超时");
}
