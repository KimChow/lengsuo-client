//! UDP 会话池（`crate::udp_pool`）用例：复用、回收、上界、cone 与并发。
//!
//! 观测面纪律：**不用「没报错」当通过**。每条用例都用独立观测面断言：
//! - 服务端侧**收包计数**（证明确实是同一个 socket / 不同 socket）；
//! - 回程**内容**逐字节比对（证明不串包）；
//! - 池的 `live_sockets` / `entry_count` 计数（证明条目真被回收）。
//!
//! 参考语义基线：Xray v26.3.27（`d2758a0`）`proxy/trojan/server.go:247-320`
//! 的 `handleUDPPayload` 与 `transport/internet/udp/dispatcher.go`。

mod udp_pool_support;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use lengsuo_trojan::udp_pool::UdpPool;
use tokio::time::timeout;
use udp_pool_support::{config, recv_reply, v4, Echo, WAIT};

const TOTAL: Duration = Duration::from_secs(30);

/// ① 同目标多包复用**同一 socket**：服务端侧只见到一个源地址。
#[tokio::test]
async fn same_target_reuses_one_socket() {
    timeout(TOTAL, async {
        let echo = Echo::spawn().await;
        let pool = UdpPool::new(config()).unwrap();

        for index in 0u8..3 {
            let payload = [index; 16];
            let dispatch = pool.dispatch(&v4(echo.port), &payload).await.unwrap();
            if index == 0 {
                assert!(!dispatch.reused, "首个包必须新建 socket");
            } else {
                assert!(dispatch.reused, "同目标的第 {index} 包必须复用同一 socket");
            }
            let (addr, reply) = recv_reply(&pool).await;
            assert_eq!(addr, v4(echo.port), "回程地址须与请求一致");
            assert_eq!(reply, payload, "回程须逐字节一致");
        }
        let again = pool.dispatch(&v4(echo.port), b"again").await.unwrap();
        assert!(again.reused, "同目标的第二个包必须复用同一 socket");
        let (_addr, reply) = recv_reply(&pool).await;
        assert_eq!(reply, b"again");

        // 独立观测面：服务端只见到**一个**源地址 ⇒ 确实只有一个出站 socket。
        assert_eq!(
            echo.peers.load(Ordering::SeqCst),
            1,
            "服务端只应见到一个源地址"
        );
        assert_eq!(echo.total.load(Ordering::SeqCst), 4, "服务端应收到四个包");
        assert_eq!(echo.counts(), &[4], "四个包应来自同一个源地址");
        assert_eq!(pool.entry_count(), 1, "池内只应有一个条目");
        assert_eq!(pool.created_sockets(), 1, "只应建立一个出站 socket");
    })
    .await
    .unwrap();
}

/// ② 不同目标 ⇒ 不同 socket，且各自回程不串。
#[tokio::test]
async fn distinct_targets_use_distinct_sockets_without_cross_talk() {
    timeout(TOTAL, async {
        let first = Echo::spawn().await;
        let second = Echo::spawn().await;
        let pool = UdpPool::new(config()).unwrap();

        pool.dispatch(&v4(first.port), b"alpha").await.unwrap();
        pool.dispatch(&v4(second.port), b"beta").await.unwrap();

        let (addr_a, reply_a) = recv_reply(&pool).await;
        let (addr_b, reply_b) = recv_reply(&pool).await;
        // 两个回程分别对应各自的目标，且载荷内容对得上（不串包）。
        let mut pairs = [(addr_a, reply_a), (addr_b, reply_b)];
        pairs.sort_by_key(|(addr, _)| match addr {
            lengsuo_trojan::TargetAddr::V4(_, port) => u32::from(*port),
            _ => u32::MAX,
        });
        let lower = pairs[0].0.clone();
        let upper = pairs[1].0.clone();
        let (first_addr, second_addr) = if lower == v4(first.port) {
            (lower, upper)
        } else {
            (upper, lower)
        };
        assert_eq!(first_addr, v4(first.port), "较小的端口须属于先建的后端");
        assert_eq!(second_addr, v4(second.port));
        let mut payloads = vec![pairs[0].1.clone(), pairs[1].1.clone()];
        payloads.sort();
        assert_eq!(payloads, &[b"alpha".to_vec(), b"beta".to_vec()]);

        assert_eq!(pool.entry_count(), 2, "两个目标 ⇒ 两个条目");
        assert_eq!(pool.created_sockets(), 2, "两个目标 ⇒ 两个出站 socket");
        assert_eq!(pool.live_sockets(), 2, "两个出站 socket 都应存活");
        // 服务端侧：两个后端各只见一个源地址。
        assert_eq!(first.peers.load(Ordering::SeqCst), 1);
        assert_eq!(second.peers.load(Ordering::SeqCst), 1);
    })
    .await
    .unwrap();
}

/// ③ cone 模式：首包目标 A，后续包目标 B ⇒ **都发往 A**（参考语义，非错包）。
#[tokio::test]
async fn cone_mode_pins_first_packet_destination() {
    timeout(TOTAL, async {
        let first = Echo::spawn().await;
        let second = Echo::spawn().await;
        let mut cfg = config();
        cfg.cone = true;
        let pool = UdpPool::new(cfg).unwrap();

        // 首包发往 A。
        let dispatch = pool.dispatch(&v4(first.port), b"to-a").await.unwrap();
        assert_eq!(dispatch.target, v4(first.port), "首包目标即固定目标");
        let (addr_a, reply_a) = recv_reply(&pool).await;
        assert_eq!(addr_a, v4(first.port), "首包回程地址须为 A");
        assert_eq!(reply_a, b"to-a");

        // 后续包自带目标 B：cone 语义下目标被忽略，仍发往 A。
        let dispatch = pool.dispatch(&v4(second.port), b"to-b").await.unwrap();
        assert_eq!(
            dispatch.target,
            v4(first.port),
            "cone 模式：后续包自身的目标被忽略，仍发往首包目标（参考语义）"
        );

        let (addr, reply) = recv_reply(&pool).await;
        assert_eq!(addr, v4(first.port), "回程地址须为固定目标");
        assert_eq!(reply, b"to-b", "载荷是第二包的内容");

        // 独立观测面：第二个后端**零收包**（包没去 B），第一个后端收到两包。
        assert_eq!(second.total.load(Ordering::SeqCst), 0, "cone 下 B 不得收包");
        assert_eq!(first.total.load(Ordering::SeqCst), 2, "cone 下 A 收两包");
        assert_eq!(pool.entry_count(), 1, "cone 模式只应有一个条目");
    })
    .await
    .unwrap();
}

/// ④ 空闲超时回收：超时后条目被移除、socket 被释放（计数归零）。
#[tokio::test]
async fn idle_timeout_reclaims_entry_and_socket() {
    timeout(TOTAL, async {
        let echo = Echo::spawn().await;
        let mut cfg = config();
        cfg.idle_timeout = Duration::from_millis(200);
        let pool = UdpPool::new(cfg).unwrap();

        pool.dispatch(&v4(echo.port), b"probe").await.unwrap();
        let (_, reply) = recv_reply(&pool).await;
        assert_eq!(reply, b"probe");
        assert_eq!(pool.entry_count(), 1);
        assert_eq!(pool.live_sockets(), 1);

        // 空闲超过阈值后回收：条目移除、socket 释放 ⇒ 存活计数归零。
        tokio::time::sleep(Duration::from_millis(400)).await;
        let reaped = pool.reap_expired();
        assert_eq!(reaped, 1, "超时条目必须被回收");
        assert_eq!(pool.entry_count(), 0, "回收后条目必须移除");
        // 读任务退出后条目的最后一个引用释放 ⇒ socket 真正释放。
        for _ in 0..50 {
            if pool.live_sockets() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            pool.live_sockets(),
            0,
            "socket 必须真正释放（存活计数归零）"
        );
    })
    .await
    .unwrap();
}

/// ⑤ 池上界：超过上限时**淘汰最久未用的条目**（LRU），不拒绝新包。
#[tokio::test]
async fn pool_upper_bound_evicts_least_recently_used() {
    timeout(TOTAL, async {
        let mut echoes = Vec::new();
        for _ in 0..4 {
            echoes.push(Echo::spawn().await);
        }
        let mut cfg = config();
        cfg.max_entries = 2;
        let pool = UdpPool::new(cfg).unwrap();

        // 建两个条目并各自收回回程（回程到达会刷新条目活跃时刻）。
        pool.dispatch(&v4(echoes[0].port), b"a").await.unwrap();
        pool.dispatch(&v4(echoes[1].port), b"b").await.unwrap();
        let mut payloads = Vec::new();
        for _ in 0..2 {
            let (_, reply) = recv_reply(&pool).await;
            payloads.push(reply);
        }
        payloads.sort();
        assert_eq!(payloads, &[b"a".to_vec(), b"b".to_vec()]);

        // 确定性 LRU：再打一次第二个目标，使条目 1 的活跃时刻**严格晚于**条目 0。
        pool.dispatch(&v4(echoes[1].port), b"b2").await.unwrap();
        let (_, reply) = recv_reply(&pool).await;
        assert_eq!(reply, b"b2");

        // 第三个目标：上界为 2 ⇒ 淘汰最久未用的（第一个）条目。
        pool.dispatch(&v4(echoes[2].port), b"c").await.unwrap();
        assert_eq!(pool.entry_count(), 2, "条目数不得超过上界");
        assert_eq!(pool.created_sockets(), 3, "第三个目标必须新建 socket");

        // 被淘汰的条目不得再复用：再发一次第一个目标 ⇒ 又是新 socket。
        let reused = pool.dispatch(&v4(echoes[0].port), b"a2").await.unwrap();
        assert!(!reused.reused, "被淘汰的条目必须重建（新 socket）");
        assert_eq!(pool.created_sockets(), 4, "重建后累计建立四个 socket");
        assert_eq!(pool.entry_count(), 2, "条目数仍不得超过上界");
    })
    .await
    .unwrap();
}

/// ⑥ 并发压力：N 个并发任务向同一目标发包，回程**全部正确**、无丢失。
#[tokio::test]
async fn concurrent_dispatch_to_same_target_is_lossless() {
    timeout(TOTAL, async {
        let echo = Echo::spawn().await;
        let pool = Arc::new(UdpPool::new(config()).unwrap());
        const TASKS: usize = 32;

        let mut handles = Vec::new();
        for index in 0..TASKS {
            let pool = Arc::clone(&pool);
            handles.push(tokio::spawn(async move {
                let payload = [index as u8; 24];
                pool.dispatch(&v4(echo.port), &payload).await.unwrap();
            }));
        }
        // 等待全部并发任务完成（投递本身完成即算结束）。
        for handle in handles {
            timeout(WAIT, handle)
                .await
                .expect("并发投递超时")
                .expect("并发投递任务 panic");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        // 收齐 TASKS 个回程，逐字节校验内容集合（不串包、不丢失）。
        let mut received: Vec<Vec<u8>> = Vec::new();
        for _ in 0..TASKS {
            let (_, reply) = recv_reply(&pool).await;
            received.push(reply);
        }
        received.sort();
        let mut expected: Vec<Vec<u8>> = (0..TASKS).map(|i| vec![i as u8; 24]).collect();
        expected.sort();
        assert_eq!(received, expected, "回程必须全部正确且不丢失");
        assert_eq!(
            echo.total.load(Ordering::SeqCst),
            TASKS,
            "服务端收包数须一致"
        );
        // 同一目标 ⇒ 只有一个出站 socket（并发不破坏复用）。
        assert_eq!(pool.created_sockets(), 1, "同一目标只应建立一个 socket");
        assert_eq!(pool.entry_count(), 1);
    })
    .await
    .unwrap();
}
