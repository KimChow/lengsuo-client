//! 五个真实参考用例：错误密码、fallback 分流、截断认证头、正常半关闭回程，
//! 以及本实现侧的失败可判别性（自建 roundtrip，不宣称与 Xray 互通）。
use super::harness::*;
use super::support::*;
use lengsuo_trojan::credential::HASH_LEN;
use lengsuo_trojan::Session;
use lengsuo_trojan::{
    codec,
    stream::{receive_request, send_request, Error},
};
use serde_json::json;
use std::{sync::atomic::Ordering, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{timeout, Instant},
};
/// 错误密码：参考端必须主动结束连接，且业务目标的 accept 计数不得增长；
/// 之后同一服务对正确密码仍然可用（证明拒绝不是进程崩溃）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn wrong_password_never_reaches_business_target() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        // 业务目标由 owner 持有：端口、accept 观测面与全部自建任务。
        let target = TcpShell::bind(REPLY.to_vec(), false).await;
        let accepted = target.counter();
        let target_port = target.port();
        let port = free_port();
        let reference = launch(
            json!({"log":{"loglevel":"warning"},"policy":policy(),
                "inbounds":[trojan_inbound(port,
                    json!({"clients":[{"password":GOOD}]}), &identity)],
                "outbounds":[{"protocol":"freedom"}]}),
            port,
        )
        .await;

        control_round_trip(&identity, port, target_port).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "对照组必须抵达业务目标");

        let mut bad = wrong_password_offer(&identity, port, target_port).await;
        let closed = await_close(&mut bad, CLOSE_BOUND).await;
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "错误密码不能收到应答：{closed:?}"
        );
        drop(bad);
        // 沉降一点时间再核对观测面，排除迟到的拨号；仍只有对照那一条。
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "错误密码不得建立通往业务目标的连接"
        );

        control_round_trip(&identity, port, target_port).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 2, "拒绝之后参考服务仍可用");
        drop(reference);
        target.recycle().await;
    })
    .await
    .unwrap();
}

/// 配置了 TLSfallback 的认证失败：失败流量只被分流到**非业务**信标端口，
/// 业务目标计数不变。信标上读到明确的 `PROXY TCP4 `（`xver:1`）头部作为
/// “确实走了 fallback 分支”的正向证据，而不是靠超时推断。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn fallback_takes_failed_auth_without_business_leak() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        // 业务目标由 owner 持有：端口、accept 观测面与全部自建任务。
        let target = TcpShell::bind(REPLY.to_vec(), false).await;
        let accepted = target.counter();
        let target_port = target.port();
        let decoy = BeaconShell::bind().await;
        let beacon_hits = decoy.counter();
        let decoy_port = decoy.port();
        let port = free_port();
        let reference = launch(
            json!({"log":{"loglevel":"warning"},"policy":policy(),
                "inbounds":[trojan_inbound(port,
                    json!({"clients":[{"password":GOOD}],
                        "fallbacks":[{"dest":decoy_port,"xver":1}]}), &identity)],
                "outbounds":[{"protocol":"freedom"}]}),
            port,
        )
        .await;

        control_round_trip(&identity, port, target_port).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "带 fallback 的对照组必须抵达业务目标"
        );

        let mut bad = wrong_password_offer(&identity, port, target_port).await;
        // 正向证据：fallback 信标接受到这条连接，并收到 xver=1 的 PROXY 头。
        // 内层 io 结果同样被 unwrap，拿不到连接就失败，不把观察超时当分流证据。
        let mut beacon = decoy.take_one().await;
        let mut prefix = [0u8; 11];
        timeout(WAIT, beacon.read_exact(&mut prefix))
            .await
            .expect("fallback 信标读超时")
            .unwrap();
        assert_eq!(&prefix, b"PROXY TCP4 ", "fallback 应带 xver=1 头部");
        assert_eq!(
            beacon_hits.load(Ordering::SeqCst),
            1,
            "fallback 应且仅应把失败流量送到信标一次"
        );
        drop(beacon);

        // fallback 把原始字节继续转给信标，我方连接由参考端维持或结束都读得到。
        let closed = await_close(&mut bad, CLOSE_BOUND).await;
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "认证失败不能收到业务应答：{closed:?}"
        );
        drop(bad);

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "认证失败不得建立通往业务目标的连接（fallback 只到非业务信标）"
        );

        control_round_trip(&identity, port, target_port).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "fallback 分流之后服务仍可用"
        );
        drop(reference);
        decoy.recycle();
        target.recycle().await;
    })
    .await
    .unwrap();
}

/// 截断认证头的有界拒绝。两类分支都要求参考端主动结束：
/// 1. 不足 58 字节 —— 参考 `proxy/trojan/server.go` 的
///    `firstLen < 58 || first.Byte(56) != '\r'` 协议判定线，立即判“not trojan
///    protocol”并结束；
/// 2. 跨过判定线之后头部不全（密码正确、地址缺失且不关闭）—— 由 policy 的
///    握手截止（此处 2 秒）结束，实测必须明显早于观察上限。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn truncated_auth_header_is_rejected_within_deadline() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        // 业务目标由 owner 持有：端口、accept 观测面与全部自建任务。
        let target = TcpShell::bind(REPLY.to_vec(), false).await;
        let accepted = target.counter();
        let target_port = target.port();
        let port = free_port();
        let reference = launch(
            json!({"log":{"loglevel":"warning"},"policy":policy(),
                "inbounds":[trojan_inbound(port,
                    json!({"clients":[{"password":GOOD}]}), &identity)],
                "outbounds":[{"protocol":"freedom"}]}),
            port,
        )
        .await;
        let header = codec::encode(&tcp_request(target_port), &Credential::new(GOOD)).unwrap();

        // 分支一：短头，含判定线两侧 57/58。
        for cut in [1usize, 30, 40, 57, 58, header.len() - 1] {
            let mut partial = identity.connect(port).await;
            // 截断头的每一段写入同样有界：超时即测试失败，不靠挂起等参考端。
            bounded_write(&mut partial, &header[..cut], WRITE_BOUND)
                .await
                .unwrap_or_else(|error| panic!("截断点 {cut} 写入失败：{error}"));
            bounded_flush(&mut partial)
                .await
                .expect("截断头 flush 超时");
            let closed = await_close(&mut partial, CLOSE_BOUND).await;
            assert!(
                matches!(closed, Ok(0) | Err(_)),
                "截断点 {cut} 不能收到应答：{closed:?}"
            );
            drop(partial);
        }

        // 分支二：只写哈希前缀后彻底静默（不关写端），必须由握手截止结束。
        let start = Instant::now();
        let mut silent = identity.connect(port).await;
        bounded_write(&mut silent, &header[..HASH_LEN], WRITE_BOUND)
            .await
            .expect("静默截断头写入超时");
        bounded_flush(&mut silent)
            .await
            .expect("静默截断头 flush 超时");
        let closed = await_close(&mut silent, CLOSE_BOUND).await;
        let elapsed = start.elapsed();
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "静默截断头不能收到应答：{closed:?}"
        );
        assert!(
            elapsed < CLOSE_BOUND,
            "握手截止必须早于观察上限生效，实测 {elapsed:?}"
        );
        drop(silent);

        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "截断头不得建立通往业务目标的连接"
        );
        control_round_trip(&identity, port, target_port).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "截断拒绝之后服务仍可用");
        drop(reference);
        target.recycle().await;
    })
    .await
    .unwrap();
}

/// 正常 TCP 半关闭：客户端关写端之后仍能收完 64 KiB 回程（跨多个 TLS 记录），
/// 说明拒绝分支的收尾没有把正常回程一并切断。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn half_close_still_delivers_bulk_reply() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let bulk = vec![0xA5u8; BULK_LEN];
        // 半关闭验收壳：回写 64 KiB 之后继续观测读侧到结束为止。
        let target = TcpShell::fin_shell(bulk.clone()).await;
        let accepted = target.counter();
        let target_port = target.port();
        let port = free_port();
        let reference = launch(
            json!({"log":{"loglevel":"warning"},"policy":policy(),
                "inbounds":[trojan_inbound(port,
                    json!({"clients":[{"password":GOOD}]}), &identity)],
                "outbounds":[{"protocol":"freedom"}]}),
            port,
        )
        .await;

        let mut stream = identity.connect(port).await;
        send_request(
            &mut stream,
            &tcp_request(target_port),
            &Credential::new(GOOD),
            WAIT,
        )
        .await
        .unwrap();
        bounded_write(&mut stream, PAYLOAD, WRITE_BOUND)
            .await
            .expect("半关闭用例写入请求载荷超时");
        bounded_flush(&mut stream)
            .await
            .expect("半关闭用例 flush 超时");
        bounded_shutdown(&mut stream)
            .await
            .expect("半关闭用例关写端超时");
        let mut received = vec![0; BULK_LEN];
        timeout(WAIT, stream.read_exact(&mut received))
            .await
            .expect("半关闭之后收完 64 KiB 回程超时")
            .unwrap();
        assert_eq!(received, bulk);
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "半关闭必须抵达业务目标");
        // 回程之后的读侧结束（我方 FIN 传播或参考端关闭）是有界的观测面，
        // 轮询到出现为止；观察上限内不出现即失败，不把超时当结论。
        let seen = timeout(CLOSE_BOUND, wait_until(|| target.fin_count() >= 1))
            .await
            .expect("回程写完后目标端读侧必须在观察上限内结束");
        assert!(seen, "目标端读侧结束观测未成立");
        drop(stream);
        drop(reference);
        // 回程收完即回收：abort accept 循环并 await 每连接任务，不留悬挂读循环。
        target.recycle().await;
    })
    .await
    .unwrap();
}

/// 同一批失败在本实现侧的可判别性（自建 roundtrip，只证明内部一致，
/// 不宣称与 Xray 互通；与上面的真实参考用例互补）：错误密码是认证失败，
/// 截断头部是超时或 I/O 失败，两条失败路径都拿不到可用 `Session`。
#[tokio::test]
async fn rust_side_distinguishes_authentication_and_truncation() {
    timeout(WAIT, async {
        // 完整头部但密码错误 → 认证失败，且在哈希阶段早拒（不等地址到达）。
        let (mut peer, mut server) = tokio::io::duplex(256);
        let bad_header = codec::encode(&tcp_request(9), &Credential::new(BAD)).unwrap();
        peer.write_all(&bad_header).await.unwrap();
        assert!(matches!(
            receive_request(&mut server, &Credential::new(GOOD), WAIT).await,
            Err(Error::Codec(codec::Error::Authentication))
        ));

        // 正确密码但头部截断且不关闭 → 截止时间到 → Timeout（不是成功）。
        let (mut peer, mut server) = tokio::io::duplex(256);
        let header = codec::encode(&tcp_request(9), &Credential::new(GOOD)).unwrap();
        peer.write_all(&header[..HASH_LEN]).await.unwrap();
        assert!(matches!(
            receive_request(
                &mut server,
                &Credential::new(GOOD),
                Duration::from_millis(5)
            )
            .await,
            Err(Error::Timeout)
        ));

        // 截断到 EOF → I/O 失败，且不得构造出可用会话。
        let (mut peer, server) = tokio::io::duplex(256);
        peer.write_all(&header[..HASH_LEN + 3]).await.unwrap();
        peer.shutdown().await.unwrap();
        let (mut read, mut write) = tokio::io::split(server);
        assert!(
            matches!(
                Session::accept(&mut read, &mut write, &Credential::new(GOOD), WAIT).await,
                Err(Error::Io(_))
            ),
            "截断头部必须是 I/O 失败，不能交还会话"
        );
    })
    .await
    .expect("失败分类超时");
}
