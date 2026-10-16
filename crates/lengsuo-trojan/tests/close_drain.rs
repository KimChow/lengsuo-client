//! 关闭前残留丢弃（drain）测试，对齐参考 `common/drain/drainer.go`。
//!
//! 覆盖：N 字节边界（正好丢满 / 提前 EOF 只丢部分 / 目标为 0 不触碰流）、
//! `AcknowledgeReceive` 抵消、超时包住静默对端、零时长拒绝、
//! 固定种子逐字节可复现、种子骰子取值域退化，以及 drain + 写半关闭组合
//! （参考默认 Nop 行为、种子化行为、两阶段共用一个截止时间）。
//! 所有异步读写都被 `tokio::time::timeout` 包住；`read_to_end` 前先关写端。
//! 密码为测试专用假凭据。

use std::time::Duration;

use lengsuo_trojan::drain::{
    BehaviorSeedLimitedDrainer, DeterministicDice, DrainOutcome, Drainer, DRAIN_FOUNDATION,
    MAX_BASE_DRAIN_SIZE, MAX_RAND_DRAIN,
};
use lengsuo_trojan::stream::{close_stream, shutdown_write};
use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(2);
const SILENT: Duration = Duration::from_millis(30);

/// 固定可复现的伪随机字节型样（不依赖随机源，便于逐字节比较）。
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u32 * 7 + 11) as u8).collect()
}

#[tokio::test]
async fn drain_discards_exactly_n_bytes() {
    timeout(WAIT, async {
        let want = 100usize;
        let (mut client, mut server) = duplex(4096);
        client.write_all(&pattern(want)).await.expect("可写入");
        // 对端不关闭也不再多发：只有正好 100 字节可读，drain 必须停在边界上。
        let mut drainer = Drainer::limited(BehaviorSeedLimitedDrainer::from_drain_size(want));
        assert_eq!(drainer.remaining(), want);
        let outcome = drainer.drain(&mut server, WAIT).await.expect("drain 成功");
        assert_eq!(outcome, DrainOutcome::FullyDrained { bytes: want });
        // 100 字节被丢弃后流上什么都不剩：静默即超时，证明没有多读也没有少读。
        let mut rest = [0u8; 1];
        assert!(
            timeout(SILENT, server.read(&mut rest)).await.is_err(),
            "drain 不应越界多读，也不应留下未丢弃的字节"
        );
    })
    .await
    .expect("N 字节边界超时");
}

#[tokio::test]
async fn drain_short_when_peer_closes_early() {
    timeout(WAIT, async {
        let (mut client, mut server) = duplex(4096);
        // 只发 37 字节就关写端：参考在这里把错误上抛为 "unable to drain"。
        client.write_all(&pattern(37)).await.expect("可写入");
        client.shutdown().await.expect("可关写端");
        let mut drainer = Drainer::limited(BehaviorSeedLimitedDrainer::from_drain_size(100));
        let outcome = drainer.drain(&mut server, WAIT).await.expect("drain 返回");
        assert_eq!(outcome, DrainOutcome::Short { bytes: 37 });
        // 目标不改（抵消只由 AcknowledgeReceive 表达），与参考 Drain 一致。
        assert_eq!(drainer.remaining(), 100);
    })
    .await
    .expect("提前 EOF 超时");
}

#[tokio::test]
async fn drain_zero_target_never_touches_the_stream() {
    timeout(WAIT, async {
        let (mut client, mut server) = duplex(4096);
        client
            .write_all(b"application payload")
            .await
            .expect("可写入");
        // 目标为 0：参考 `if d.DrainSize > 0` 不成立时完全不读。
        let mut drainer = Drainer::default();
        assert_eq!(drainer.remaining(), 0);
        assert_eq!(
            drainer.drain(&mut server, WAIT).await.expect("Nop 成功"),
            DrainOutcome::NothingToDrain
        );
        // 先只读 "application "：剩余字节留给后续断言，证明 Nop 没吞任何字节。
        let mut buf = [0u8; 12];
        server.read_exact(&mut buf).await.expect("可读");
        assert_eq!(&buf, b"application ", "Nop 必须一个字节都不吞");

        // 种子化 drainer 被抵消到 0 之后同样不读流。
        let mut limited = Drainer::limited(BehaviorSeedLimitedDrainer::from_drain_size(5));
        limited.acknowledge_receive(5);
        assert_eq!(limited.remaining(), 0);
        assert_eq!(
            limited.drain(&mut server, WAIT).await.expect("抵消后成功"),
            DrainOutcome::NothingToDrain
        );
        let mut rest = Vec::new();
        client.shutdown().await.expect("可关写端");
        timeout(WAIT, server.read_to_end(&mut rest))
            .await
            .expect("读超时")
            .expect("可读到 EOF");
        assert_eq!(rest, b"payload", "抵消后的 drain 仍未消耗任何字节");
    })
    .await
    .expect("零目标不读流超时");
}

#[tokio::test]
async fn acknowledge_receive_subtracts_and_can_go_negative() {
    timeout(WAIT, async {
        let mut drainer = BehaviorSeedLimitedDrainer::from_drain_size(50);
        drainer.acknowledge_receive(30);
        assert_eq!(drainer.remaining(), 20);
        // 参考允许 DrainSize 被减成负数，负数一律按“无需再读”处理。
        drainer.acknowledge_receive(999);
        assert_eq!(drainer.remaining(), 0);
        let (_client, mut server) = duplex(8);
        assert_eq!(
            drainer.drain(&mut server, WAIT).await.expect("可为 0"),
            DrainOutcome::NothingToDrain
        );

        // Nop 的抵消是空操作（对齐参考 NopDrainer）。
        let mut nop = Drainer::nop();
        nop.acknowledge_receive(usize::MAX);
        assert_eq!(nop.remaining(), 0);
    })
    .await
    .expect("抵消超时");
}

#[tokio::test]
async fn drain_wraps_silent_peer_with_timeout_and_rejects_zero_deadline() {
    timeout(WAIT, async {
        // 静默对端：一个字节都不发，drain 必须在截止时间内失败而不是挂住。
        let (_client, mut server) = duplex(4096);
        let mut drainer = Drainer::limited(BehaviorSeedLimitedDrainer::from_drain_size(16));
        assert!(matches!(
            drainer.drain(&mut server, SILENT).await,
            Err(lengsuo_trojan::drain::Error::Timeout)
        ));
        // 零时长显式拒绝（与 stream 各操作一致）。
        assert!(matches!(
            drainer.drain(&mut server, Duration::ZERO).await,
            Err(lengsuo_trojan::drain::Error::InvalidDeadline)
        ));
        // Nop 策略同样校验截止时间，但不读流。
        let mut nop = Drainer::nop();
        assert!(matches!(
            nop.drain(&mut server, Duration::ZERO).await,
            Err(lengsuo_trojan::drain::Error::InvalidDeadline)
        ));
    })
    .await
    .expect("静默 drain 超时");
}

#[tokio::test]
async fn seeded_drain_is_reproducible_byte_for_byte() {
    timeout(WAIT, async {
        // 同一颗种子在多次构造下必须给出完全相同的丢弃长度，并且
        // “丢到哪一字节为止”可逐字节复现（比较被留下给应用的残余字节）。
        const TOTAL: usize = 4000;
        let seeds = [0i64, 1, -1, 7, 42, i64::MIN, i64::MAX, 1234_5678_9012];
        for seed in seeds {
            let first = Drainer::behavior_seeded(seed).remaining();
            let second = Drainer::behavior_seeded(seed).remaining();
            let third = Drainer::limited(BehaviorSeedLimitedDrainer::with_reference_limits(seed))
                .remaining();
            assert_eq!(first, second, "种子 {seed} 的派生不可复现");
            assert_eq!(first, third, "两条构造路径必须一致");
            // 参考公式的取值域：foundation + [0,maxBase) + [0,maxRand)。
            let upper = DRAIN_FOUNDATION + MAX_BASE_DRAIN_SIZE + MAX_RAND_DRAIN;
            assert!(
                first >= DRAIN_FOUNDATION && first <= upper,
                "种子 {seed} 的 DrainSize {first} 超出参考公式范围 [{DRAIN_FOUNDATION}, {upper}]"
            );

            let mut tails = Vec::new();
            for _ in 0..2 {
                let (mut client, mut server) = duplex(TOTAL + 16);
                client.write_all(&pattern(TOTAL)).await.expect("可写入");
                let mut drainer = Drainer::behavior_seeded(seed);
                let outcome = drainer.drain(&mut server, WAIT).await.expect("drain 成功");
                assert_eq!(outcome, DrainOutcome::FullyDrained { bytes: first });
                // 剩下给应用的字节必须从同一偏移开始，逐字节相同。
                let mut tail = Vec::new();
                client.shutdown().await.expect("可关写端");
                timeout(WAIT, server.read_to_end(&mut tail))
                    .await
                    .expect("读残余超时")
                    .expect("可读到 EOF");
                assert_eq!(tail.len(), TOTAL - first, "种子 {seed} 丢弃长度不一致");
                tails.push(tail);
            }
            assert_eq!(tails[0], tails[1], "种子 {seed} 的残留起点逐字节不可复现");
            assert_eq!(tails[0], pattern(TOTAL)[first..]);
        }
        // 不同种子之间确实有差异（不是常量退化）。
        let a = Drainer::behavior_seeded(1).remaining();
        let b = Drainer::behavior_seeded(2).remaining();
        assert_ne!(a, b, "不同种子给出同一长度：{a}");
    })
    .await
    .expect("种子化确定性超时");
}

#[tokio::test]
async fn dice_roll_matches_reference_value_domain() {
    timeout(WAIT, async {
        // 参考 DeterministicDice.Roll / dice.Roll：n == 1 恒为 0。
        assert_eq!(DeterministicDice::rolled(1, 9), 0);
        assert_eq!(DeterministicDice::new(-3).roll(1), 0);
        // n <= 0 在本仓按同样域处理（Go 的 Intn(0) 会 panic，这里必须不 panic）。
        assert_eq!(DeterministicDice::new(5).roll(0), 0);
        for seed in [0i64, 1, -1, i64::MIN, i64::MAX, 99] {
            for n in [2usize, 3, 64, MAX_BASE_DRAIN_SIZE, 100_000] {
                let mut dice = DeterministicDice::new(seed);
                for _ in 0..32 {
                    let value = dice.roll(n);
                    assert!(value < n, "roll({n}) 越界：{value}");
                }
            }
        }
        // 同种子两次序列必须逐值相同（确定性）。
        let mut left = DeterministicDice::new(2026);
        let mut right = DeterministicDice::new(2026);
        for _ in 0..64 {
            assert_eq!(left.roll(1000), right.roll(1000));
        }
    })
    .await
    .expect("骰子取值域超时");
}

#[tokio::test]
async fn half_close_with_default_drainer_matches_reference() {
    timeout(WAIT, async {
        // 参考 trojan 不安装 drainer：默认策略只 flush + SHUT_WR，不读任何残留。
        let (stream, peer) = duplex(4096);
        let (mut read, mut write) = split(stream);
        let mut client = peer;
        client
            .write_all(b"left for the app")
            .await
            .expect("可写入对端数据");

        write.write_all(b"our payload").await.expect("可写载荷");
        let report = close_stream(&mut read, &mut write, &mut Drainer::default(), WAIT).await;
        assert!(report.succeeded(), "默认收尾两步都要成功：{report:?}");
        assert!(
            matches!(report.drain, Ok(DrainOutcome::NothingToDrain)),
            "实际 {:?}",
            report
                .drain
                .as_ref()
                .map(|_| "Ok")
                .map_err(|e| e.to_string())
        );
        assert_eq!(report.drained_bytes(), 0);

        let (mut peer_read, peer_write) = split(client);
        let mut got = Vec::new();
        timeout(WAIT, peer_read.read_to_end(&mut got))
            .await
            .expect("读超时")
            .expect("可读到 EOF");
        assert_eq!(got, b"our payload", "写半关闭只给出 EOF，不多不少");
        // 我们没读过自己的读侧：那 16 字节仍在流上。
        let mut mine = [0u8; 16];
        timeout(WAIT, read.read_exact(&mut mine))
            .await
            .expect("读超时")
            .expect("可读");
        assert_eq!(&mine, b"left for the app");
        let _ = peer_write;
    })
    .await
    .expect("默认收尾超时");
}

#[tokio::test]
async fn half_close_after_seeded_drain_uses_only_the_leftover() {
    timeout(WAIT, async {
        // 对端在我们关写端前塞了 500 字节探测残留：种子化 drain 先按策略丢弃，
        // 再 SHUT_WR，避免带着未读残留关闭而吃到 RST。
        let seed = 20_260_327i64;
        let target = Drainer::behavior_seeded(seed).remaining();
        let (stream, mut peer) = duplex(8192);
        let (mut read, mut write) = split(stream);
        peer.write_all(&pattern(target + 5))
            .await
            .expect("可写入残留+尾部");

        let mut drainer = Drainer::behavior_seeded(seed);
        let report = close_stream(&mut read, &mut write, &mut drainer, WAIT).await;
        assert!(report.succeeded(), "种子化收尾应两步成功：{report:?}");
        assert!(
            matches!(
                report.drain,
                Ok(DrainOutcome::FullyDrained { bytes }) if bytes == target
            ),
            "丢弃长度应为该种子的 DrainSize，实际 {:?}",
            report
                .drain
                .as_ref()
                .map(|_| "Ok")
                .map_err(|e| e.to_string())
        );
        assert_eq!(report.drained_bytes(), target);

        // 剩下的 5 字节仍归应用可读（drain 只丢到 DrainSize 为止）。对端写侧
        // 仍开着，EOF 不会到来——精确读取剩余字节数而不是 read_to_end。
        // 写半关闭之后本端不得再写（与 SS TCP 收尾语义一致）：试写必须报错。
        let late = write.write_all(b"late").await;
        assert!(late.is_err(), "写半关闭后不得再写");
        let leftover = pattern(target + 5)[target..].to_vec();
        let mut tail = vec![0u8; leftover.len()];
        timeout(WAIT, read.read_exact(&mut tail))
            .await
            .expect("读超时")
            .expect("可读");
        assert_eq!(tail, leftover, "drain 只丢到 DrainSize，剩余归应用");

        // 对端读到我们的 EOF：说明写半关闭确实发生（不是整连接被 RST）。
        let mut seen = Vec::new();
        timeout(WAIT, peer.read_to_end(&mut seen))
            .await
            .expect("对端读超时")
            .expect("对端可读到 EOF");
    })
    .await
    .expect("种子化 drain + 半关闭超时");
}

#[tokio::test]
async fn close_shares_one_deadline_across_both_phases() {
    timeout(WAIT, async {
        // 静默对端让阶段一吃满截止时间；阶段二必须立刻以超时结束而不是挂住，
        // 两阶段合起来的等待不超过一个 wait。
        let (stream, _peer) = duplex(4096);
        let (mut read, mut write) = split(stream);
        let mut drainer = Drainer::limited(BehaviorSeedLimitedDrainer::from_drain_size(64));
        let started = tokio::time::Instant::now();
        let report = timeout(
            WAIT,
            close_stream(&mut read, &mut write, &mut drainer, SILENT),
        )
        .await
        .expect("close_stream 自身必须在一半截止时间内返回");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "两阶段共用了过多时间：{:?}",
            started.elapsed()
        );
        assert!(report.drain.is_err(), "阶段一应失败：{:?}", report.drain);
        assert!(
            report.write_shutdown.is_err(),
            "阶段二应报超时而不是假装成功"
        );
        assert!(!report.succeeded());

        // 零时长：两步都被拒绝，不做任何 I/O。
        let report = close_stream(&mut read, &mut write, &mut drainer, Duration::ZERO).await;
        for err in [report.drain.err(), report.write_shutdown.err()] {
            assert!(
                matches!(err, Some(lengsuo_trojan::stream::Error::InvalidDeadline)),
                "零时长必须拒绝：{err:?}"
            );
        }
    })
    .await
    .expect("共用截止时间超时");
}

#[tokio::test]
async fn shutdown_write_only_closes_write_half() {
    timeout(WAIT, async {
        let (mut client, mut server) = duplex(4096);
        client.write_all(b"up").await.expect("可写入");
        client.shutdown().await.expect("可半关闭");
        let mut buf = [0u8; 2];
        timeout(WAIT, server.read_exact(&mut buf))
            .await
            .expect("读超时")
            .expect("可读");
        assert_eq!(&buf, b"up");
        // 半关闭之后读侧仍可用：server 回写、client 仍可读。
        server.write_all(b"down").await.expect("可回写");
        let mut back = [0u8; 4];
        timeout(WAIT, client.read_exact(&mut back))
            .await
            .expect("读超时")
            .expect("可读");
        assert_eq!(&back, b"down");
        // 零时长拒绝。
        assert!(matches!(
            shutdown_write(&mut client, Duration::ZERO).await,
            Err(lengsuo_trojan::stream::Error::InvalidDeadline)
        ));
    })
    .await
    .expect("写半关闭超时");
}
