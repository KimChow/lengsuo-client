// half_close / close 语义用例：默认 drainer 的收尾、种子化 drain 后的半关闭、
// 两阶段共用一个截止时间、只关写半。
//
// 本文件由 `tests/close_drain.rs` 以 `include!` 拼入该测试目标的根模块，
// 因此共享的导入、常量（`WAIT` / `SILENT`）与 `pattern` 辅助都在入口文件里。

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
