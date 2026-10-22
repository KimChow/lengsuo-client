/// **5. Mux 正例**：承载建立 + 单会话往返。
///
/// 承载上**先发 mux 帧**（`New`），服务端才把滞留的响应头连同首个回程帧一起
/// flush（参考 `common/buf/writer.go` 的 `SetFlushNext()` 时序）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_mux_single_session_roundtrip() {
    timeout(DEADLINE, async {
        let fixture = server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vless_node(port, &ca_pem, None, true);
        assert!(node.validate().is_ok(), "配置应通过校验");
        let mut peer = spawn_mux_peer(fixture, KEY);

        let mut outbound = dial_vless(&node, WAIT).await.expect("mux 建承载应成功");
        let session_id = match &outbound.stream {
            VlessStream::Mux(session) => session.id(),
            _ => panic!("承载应是 mux"),
        };
        outbound.stream.write_all(PAYLOAD).await.expect("写载荷");
        let mut received = vec![0u8; PAYLOAD.len() + 2];
        timeout(WAIT, outbound.stream.read_exact(&mut received))
            .await
            .expect("读载荷超时")
            .expect("读载荷");
        // 服务端回显带会话标签（会话 ID ‖ 载荷）⇒ 路由串扰会立刻暴露。
        assert_eq!(
            &received[..2],
            &session_id.to_be_bytes(),
            "回显必须落在本会话上"
        );
        assert_eq!(&received[2..], PAYLOAD, "回环载荷必须逐字节一致");

        // 承载断开 ⇒ 服务端任务收尾（顺带验证服务端确实收到了载荷）。
        peer.close.take().expect("关闭句柄").send(()).ok();
        let outcome = peer.task.await.expect("服务端任务").expect("服务端");
        assert_eq!(outcome.received.len(), 1, "服务端应只收到一条会话的载荷");
        assert_eq!(outcome.received[0].1, PAYLOAD, "服务端收到的载荷应一致");
    })
    .await
    .expect("用例总超时");
}

/// **6. Mux 正例**：多会话隔离 —— 同一条承载开**两条**逻辑会话（不同目标、
/// 不同载荷），断言两条**互不串扰**（A 的字节不能出现在 B 里，反之亦然）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_mux_two_sessions_are_isolated() {
    timeout(DEADLINE, async {
        let fixture = server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vless_node(port, &ca_pem, None, true);
        let mut peer = spawn_mux_peer(fixture, KEY);

        let outbound = dial_vless(&node, WAIT).await.expect("mux 建承载应成功");
        let VlessStream::Mux(mut session_a) = outbound.stream else {
            panic!("承载应是 mux");
        };
        // 第二条逻辑会话：同一条承载、不同目标。
        let mut session_b = session_a
            .open_session(TargetAddr::Domain("b.example.test".to_owned(), 80))
            .await
            .expect("开第二条逻辑会话");
        assert_ne!(session_a.id(), session_b.id(), "两条会话的 ID 必须不同");

        session_a.write_all(PAYLOAD_A).await.expect("写 A 载荷");
        session_b.write_all(PAYLOAD_B).await.expect("写 B 载荷");

        let mut got_a = vec![0u8; PAYLOAD_A.len() + 2];
        timeout(WAIT, session_a.read_exact(&mut got_a))
            .await
            .expect("读 A 载荷超时")
            .expect("读 A 载荷");
        let mut got_b = vec![0u8; PAYLOAD_B.len() + 2];
        timeout(WAIT, session_b.read_exact(&mut got_b))
            .await
            .expect("读 B 载荷超时")
            .expect("读 B 载荷");

        assert_eq!(
            &got_a[..2],
            &session_a.id().to_be_bytes(),
            "A 的回显必须落在 A 会话上"
        );
        assert_eq!(
            &got_b[..2],
            &session_b.id().to_be_bytes(),
            "B 的回显必须落在 B 会话上"
        );
        assert_eq!(&got_a[2..], PAYLOAD_A, "A 的载荷必须逐字节一致");
        assert_eq!(&got_b[2..], PAYLOAD_B, "B 的载荷必须逐字节一致");
        assert!(
            !got_a.windows(PAYLOAD_B.len()).any(|w| w == PAYLOAD_B),
            "A 的回显里不得出现 B 的字节"
        );
        assert!(
            !got_b.windows(PAYLOAD_A.len()).any(|w| w == PAYLOAD_A),
            "B 的回显里不得出现 A 的字节"
        );

        peer.close.take().expect("关闭句柄").send(()).ok();
        let outcome = peer.task.await.expect("服务端任务").expect("服务端");
        assert_eq!(outcome.received.len(), 2, "服务端应收到两条会话的载荷");
    })
    .await
    .expect("用例总超时");
}

/// **7. Mux 负例**：承载断开 ⇒ **所有**逻辑会话必须失败（⛔ 不得静默挂住）。
///
/// 承载断开的判定：承载连接被关闭 ⇒ 读循环收尾 ⇒ 所有会话的收件箱被关闭 ⇒
/// 会话读必须**返回错误**（EOF ⇒ `read_exact` 报 `UnexpectedEof`），而不是
/// 永远 pending。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_mux_carrier_close_fails_all_sessions() {
    timeout(DEADLINE, async {
        let fixture = server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vless_node(port, &ca_pem, None, true);
        let mut peer = spawn_mux_peer(fixture, KEY);

        let outbound = dial_vless(&node, WAIT).await.expect("mux 建承载应成功");
        let VlessStream::Mux(mut session_a) = outbound.stream else {
            panic!("承载应是 mux");
        };
        let mut session_b = session_a
            .open_session(TargetAddr::Domain("b.example.test".to_owned(), 80))
            .await
            .expect("开第二条逻辑会话");

        // 先做一次成功往返，确认承载确实通着。
        session_a.write_all(PAYLOAD_A).await.expect("写 A 载荷");
        let mut got = vec![0u8; PAYLOAD_A.len() + 2];
        timeout(WAIT, session_a.read_exact(&mut got))
            .await
            .expect("读 A 载荷超时")
            .expect("读 A 载荷");
        assert_eq!(&got[2..], PAYLOAD_A, "A 的载荷必须逐字节一致");

        // 承载断开。
        peer.close.take().expect("关闭句柄").send(()).ok();
        peer.task.await.expect("服务端任务").expect("服务端");

        // 两条会话都必须失败，且不得挂住。
        let mut buf = vec![0u8; 8];
        let a = timeout(WAIT, session_a.read_exact(&mut buf)).await;
        assert!(a.is_ok(), "承载断开后 A 会话必须结束（不得静默挂住）");
        assert!(a.expect("已结束").is_err(), "承载断开后 A 会话必须失败");
        let b = timeout(WAIT, session_b.read_exact(&mut buf)).await;
        assert!(b.is_ok(), "承载断开后 B 会话必须结束（不得静默挂住）");
        assert!(b.expect("已结束").is_err(), "承载断开后 B 会话必须失败");
    })
    .await
    .expect("用例总超时");
}

/// **8. Mux 顺序**：承载上**先发 mux 帧**、再在读帧流时消费响应头。
///
/// 参考把 VLESS 响应头滞留到**首个 mux 帧写出**才 flush
/// （`proxy/vless/inbound/inbound.go:618-621` 写进 `buf.BufferedWriter`，之后
/// 才 `SetFlushNext()`；`common/buf/writer.go:165` 的 `flushNext` 只在**下一次
/// Write** 时触发）⇒ 若 node「先阻塞等响应头、再发 mux 帧」，承载两端互锁。
///
/// 判据：服务端在**收到客户端的 mux 帧之后**才把响应头 flush 出来 ⇒
/// `frames_before_header ≥ 1` 即证明客户端**先发了帧**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_vless_mux_sends_frames_before_waiting_for_response_header() {
    timeout(DEADLINE, async {
        let fixture = server_fixture().await;
        let port = fixture.port;
        let ca_pem = fixture.ca_pem.clone();
        let node = vless_node(port, &ca_pem, None, true);
        let mut peer = spawn_mux_peer(fixture, KEY);

        let mut outbound = dial_vless(&node, WAIT).await.expect("mux 建承载应成功");
        outbound.stream.write_all(PAYLOAD).await.expect("写载荷");
        let mut received = vec![0u8; PAYLOAD.len() + 2];
        timeout(WAIT, outbound.stream.read_exact(&mut received))
            .await
            .expect("读载荷超时")
            .expect("读载荷");
        assert_eq!(&received[2..], PAYLOAD, "回环载荷必须逐字节一致");

        peer.close.take().expect("关闭句柄").send(()).ok();
        let outcome = peer.task.await.expect("服务端任务").expect("服务端");
        assert!(
            outcome.frames_before_header >= 1,
            "客户端必须先发 mux 帧再拿响应头（实际收到 {} 帧后才 flush 响应头）",
            outcome.frames_before_header
        );
        println!(
            "mux 承载顺序正确：响应头在客户端发出 {} 帧之后才 flush",
            outcome.frames_before_header
        );
    })
    .await
    .expect("用例总超时");
}
