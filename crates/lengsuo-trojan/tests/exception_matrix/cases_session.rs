// 用例组 B：重放、半关闭、拨号失败收尾、拒绝后无悬挂任务。
//
// 本文件由 `tests/exception_matrix.rs` 以 `include!` 拼入该测试目标的根模块。

// ───────────────────────── 重放 ─────────────────────────

/// 重放同一请求头：在**同一个连接**上把合法头 + 载荷发送两次。
/// Trojan 是无状态协议、无重放防护（参考亦然）：第一次被处理，第二次的字节被当作
/// 第一条连接的应用载荷转发给目标（TCP 流无边界）。本用例**如实记录该行为**：
/// 断言不 panic、服务端不因重放而额外建立第二条到目标的连接（accept 计数 == 1）。
#[tokio::test]
async fn replay_same_header_is_not_specially_guarded() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        // 目标只读一次回复（第一次 CONNECT 的载荷），第二次头字节被并入同一流。
        let (echo_port, accepted) = spawn_echo(REPLY.len()).await;
        let (harness, task) = Harness::start(&identity, PASSWORD).await;
        let mut stream = identity.connect(harness.port).await;
        let header = valid_header(echo_port);
        stream.write_all(&header).await.unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        // 重放同一请求头（其 68 字节会被当作后续应用载荷）。
        stream.write_all(&header).await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = vec![0u8; REPLY.len()];
        timeout(WAIT, stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, REPLY, "第一次请求必须正常完成");
        // 关机并让服务端收尾（会读到重放字节作为载荷，最后我方 EOF 结束）。
        stream.shutdown().await.unwrap();
        let outcome = timeout(WAIT, task).await.unwrap().unwrap();
        // 参考亦无重放防护：允许正常结束（Ok）或中继 IO 结束，但不允许 panic/挂起。
        assert!(
            matches!(
                outcome,
                Ok(()) | Err(Error::Relay(_)) | Err(Error::Io(_)) | Err(Error::Timeout)
            ),
            "重放不得 panic 或挂起：{outcome:?}"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "重放不得额外建立到目标的连接（无重放防护，如实记录）"
        );
    })
    .await
    .unwrap();
}

// ───────────────────────── 半关闭 ─────────────────────────

/// 客户端 `shutdown(Write)` 后仍能读完响应（我方 FIN 不切断回程）。
#[tokio::test]
async fn client_half_close_still_receives_reply() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, accepted) = spawn_echo(REPLY.len()).await;
        let (harness, task) = Harness::start(&identity, PASSWORD).await;
        let mut stream = identity.connect(harness.port).await;
        stream.write_all(&valid_header(echo_port)).await.unwrap();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.flush().await.unwrap();
        // 写半关闭（WS 下无关；此处为裸 TLS 流上的 SHUT_WR）。
        stream.shutdown().await.unwrap();
        let mut reply = vec![0u8; REPLY.len()];
        timeout(WAIT, stream.read_exact(&mut reply))
            .await
            .expect("半关闭后回程仍须到达")
            .unwrap();
        assert_eq!(reply, REPLY);
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        let _ = timeout(WAIT, task).await;
    })
    .await
    .unwrap();
}

/// 服务端关闭后客户端 EOF 不挂死：目标端拒连（拨号失败）→ 服务端应尽快结束连接。
#[tokio::test]
async fn server_close_after_dial_failure_is_prompt() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        // 一个已释放的端口 → 拨号失败。
        let dead_port = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let (harness, task) = Harness::start(&identity, PASSWORD).await;
        let mut stream = identity.connect(harness.port).await;
        stream.write_all(&valid_header(dead_port)).await.unwrap();
        stream.flush().await.unwrap();
        // 服务端拨号失败 → 主动关闭；客户端读侧必须在观察上限内结束（EOF/Err），
        // 不能挂死到总预算耗尽。
        assert_peer_closed(&mut stream, CLOSE_BOUND).await;
        // 不变式：**拨号没有成功**。具体错误分类随平台而异，不得绑定单一取值：
        // - Linux：回环已释放端口 → 立即 ECONNREFUSED → `Error::Dial`。
        // - Windows 实机（2026-10-20 取证）：同场景被本机防火墙/安全软件静默丢弃
        //   SYN → 表现为 `Error::Timeout`。两者都证明「未建立到目标的连接」，
        //   且上面已断言客户端侧及时收到关闭。
        match timeout(WAIT, task).await.unwrap().unwrap() {
            Err(Error::Dial(_)) => {}
            Err(Error::Timeout) => {}
            other => panic!("期望拨号未成功（Dial 或 Timeout），得到 {other:?}"),
        }
    })
    .await
    .unwrap();
}

// ───────────────────── 超时与资源清理 ─────────────────────

/// 拒绝/超时后无悬挂任务：重复“写一半后静默”的连接，每次都在握手截止内结束，
/// 且处理任务全部`await`完成（计数器回到 0），不泄漏。
#[tokio::test]
async fn rejected_connections_leave_no_dangling_tasks() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, accepted) = spawn_echo(REPLY.len()).await;
        let header = valid_header(echo_port);
        for _ in 0..8 {
            let (harness, task) = Harness::start(&identity, PASSWORD).await;
            let mut stream = identity.connect(harness.port).await;
            // 写 58 字节（首块守卫通过：第 57 字节是 CR）后**静默** → 头部读不满，
            // 由握手截止（2s）有界拒绝。这才能真正观测到“超时”路径而非首块短路。
            stream.write_all(&header[..58]).await.unwrap();
            stream.flush().await.unwrap();
            assert_peer_closed(&mut stream, CLOSE_BOUND).await;
            // 任务必须真正结束（await 返回），live 计数回到 0。
            match timeout(WAIT, task).await.unwrap().unwrap() {
                Err(Error::Timeout) => {}
                other => panic!("期望握手超时，得到 {other:?}"),
            }
            assert_eq!(
                harness.live.load(Ordering::SeqCst),
                0,
                "连接处理任务必须已结束"
            );
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 0, "拒绝不得抵达业务目标");
    })
    .await
    .unwrap();
}
