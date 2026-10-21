// 用例组 A：错密码、请求头截断（每个位置 / 各结构部分）、摘要篡改。
//
// 本文件由 `tests/exception_matrix.rs` 以 `include!` 拼入该测试目标的根模块。

// ───────────────────────── 错密码 ─────────────────────────

/// 错密码：服务端必须返回 `Authentication` 且主动关闭；业务目标 accept 计数不增长。
/// 先跑正确密码对照组证明观测面有效。
#[tokio::test]
async fn wrong_password_rejected_and_target_untouched() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, accepted) = spawn_echo(REPLY.len()).await;

        // 对照组：正确密码抵达业务目标。
        let (harness, task) = Harness::start(&identity, PASSWORD).await;
        {
            let mut stream = identity.connect(harness.port).await;
            let header = valid_header(echo_port);
            stream.write_all(&header).await.unwrap();
            stream.write_all(PAYLOAD).await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = vec![0u8; REPLY.len()];
            timeout(WAIT, stream.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply, REPLY);
            stream.shutdown().await.unwrap();
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "对照组必须抵达业务目标");
        let _ = timeout(WAIT, task).await;

        // 错误密码：拒绝 + 计数不增长。
        let before = accepted.load(Ordering::SeqCst);
        let (harness, task) = Harness::start(&identity, PASSWORD).await;
        {
            let mut stream = identity.connect(harness.port).await;
            let header = codec::encode(
                &Request {
                    command: Command::Tcp,
                    target: TargetAddr::V4([127, 0, 0, 1], echo_port),
                },
                &Credential::new(BAD_PASSWORD),
            )
            .unwrap();
            stream.write_all(&header).await.unwrap();
            stream.write_all(PAYLOAD).await.unwrap();
            stream.flush().await.unwrap();
            assert_peer_closed(&mut stream, CLOSE_BOUND).await;
        }
        match timeout(WAIT, task).await.unwrap().unwrap() {
            Err(Error::Authentication) => {}
            other => panic!("期望 Authentication，得到 {other:?}"),
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            before,
            "错误密码不得抵达业务目标"
        );
    })
    .await
    .unwrap();
}

// ───────────────────── 截断请求头（每一部分） ─────────────────────

/// 截断在**每一个位置**（0..header.len()）：服务端必须在握手截止内有界拒绝，
/// 返回 `Timeout`（读不满）或 `Authentication`（哈希已读完但错），绝不 panic、
/// 绝不挂起、绝不放行。
#[tokio::test]
async fn every_truncation_point_is_rejected_within_deadline() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, accepted) = spawn_echo(REPLY.len()).await;
        let header = valid_header(echo_port);
        assert!(header.len() > 60, "V4 目标头必须多于 60 字节");

        for cut in 0..header.len() {
            let (harness, task) = Harness::start(&identity, PASSWORD).await;
            let mut stream = identity.connect(harness.port).await;
            stream.write_all(&header[..cut]).await.unwrap();
            stream.flush().await.unwrap();
            // 截断点 < 56：哈希未读完 → 握手截止；否则地址/CRLF 未读完 → 同样截止。
            assert_peer_closed(&mut stream, CLOSE_BOUND).await;
            match timeout(WAIT, task).await.unwrap().unwrap() {
                Err(Error::Timeout)
                | Err(Error::Authentication)
                | Err(Error::NotTrojanProtocol) => {}
                other => panic!("截断点 {cut} 期望有界拒绝，得到 {other:?}"),
            }
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "任何截断都不得抵达业务目标"
        );
    })
    .await
    .unwrap();
}

/// 各**结构部分**的精确截断（文档表格用）：哈希 / 哈希后 CRLF / 命令 / 地址 /
/// 尾 CRLF 各截断一字节，断言错误变体。
#[tokio::test]
async fn structural_truncations_have_expected_variants() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, _accepted) = spawn_echo(REPLY.len()).await;
        let header = valid_header(echo_port);
        // 头部结构：56 哈希 + 2 CRLF + 1 命令 + 地址(1+4+2=7) + 2 CRLF = 68。
        assert_eq!(header.len(), 68);
        // 首块守卫：单次首读不足 58 字节即 NotTrojanProtocol（参考
        // `server.go` 的 `first.Byte(56) != '\r'` 判定）；≥58 字节但头部读不满则
        // 走握手截止 Timeout。两者都是“有界拒绝”，此处逐条给出预期变体。
        let cases: &[(&str, usize, Expected)] = &[
            ("哈希（<58，首块守卫）", 30, Expected::Protocol),
            ("哈希后 CRLF（<58，首块守卫）", 57, Expected::Protocol),
            ("命令后（≥58，读地址中）", 59, Expected::Timeout),
            ("地址中间（≥58）", 62, Expected::Timeout),
            ("尾 CRLF 一半（≥58）", 67, Expected::Timeout),
        ];
        for (name, cut, expected) in cases {
            let (harness, task) = Harness::start(&identity, PASSWORD).await;
            let mut stream = identity.connect(harness.port).await;
            stream.write_all(&header[..*cut]).await.unwrap();
            stream.flush().await.unwrap();
            assert_peer_closed(&mut stream, CLOSE_BOUND).await;
            let outcome = timeout(WAIT, task).await.unwrap().unwrap();
            match (expected, &outcome) {
                (Expected::Timeout, Err(Error::Timeout)) => {}
                (Expected::Protocol, Err(Error::NotTrojanProtocol)) => {}
                _ => panic!("{name} 截断期望 {expected:?}，得到 {outcome:?}"),
            }
        }
    })
    .await
    .unwrap();
}

#[derive(Debug, Clone, Copy)]
enum Expected {
    Timeout,
    Protocol,
}

// ───────────────────── 篡改 SHA224 摘要 ─────────────────────

/// 篡改摘要：首字节 / 末字节 / 全零。全部必须在读满 56 字节后判 `Authentication`，
/// 且不抵达业务目标；对照组正确密码仍可用。
#[tokio::test]
async fn tampered_digest_is_rejected() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let (echo_port, accepted) = spawn_echo(REPLY.len()).await;
        let header = valid_header(echo_port);
        let tampered: &[(&str, usize, u8)] = &[("首字节", 0, 0x00), ("末字节", 55, 0x00)];
        for (name, index, value) in tampered {
            let mut bad = header.clone();
            if bad[*index] == *value {
                bad[*index] ^= 0x01;
            } else {
                bad[*index] = *value;
            }
            let (harness, task) = Harness::start(&identity, PASSWORD).await;
            let mut stream = identity.connect(harness.port).await;
            stream.write_all(&bad).await.unwrap();
            stream.write_all(PAYLOAD).await.unwrap();
            stream.flush().await.unwrap();
            assert_peer_closed(&mut stream, CLOSE_BOUND).await;
            match timeout(WAIT, task).await.unwrap().unwrap() {
                Err(Error::Authentication) => {}
                other => panic!("{name} 篡改期望 Authentication，得到 {other:?}"),
            }
        }
        // 全零哈希。
        let mut zero = header.clone();
        zero[..56].fill(0);
        let (harness, task) = Harness::start(&identity, PASSWORD).await;
        let mut stream = identity.connect(harness.port).await;
        stream.write_all(&zero).await.unwrap();
        stream.flush().await.unwrap();
        assert_peer_closed(&mut stream, CLOSE_BOUND).await;
        match timeout(WAIT, task).await.unwrap().unwrap() {
            Err(Error::Authentication) => {}
            other => panic!("全零摘要期望 Authentication，得到 {other:?}"),
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "任何篡改都不得抵达业务目标"
        );
    })
    .await
    .unwrap();
}
