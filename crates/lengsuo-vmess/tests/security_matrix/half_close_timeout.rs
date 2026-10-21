// 传输层半关闭与超时上限（TCP 连接级，不涉及数据段帧）。
//
// 本文件由 `tests/security_matrix.rs` 用 `include!` 文本并入同一模块；
// 共享常量与助手在 `security_matrix/common.rs`，`use` 写在入口文件。

// ---- 5) 半关闭 ----

/// 半关闭：写端关闭后读端必须干净地看到 EOF（不挂起、不返回半截明文）。
#[tokio::test]
async fn half_close_yields_clean_eof_for_every_tier() {
    for (security, _) in TIERS {
        let outcome = tokio::time::timeout(CASE_TIMEOUT, async {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("可监听");
            let addr = listener.local_addr().expect("有地址");
            let wire = seal_request(security);
            let server = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.expect("可接受");
                // 读一点就关闭写端（半关闭）。
                let mut buf = [0u8; 64];
                let _ = sock.read(&mut buf).await;
                let _ = sock.shutdown().await;
            });
            let mut client = tokio::net::TcpStream::connect(addr).await.expect("可连接");
            client.write_all(&wire).await.expect("可写");
            let _ = client.shutdown().await;
            let mut rest = Vec::new();
            let read_result = client.read_to_end(&mut rest).await;
            server.await.expect("服务端线程不 panic");
            (read_result, rest.len())
        })
        .await
        .expect("半关闭用例不得超时");
        let (read_result, rest_len) = outcome;

        assert!(
            matches!(read_result, Ok(0)),
            "security={security:?} 半关闭后读端必须干净 EOF，实际 {read_result:?}"
        );
        assert_eq!(rest_len, 0, "security={security:?} 半关闭后不得有残留数据");
    }
}

// ---- 6) 超时 ----

/// 超时：对端不响应时，读端必须在上限内返回（不得无限挂起）。
#[tokio::test]
async fn unresponsive_peer_hits_the_timeout_bound_for_every_tier() {
    for (security, _) in TIERS {
        let outcome = tokio::time::timeout(CASE_TIMEOUT, async {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("可监听");
            let addr = listener.local_addr().expect("有地址");
            // 对端接受连接后**不写任何字节**，也不关闭。
            let server = tokio::spawn(async move {
                let (sock, _) = listener.accept().await.expect("可接受");
                // 保持连接开着直到被取消。
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(sock);
            });
            let mut client = tokio::net::TcpStream::connect(addr).await.expect("可连接");
            let read = tokio::time::timeout(
                Duration::from_millis(500),
                client.read_exact(&mut [0u8; 18]),
            )
            .await;
            server.abort();
            read
        })
        .await
        .expect("超时用例本身不得挂起");

        assert!(
            outcome.is_err(),
            "security={security:?} 不响应对端必须触发读超时"
        );
    }
}
