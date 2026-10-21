// 异常路径：错误 PSK、截断头、篡改 AEAD tag、同 salt 重放，四项判据各配有限超时。
//
// 本文件由 `tests/xray_tcp_matrix.rs` 用 `include!` 文本并入同一模块；
// 共享常量与 `use` 全部留在 `tests/xray_tcp_matrix.rs` 入口文件。
/// 异常路径：错误 PSK、截断头、篡改 AEAD tag、同 salt 重放，四项判据各配有限超时。
/// 纯 Rust 原语即可判定，不依赖 Xray；判据按下文每个 `assert!(matches!(...))` 锁定。
#[tokio::test]
#[ignore = "随参考套件以 --ignored 一起运行"]
async fn receiver_rejects_abnormal_streams() {
    let method = Method::Aes256;
    let key_a = Key::new(method, &[0x11; 32]).expect("假密钥 A 可用");
    let key_b = Key::new(method, &[0x99; 32]).expect("假密钥 B 可用");
    let salt = vec![0x5A; method.key_len()];
    let target = TargetAddr::V4([127, 0, 0, 1], 9);
    let now = now_secs();

    // 1) 错误 PSK：同一 salt 下的请求开场，用另一个密钥的读端必须认证失败。
    {
        let wire = sealed_request(&key_a, &salt, &target, b"wrong-key", now).await;
        let (mut client, mut server) = loopback_pair().await;
        client.write_all(&wire).await.expect("应可写入");
        drop(client);
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut reader = Reader::new(key_b.clone(), Direction::Request, Duration::from_secs(2))
            .expect("可构造读端");
        let outcome = timeout(WAIT, reader.open(&mut server, &mut replay, clock(), None))
            .await
            .expect("错误 PSK 判定超时");
        let error = rejected_tcp(outcome, "错误 PSK 的密文");
        assert!(
            matches!(error, Error::Authentication),
            "错误 PSK 应报 Authentication，实际 {error:?}"
        );
    }

    // 2) 截断头：只写 salt 后关闭，读端在固定头处应报 Length，而非认证或悬挂。
    {
        let (mut client, mut server) = loopback_pair().await;
        client.write_all(&salt).await.expect("应可写入 salt");
        client.shutdown().await.expect("关写半失败");
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut reader = Reader::new(key_a.clone(), Direction::Request, Duration::from_secs(2))
            .expect("可构造读端");
        let outcome = timeout(WAIT, reader.open(&mut server, &mut replay, clock(), None))
            .await
            .expect("截断头判定超时");
        let error = rejected_tcp(outcome, "截断头");
        assert!(
            matches!(error, Error::Length),
            "截断头应报 Length，实际 {error:?}"
        );
    }

    // 3) 篡改固定头 AEAD tag：翻转固定头 auth tag 首字节，读端必须认证失败。
    {
        let mut wire = sealed_request(&key_a, &salt, &target, b"tampered", now).await;
        wire[salt.len() + 11] ^= 0x01;
        let (mut client, mut server) = loopback_pair().await;
        client.write_all(&wire).await.expect("应可写入");
        drop(client);
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut reader = Reader::new(key_a.clone(), Direction::Request, Duration::from_secs(2))
            .expect("可构造读端");
        let outcome = timeout(WAIT, reader.open(&mut server, &mut replay, clock(), None))
            .await
            .expect("篡改 tag 判定超时");
        let error = rejected_tcp(outcome, "篡改 AEAD tag 的密文");
        assert!(
            matches!(error, Error::Authentication),
            "篡改 AEAD tag 应报 Authentication，实际 {error:?}"
        );
    }

    // 4) 同 salt 重放：同一 salt 第二次合法开场必须被 SessionReplay 判为重放。
    {
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let first = sealed_request(&key_a, &salt, &target, b"first", now).await;
        let (mut client, mut server) = loopback_pair().await;
        client.write_all(&first).await.expect("首条应可写入");
        drop(client);
        let mut reader = Reader::new(key_a.clone(), Direction::Request, Duration::from_secs(2))
            .expect("可构造读端");
        let opened = timeout(WAIT, reader.open(&mut server, &mut replay, clock(), None))
            .await
            .expect("首条判定超时")
            .expect("首条合法开场应通过");
        assert_eq!(opened.payload, b"first", "首条开场载荷应可解出");

        let second = sealed_request(&key_a, &salt, &target, b"second", now).await;
        let (mut client, mut server) = loopback_pair().await;
        client.write_all(&second).await.expect("次条应可写入");
        drop(client);
        let mut reader = Reader::new(key_a.clone(), Direction::Request, Duration::from_secs(2))
            .expect("可构造读端");
        let outcome = timeout(WAIT, reader.open(&mut server, &mut replay, clock(), None))
            .await
            .expect("重放判定超时");
        let error = rejected_tcp(outcome, "同 salt 第二次开场");
        assert!(
            matches!(error, Error::Replay),
            "同 salt 重放应报 Replay，实际 {error:?}"
        );
    }
}
