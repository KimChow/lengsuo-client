// 认证块篡改 3 条：摘要改 1 bit / padding 长度超上限 / 摘要整段替换。
//
// 本文件由 `tests/tamper_matrix/frame_tamper.rs` 用 `include!` 文本并入同一模块；
// `use` 在入口文件，助手 `auth_block`（本主题专属）在本文件。

/// 认证块：`SHA256(口令)` 32 字节 + BE16 padding 长度 + padding。
/// 用**生产代码路径**（`Credential::send`）生成，避免自造摘要实现。
async fn auth_block(password: &[u8]) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    Credential::new(password)
        .send(&mut buffer, b"", WAIT)
        .await
        .expect("生成认证块");
    buffer
}

/// 认证块篡改：口令摘要改 1 bit ⇒ 必须认证失败，且**不得**进入帧循环。
///
/// 判据位置：`src/auth.rs:67-69`——常量时间比对（`subtle::ConstantTimeEq`）
/// 不等即 `Error::Authentication`。
/// 参考 anytls-go `cmd/server/inbound_tcp.go:40-45`：32 字节摘要不等即走
/// `fallback`（未实现 = 直接断连）⇒ 与本仓一致。
#[tokio::test]
async fn authentication_block_tampering_is_rejected() {
    timeout(TOTAL, async {
        let target = spawn_target().await;
        let (client, server_side) = tokio::io::duplex(64 * 1024);
        let config = lengsuo_anytls::server::ServerConfig::new(PASSWORD, WAIT);
        let task = tokio::spawn(lengsuo_anytls::server::serve(server_side, config));
        let mut client = client;

        // 用生产代码路径生成认证块，再改摘要的第 1 个字节。
        let mut block = auth_block(PASSWORD).await;
        flip_bit(&mut block, 0);
        client.write_all(&block).await.expect("写篡改认证块");
        client.flush().await.expect("刷新");

        // 服务端不得回应任何帧（认证失败发生在帧循环之前）。
        // 注意：`timeout(...)` 成功时返回 `Ok(inner)`，故要判**内层**结果。
        let read = timeout(WAIT, Frame::read(&mut client, u16::MAX, WAIT)).await;
        match read {
            Err(_elapsed) => {}
            Ok(Err(err)) => assert!(
                matches!(err, Error::Io(_)),
                "认证失败后服务端只能断开，不得回语义帧，实际错误：{err}"
            ),
            Ok(Ok(_frame)) => panic!("认证失败后服务端不得发送任何帧"),
        }

        drop(client);
        let outcome = timeout(TOTAL, task)
            .await
            .expect("会话结束超时")
            .expect("会话任务 panic");
        assert!(
            matches!(outcome, Err(Error::Authentication)),
            "认证块篡改必须以 Error::Authentication 失败，实际：{outcome:?}"
        );
        assert_eq!(
            target.accepted.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "认证失败不得触发任何拨号"
        );
    })
    .await
    .expect("用例超时");
}

/// 认证块篡改：padding 长度字段改大到超上限 ⇒ 必须被拒绝（`Error::TooLarge`）。
///
/// 判据位置：`src/auth.rs:57-59`——`length > max_padding` 即 `Error::TooLarge`。
/// 上限来自 `src/server/mod.rs:21`（`PADDING_LIMIT = 4096`）。
#[tokio::test]
async fn authentication_padding_length_above_limit_is_rejected() {
    timeout(TOTAL, async {
        let (client, server_side) = tokio::io::duplex(64 * 1024);
        let config = lengsuo_anytls::server::ServerConfig::new(PASSWORD, WAIT);
        let task = tokio::spawn(lengsuo_anytls::server::serve(server_side, config));
        let mut client = client;

        let mut block = auth_block(PASSWORD).await;
        // 摘要正确；把 padding 长度改成 0xFFFF（远超 4096 上限）。
        block[32..34].copy_from_slice(&u16::MAX.to_be_bytes());
        client.write_all(&block).await.expect("写篡改认证块");
        client.flush().await.expect("刷新");

        drop(client);
        let outcome = timeout(TOTAL, task)
            .await
            .expect("会话结束超时")
            .expect("会话任务 panic");
        assert!(
            matches!(outcome, Err(Error::TooLarge)),
            "认证块 padding 长度超上限必须以 Error::TooLarge 失败，实际：{outcome:?}"
        );
    })
    .await
    .expect("用例超时");
}

/// 认证块篡改：摘要整段替换成等长垃圾 ⇒ 同样必须认证失败。
///
/// 与 `authentication_block_tampering_is_rejected` 互补：证明判据是
/// **摘要比对**而不是「碰巧有一位不同」。
#[tokio::test]
async fn authentication_block_fully_replaced_is_rejected() {
    timeout(TOTAL, async {
        let (client, server_side) = tokio::io::duplex(64 * 1024);
        let config = lengsuo_anytls::server::ServerConfig::new(PASSWORD, WAIT);
        let task = tokio::spawn(lengsuo_anytls::server::serve(server_side, config));
        let mut client = client;

        let mut block = auth_block(PASSWORD).await;
        for byte in block.iter_mut().take(32) {
            *byte = 0x00;
        }
        client.write_all(&block).await.expect("写替换认证块");
        client.flush().await.expect("刷新");

        drop(client);
        let outcome = timeout(TOTAL, task)
            .await
            .expect("会话结束超时")
            .expect("会话任务 panic");
        assert!(
            matches!(outcome, Err(Error::Authentication)),
            "整段替换的摘要必须以 Error::Authentication 失败，实际：{outcome:?}"
        );
    })
    .await
    .expect("用例超时");
}
