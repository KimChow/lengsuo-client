// fail-closed 类用例：缺 Settings / 错误口令 / 空口令 / 活跃流超上限。
//
// 本文件由 `tests/server_roundtrip.rs` 用 `include!` 文本并入同一模块；`use` 与
// 共享助手都在入口文件。

/// Settings 之前发 SYN：必须回 Alert 文本并以协议失败结束（fail-closed），
/// 且不建立任何流。
#[tokio::test]
async fn syn_before_settings_is_alerted() {
    let mut harness = Harness::start(PASSWORD).await;
    harness
        .send(Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        })
        .await;
    let alert = harness.expect(Command::Alert).await;
    let text = String::from_utf8_lossy(&alert.data);
    assert!(
        text.contains("settings"),
        "Alert 文本应说明缺 Settings，实际：{text}"
    );
    let outcome = harness.finish().await;
    assert!(outcome.is_err(), "违规会话应以失败结束：{outcome:?}");
}

/// 错误口令：认证失败，会话在进入帧循环前就结束，不产生任何统计。
#[tokio::test]
async fn wrong_password_fails_before_frame_loop() {
    let mut harness = Harness::start(b"correct-password").await;
    // Harness 已用 b"correct-password" 认证；这里改用错误口令重连。
    let _ = &mut harness;
    drop(harness);

    let (client, server_side) = tokio::io::duplex(1024);
    let config = ServerConfig::new(PASSWORD, WAIT);
    let task = tokio::spawn(server::serve(server_side, config));
    let mut client = client;
    Credential::new(b"wrong-password")
        .send(&mut client, b"", WAIT)
        .await
        .expect("发送错误口令");
    drop(client);
    let outcome = timeout(TOTAL, task)
        .await
        .expect("超时")
        .expect("任务 panic");
    assert!(
        matches!(outcome, Err(Error::Authentication)),
        "应为认证失败，实际：{outcome:?}"
    );
}

/// 空口令边界：口令为空时 SHA256("") 仍是合法摘要；只是对端摘要不同即拒绝。
#[tokio::test]
async fn empty_configured_password_rejects_non_empty() {
    let (client, server_side) = tokio::io::duplex(1024);
    let config = ServerConfig::new(b"", WAIT);
    let task = tokio::spawn(server::serve(server_side, config));
    let mut client = client;
    Credential::new(b"non-empty")
        .send(&mut client, b"", WAIT)
        .await
        .expect("发送");
    drop(client);
    let outcome = timeout(TOTAL, task)
        .await
        .expect("超时")
        .expect("任务 panic");
    assert!(matches!(outcome, Err(Error::Authentication)));
}

/// 活跃流容量：达到 `max_streams` 后再开流，服务端必须 fail-closed 结束会话
/// （状态机 `InvalidStream("活跃流已达上限")`）。
#[tokio::test]
async fn exceeding_max_streams_ends_session() {
    let (client, server_side) = tokio::io::duplex(64 * 1024);
    let mut config = ServerConfig::new(PASSWORD, WAIT);
    config.max_streams = 2;
    let task = tokio::spawn(server::serve(server_side, config));
    let mut client = client;
    Credential::new(PASSWORD)
        .send(&mut client, b"", WAIT)
        .await
        .expect("认证");
    let md5 = PaddingScheme::default_scheme().md5().to_owned();
    settings(&md5)
        .write(&mut client, WAIT)
        .await
        .expect("Settings");
    for sid in 1..=2 {
        Frame {
            command: Command::Syn,
            stream_id: sid,
            data: Vec::new(),
        }
        .write(&mut client, WAIT)
        .await
        .expect("SYN");
    }
    // 第三条超出容量：会话应以失败结束。
    Frame {
        command: Command::Syn,
        stream_id: 3,
        data: Vec::new(),
    }
    .write(&mut client, WAIT)
    .await
    .expect("SYN");
    drop(client);
    let outcome = timeout(TOTAL, task)
        .await
        .expect("超时")
        .expect("任务 panic");
    assert!(outcome.is_err(), "超容量应结束会话，实际：{outcome:?}");
}
