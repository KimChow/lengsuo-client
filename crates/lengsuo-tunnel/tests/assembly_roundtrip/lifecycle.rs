// 生命周期与角色校验主题：keepalive 启停时机、cookie 路径、角色错配、零间隔 keepalive。
//
// 本文件由入口 `assembly_roundtrip.rs` 用 `include!` **文本并入**同一模块，
// 故不写 `use`（入口已全部引入），用例名也不带模块前缀。

// ---------------------------------- 6. 会话未就绪不发 keepalive（就绪后才发）

#[tokio::test]
async fn keepalive_starts_only_after_session_ready() {
    let (a_socket, b_socket) = pair().await;

    // 会话**未就绪**：keepalive 任务**尚未启动** ⇒ 一个字节都不发。
    let mut driver = KeepaliveDriver::new(KeepaliveConfig {
        interval: Some(Duration::from_millis(50)),
    })
    .expect("keepalive 驱动可建");
    assert!(
        !driver.is_running(),
        "会话未就绪时 keepalive 任务不得已启动"
    );
    // 未 `activate` ⇒ 对端收不到任何东西。
    let mut buf = buffer();
    let quiet = tokio::time::timeout(QUIET, b_socket.recv_frame(&mut buf)).await;
    assert!(quiet.is_err(), "会话未就绪时不得发出任何 keepalive");

    // 会话**未就绪**时，装配层**拒绝**启动 keepalive。
    let mut assembly = Assembly::new(initiator_config()).expect("发起方装配层可建");
    let err = assembly
        .start_keepalive(&mut driver, a_socket.clone())
        .expect_err("会话未就绪时必须拒绝启动 keepalive");
    assert!(
        matches!(err, AssemblyError::SessionNotEstablished),
        "期望 SessionNotEstablished，实际 {err:?}"
    );
    assert!(
        !driver.is_running(),
        "拒绝之后 keepalive 任务仍然不得已启动"
    );

    // 会话**就绪** ⇒ 启动任务 ⇒ 对端开始收到 keepalive。
    let (mut initiator, _responder, _, _) = handshake_over_udp().await;
    initiator
        .start_keepalive(&mut driver, a_socket)
        .expect("就绪后 keepalive 应当能启动");
    assert!(driver.is_running(), "就绪后 keepalive 任务必须已启动");

    let mut buf = buffer();
    let got = tokio::time::timeout(TIMEOUT, b_socket.recv_frame(&mut buf))
        .await
        .expect("就绪后 keepalive 必须在超时内到达")
        .expect("应当收到一个合法帧");
    assert_eq!(
        got.frame_type,
        FrameType::Keepalive,
        "keepalive 帧类型必须正确"
    );
    assert!(got.payload.is_empty(), "keepalive 的载荷必须零长");

    tokio::time::timeout(TIMEOUT, driver.stop())
        .await
        .expect("keepalive 任务必须在超时内退出");
}

// ------------------------------------------------------- 附加：cookie 路径

#[tokio::test]
async fn mac_failure_is_reported_so_caller_can_issue_cookie_reply() {
    let responder = Assembly::new(responder_config()).expect("响应方装配层可建");
    let mut responder_hs = ResponderHandshake::new(&responder).expect("响应方握手上下文可建");

    // 一条**长度合法但 MAC1 不对**的 initiation。
    let mut broken = [0u8; 148];
    broken[..4].copy_from_slice(&1u32.to_le_bytes());
    broken[4..8].copy_from_slice(&7u32.to_le_bytes());

    let err = responder_hs
        .consume_initiation(&broken)
        .expect_err("MAC1 不符必须被拒绝");
    match err {
        AssemblyError::HandshakeRejected { reason } => {
            assert_eq!(reason, "MAC1 校验失败", "失败原因必须可判定");
        }
        other => panic!("期望 HandshakeRejected，实际 {other:?}"),
    }

    // ⛔ 失败**不得**直接丢弃：调用方据此签发 cookie reply（64 字节）。
    let reply = responder_hs
        .create_cookie_reply(&broken, b"203.0.113.1:51820", [0x44; 32], [0x55; 24])
        .expect("cookie reply 必须能签发");
    assert_eq!(reply.len(), 64, "cookie reply 必须是 64 字节");
    assert_eq!(
        &reply[..4],
        &3u32.to_le_bytes(),
        "cookie reply 的类型字段必须是 3"
    );
}

// ------------------------------------------------- 附加：角色错配被拒

#[tokio::test]
async fn wrong_role_operations_are_rejected() {
    let initiator = Assembly::new(initiator_config()).expect("发起方装配层可建");
    let err = ResponderHandshake::new(&initiator).expect_err("发起方不得当响应方用");
    assert!(
        matches!(err, AssemblyError::WrongRole { .. }),
        "期望 WrongRole，实际 {err:?}"
    );

    let responder = Assembly::new(responder_config()).expect("响应方装配层可建");
    let err = InitiatorHandshake::new(&responder, SEED).expect_err("响应方不得当发起方用");
    assert!(
        matches!(err, AssemblyError::WrongRole { .. }),
        "期望 WrongRole，实际 {err:?}"
    );
}

// --------------------------------------- 附加：零间隔 keepalive 被拒（busy loop）

#[tokio::test]
async fn zero_interval_keepalive_is_rejected() {
    let err = KeepaliveDriver::new(KeepaliveConfig {
        interval: Some(Duration::ZERO),
    })
    .expect_err("零间隔必须被拒绝（busy loop）");
    assert!(
        matches!(err, AssemblyError::KeepaliveDisabled(_)),
        "期望 KeepaliveDisabled，实际 {err:?}"
    );
}
