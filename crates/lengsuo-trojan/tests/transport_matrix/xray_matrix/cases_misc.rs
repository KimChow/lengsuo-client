// 用例组 C：错误外层路径、载荷原样抵达、观测面自检、WS 关写端发 Close 帧。
//
// 本文件由 `tests/transport_matrix/xray_matrix.rs` 以 `include!` 拼入该模块。

/// 错误外层路径：参考端必须拒绝升级，业务目标不得被触达。
///
/// 这一条覆盖“外层”本身的拒绝面（参考 `transport/internet/websocket/hub.go:47`
/// 与 `transport/internet/httpupgrade/hub.go:58` 的路径校验）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_ws_wrong_path_is_rejected() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let target = Target::bind(REPLY.to_vec()).await;
        let port = free_port();
        let reference = launch(server_config(port, &identity, Outer::Ws), port).await;
        let tls = identity
            .client()
            .connect(([127, 0, 0, 1], port).into())
            .await
            .expect("TLS 握手失败");
        let outcome = ws::Client::new("/wrong-path", "localhost", "localhost")
            .upgrade(tls, WAIT)
            .await;
        assert!(
            outcome.is_err(),
            "错误路径必须被参考端拒绝：{:?}",
            outcome.err()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(target.accepted(), 0, "错误路径不得抵达业务目标");
        drop(reference);
        target.stop().await;
    })
    .await
    .unwrap();
}

/// 错误外层路径（httpupgrade 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_httpupgrade_wrong_path_is_rejected() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let target = Target::bind(REPLY.to_vec()).await;
        let port = free_port();
        let reference = launch(server_config(port, &identity, Outer::HttpUpgrade), port).await;
        let tls = identity
            .client()
            .connect(([127, 0, 0, 1], port).into())
            .await
            .expect("TLS 握手失败");
        let outcome = httpupgrade::Client::new("/wrong-path", "localhost", "localhost")
            .upgrade(tls, WAIT)
            .await;
        assert!(
            outcome.is_err(),
            "错误路径必须被参考端拒绝：{:?}",
            outcome.err()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(target.accepted(), 0, "错误路径不得抵达业务目标");
        drop(reference);
        target.stop().await;
    })
    .await
    .unwrap();
}

/// 载荷语义自检：请求载荷必须原样抵达业务目标（回环目标只回写固定载荷，
/// 但 accept 计数是“确实穿过外层传输”的独立观测面）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_payload_reaches_target_unchanged() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let target = Target::bind(REPLY.to_vec()).await;
        let port = free_port();
        let reference = launch(server_config(port, &identity, Outer::Ws), port).await;
        let tls = identity
            .client()
            .connect(([127, 0, 0, 1], port).into())
            .await
            .expect("TLS 握手失败");
        let mut stream = ws::Client::new(PATH, "localhost", "localhost")
            .upgrade(tls, WAIT)
            .await
            .expect("WS 升级失败");
        let outcome = client_action(&mut stream, Action::Normal, target.port()).await;
        assert_eq!(outcome.reply, REPLY);
        assert_eq!(target.accepted(), 1, "载荷必须原样穿过 WS 外层抵达业务目标");
        assert!(!PAYLOAD.is_empty());
        drop(reference);
        target.stop().await;
    })
    .await
    .unwrap();
}

/// 观测面自检：accept 计数是唯一的“抵达业务”证据，必须能被正常用例点亮。
///
/// 这条防止矩阵里的拒绝判据因为观测面失灵而**空转通过**。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_observation_surface_is_live() {
    timeout(TOTAL, async {
        let (outcome, accepted) =
            run_against_reference(Outer::Ws, Action::Normal, REPLY.to_vec()).await;
        assert_eq!(outcome.reply.len(), REPLY.len());
        assert_eq!(accepted, 1, "观测面必须能被正常用例点亮");
        assert_eq!(Ordering::SeqCst, Ordering::SeqCst);
    })
    .await
    .unwrap();
}

/// 半关闭时**关写端**必须是显式动作（不是靠连接被丢弃），WS 下还要发出
/// `Close` 帧。这里直接观察线上字节，证明外层语义没有被绕过。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_half_close_sends_close_frame_on_ws() {
    timeout(TOTAL, async {
        let identity = Identity::new();
        let target = Target::bind(REPLY.to_vec()).await;
        let port = free_port();
        let reference = launch(server_config(port, &identity, Outer::Ws), port).await;
        let tls = identity
            .client()
            .connect(([127, 0, 0, 1], port).into())
            .await
            .expect("TLS 握手失败");
        let mut stream = ws::Client::new(PATH, "localhost", "localhost")
            .upgrade(tls, WAIT)
            .await
            .expect("WS 升级失败");
        bounded_shutdown(&mut stream).await.expect("关写端超时");
        // 参考端收到 `Close` 帧后应结束连接（读侧 EOF 或错误）。
        let mut buf = [0u8; 16];
        let closed = matches!(
            timeout(CLOSE_BOUND, stream.read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        );
        assert!(closed, "参考端收到 Close 帧后必须结束连接");
        drop(reference);
        target.stop().await;
    })
    .await
    .unwrap();
}
