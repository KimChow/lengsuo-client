// 用例组 A：正常往返、错密码、请求头截断（逐外层各一条）。
//
// 本文件由 `tests/transport_matrix/xray_matrix.rs` 以 `include!` 拼入该模块。

/// 正常往返（raw / tcp 档）：回程逐字节一致，业务目标恰被抵达一次。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_tcp_normal() {
    timeout(TOTAL, async {
        let (outcome, accepted) =
            run_against_reference(Outer::Tcp, Action::Normal, REPLY.to_vec()).await;
        assert_eq!(
            outcome.reply,
            REPLY,
            "{} 回程必须与请求逐字节一致",
            Action::Normal.name()
        );
        assert_eq!(accepted, 1, "必须恰好抵达业务目标一次");
    })
    .await
    .unwrap();
}

/// 正常往返（ws 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_ws_normal() {
    timeout(TOTAL, async {
        let (outcome, accepted) =
            run_against_reference(Outer::Ws, Action::Normal, REPLY.to_vec()).await;
        assert_eq!(
            outcome.reply,
            REPLY,
            "{} 回程必须与请求逐字节一致",
            Action::Normal.name()
        );
        assert_eq!(accepted, 1, "必须恰好抵达业务目标一次");
    })
    .await
    .unwrap();
}

/// 正常往返（httpupgrade 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_httpupgrade_normal() {
    timeout(TOTAL, async {
        let (outcome, accepted) =
            run_against_reference(Outer::HttpUpgrade, Action::Normal, REPLY.to_vec()).await;
        assert_eq!(
            outcome.reply,
            REPLY,
            "{} 回程必须与请求逐字节一致",
            Action::Normal.name()
        );
        assert_eq!(accepted, 1, "必须恰好抵达业务目标一次");
    })
    .await
    .unwrap();
}

/// 错密码（raw / tcp 档）：业务目标不得被触达。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_tcp_wrong_password() {
    timeout(TOTAL, async {
        let (outcome, accepted) =
            run_against_reference(Outer::Tcp, Action::WrongPassword, REPLY.to_vec()).await;
        assert!(
            !outcome.unexpected_data,
            "{} 不得收到任何数据",
            Action::WrongPassword.name()
        );
        assert_eq!(accepted, 0, "错密码不得抵达业务目标");
    })
    .await
    .unwrap();
}

/// 错密码（ws 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_ws_wrong_password() {
    timeout(TOTAL, async {
        let (outcome, accepted) =
            run_against_reference(Outer::Ws, Action::WrongPassword, REPLY.to_vec()).await;
        assert!(!outcome.unexpected_data, "错密码不得收到任何数据");
        assert_eq!(accepted, 0, "错密码不得抵达业务目标");
    })
    .await
    .unwrap();
}

/// 错密码（httpupgrade 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_httpupgrade_wrong_password() {
    timeout(TOTAL, async {
        let (outcome, accepted) =
            run_against_reference(Outer::HttpUpgrade, Action::WrongPassword, REPLY.to_vec()).await;
        assert!(!outcome.unexpected_data, "错密码不得收到任何数据");
        assert_eq!(accepted, 0, "错密码不得抵达业务目标");
    })
    .await
    .unwrap();
}

/// 截断请求头（raw / tcp 档）：参考端必须**主动结束**连接，业务目标不得被触达。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_tcp_truncated() {
    timeout(TOTAL, async {
        for (cut, label) in TRUNCATION_CUTS {
            let identity = Identity::new();
            let target = Target::bind(REPLY.to_vec()).await;
            let port = free_port();
            let reference = launch(server_config(port, &identity, Outer::Tcp), port).await;
            let mut stream = identity
                .client()
                .connect(([127, 0, 0, 1], port).into())
                .await
                .expect("TLS 握手失败");
            let header = super::harness::header_bytes(target.port(), PASSWORD);
            stream.write_all(&header[..cut]).await.unwrap();
            stream.flush().await.unwrap();
            assert!(
                expect_reference_closed(&mut stream).await,
                "截断({label})必须由参考端主动结束连接"
            );
            drop(stream);
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(target.accepted(), 0, "截断({label})不得抵达业务目标");
            drop(reference);
            target.stop().await;
        }
    })
    .await
    .unwrap();
}

/// 截断请求头（ws 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_ws_truncated() {
    timeout(TOTAL, async {
        for (cut, label) in TRUNCATION_CUTS {
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
            let header = super::harness::header_bytes(target.port(), PASSWORD);
            stream.write_all(&header[..cut]).await.unwrap();
            stream.flush().await.unwrap();
            assert!(
                expect_reference_closed(&mut stream).await,
                "截断({label})必须由参考端主动结束连接"
            );
            drop(stream);
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(target.accepted(), 0, "截断({label})不得抵达业务目标");
            drop(reference);
            target.stop().await;
        }
    })
    .await
    .unwrap();
}

/// 截断请求头（httpupgrade 档）。
#[tokio::test]
#[ignore = "需要显式提供固定版本参考二进制"]
async fn xray_matrix_httpupgrade_truncated() {
    timeout(TOTAL, async {
        for (cut, label) in TRUNCATION_CUTS {
            let identity = Identity::new();
            let target = Target::bind(REPLY.to_vec()).await;
            let port = free_port();
            let reference = launch(server_config(port, &identity, Outer::HttpUpgrade), port).await;
            let tls = identity
                .client()
                .connect(([127, 0, 0, 1], port).into())
                .await
                .expect("TLS 握手失败");
            let mut stream = httpupgrade::Client::new(PATH, "localhost", "localhost")
                .upgrade(tls, WAIT)
                .await
                .expect("HTTPUpgrade 升级失败");
            let header = super::harness::header_bytes(target.port(), PASSWORD);
            stream.write_all(&header[..cut]).await.unwrap();
            stream.flush().await.unwrap();
            assert!(
                expect_reference_closed(&mut stream).await,
                "截断({label})必须由参考端主动结束连接"
            );
            drop(stream);
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(target.accepted(), 0, "截断({label})不得抵达业务目标");
            drop(reference);
            target.stop().await;
        }
    })
    .await
    .unwrap();
}
