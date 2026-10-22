// 拒绝类用例：明文连接 / 错误口令 / 缺 Settings / 错误 SNI 名称。
//
// 本文件由 `tests/interop_server.rs` 用 `include!` 文本并入同一模块；`use` 与
// 共享助手都在入口文件。

/// 明文连接必须被 TLS 接受器拒绝，且会话层一次都不进入（fail-closed，无明文回退）。
/// 不需要参考二进制，因此不 #[ignore]。
#[tokio::test]
async fn plaintext_connection_is_rejected_before_anytls_layer() {
    use harness::Observed;
    use tokio::io::AsyncWriteExt;

    let password = support::PASSWORD;
    let wait = support::WAIT;
    let dir = support::temp_dir("reject-dir");
    let pki = tls::generate_test_pki(&dir).expect("openssl 测试 PKI（CA+叶子证书）");
    let acceptor = tls::acceptor(&pki).expect("TLS 服务端配置");
    let (port, mut observed) = harness::spawn_tls_server(password.as_bytes(), acceptor, wait);

    // 直接写 anytls 认证字节（明文），期望握手期就被拒。
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("连接 TLS 端口");
    // SHA256(口令) + BE16 长度 0，与 Credential::send 的明文形式一致。
    let digest = <sha2::Sha256 as sha2::Digest>::digest(password.as_bytes());
    socket.write_all(&digest).await.expect("写明文摘要");
    socket
        .write_all(&0u16.to_be_bytes())
        .await
        .expect("写零填充长度");
    let _ = socket.flush().await;

    let event = timeout(wait, observed.recv())
        .await
        .expect("等待握手判定超时")
        .expect("接受循环已回报");
    match event {
        Observed::HandshakeRejected(reason) => {
            println!("明文连接被拒：{reason}");
            assert!(
                reason.contains("TLS 握手"),
                "拒绝理由应为 TLS 握手失败，实际：{reason}"
            );
        }
        Observed::SessionEnded(stats, outcome) => {
            panic!("明文连接竟然进入了会话层：{stats:?} {outcome:?}");
        }
    }
    // 再多等一会儿，确认没有第二条会话（明文不会以其他方式被接受）。
    let extra = timeout(Duration::from_millis(200), observed.recv()).await;
    assert!(
        extra.is_err(),
        "明文连接后不应再出现任何会话事件：{extra:?}"
    );
    support::remove_temp(&dir);
}

/// 真实 TLS + 错误口令：认证必须失败且不进入会话层（无明文/无静默放行）。
#[tokio::test]
async fn tls_handshake_succeeds_but_wrong_password_is_not_authenticated() {
    use harness::Observed;
    use report::Failure;
    use tokio::io::AsyncWriteExt;

    let password = support::PASSWORD;
    let wait = support::WAIT;
    let dir = support::temp_dir("wrong-pw-dir");
    let pki = tls::generate_test_pki(&dir).expect("openssl 测试 PKI（CA+叶子证书）");
    let acceptor = tls::acceptor(&pki).expect("TLS 服务端配置");
    let (port, mut observed) = harness::spawn_tls_server(password.as_bytes(), acceptor, wait);

    // 用会校验服务端的 Rust TLS 客户端连接（信任锚=该自签证书，名称=localhost）。
    let connector = tls::verifying_connector(&pki.ca).expect("TLS 客户端配置");
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("连接 TLS 端口");
    let mut stream = tls::client_handshake(&connector, tls::TEST_SERVER_NAME, socket, wait)
        .await
        .expect("Rust 客户端 TLS 握手（含证书校验）");

    // 发送错误口令的认证字节：摘要应为 SHA256(其它口令)。
    let wrong = <sha2::Sha256 as sha2::Digest>::digest(b"definitely-not-the-password");
    stream.write_all(&wrong).await.expect("写错误摘要");
    stream
        .write_all(&0u16.to_be_bytes())
        .await
        .expect("写零填充长度");
    stream.flush().await.expect("flush");

    let event = timeout(support::TOTAL, observed.recv())
        .await
        .expect("等待会话结果超时")
        .expect("接受循环已回报");
    match event {
        Observed::HandshakeRejected(reason) => {
            panic!("TLS 握手本应成功（证书已校验），实际被拒：{reason}");
        }
        Observed::SessionEnded(stats, outcome) => {
            assert!(
                matches!(outcome, Some(Failure::Authentication)),
                "应为认证失败"
            );
            assert!(
                stats.streams_opened.is_empty()
                    && stats.syn_acks_sent == 0
                    && stats.bytes_to_target == 0,
                "认证失败不得有会话统计"
            );
        }
    }
    support::remove_temp(&dir);
}

/// 真实 TLS + 正确口令但未发 Settings 就送 SYN：会话层必须 fail-closed，
/// 发出 Alert 并以 `Failure::Protocol`（携带原因文本）结束。客户端实际读回
/// Alert 帧作为观测佐证——不是只靠超时推断被拒。
#[tokio::test]
async fn syn_before_settings_is_alerted_and_session_refused() {
    use harness::Observed;
    use lengsuo_anytls::{
        auth::Credential,
        frame::{Command, Frame},
    };
    use report::Failure;

    let password = support::PASSWORD;
    let wait = support::WAIT;
    let dir = support::temp_dir("no-settings-dir");
    let pki = tls::generate_test_pki(&dir).expect("openssl 测试 PKI（CA+叶子证书）");
    let acceptor = tls::acceptor(&pki).expect("TLS 服务端配置");
    let (port, mut observed) = harness::spawn_tls_server(password.as_bytes(), acceptor, wait);

    let connector = tls::verifying_connector(&pki.ca).expect("TLS 客户端配置");
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("连接 TLS 端口");
    let mut stream = tls::client_handshake(&connector, tls::TEST_SERVER_NAME, socket, wait)
        .await
        .expect("TLS 握手（证书校验通过）");

    timeout(support::TOTAL, async {
        Credential::new(password.as_bytes())
            .send(&mut stream, b"", wait)
            .await
            .expect("认证发送");
        // 故意跳过 Settings 帧，直接 SYN（流编号非零即可命中 started() 检查）。
        Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        }
        .write(&mut stream, wait)
        .await
        .expect("写 SYN");
        // 观测佐证：客户端必须真的收到 Alert 帧，而不是等超时。
        let frame = Frame::read(&mut stream, u16::MAX, wait)
            .await
            .expect("读服务端帧");
        assert_eq!(frame.command, Command::Alert, "应答帧应为 Alert");
        let text = String::from_utf8_lossy(&frame.data).into_owned();
        println!("收到 Alert：{text}");
        assert!(
            text.contains("settings"),
            "Alert 文本应说明缺 Settings，实际：{text}"
        );
    })
    .await
    .expect("总超时");

    let event = timeout(support::TOTAL, observed.recv())
        .await
        .expect("等待会话结果超时")
        .expect("接受循环已回报");
    let Observed::SessionEnded(stats, outcome) = event else {
        panic!("TLS 握手本应成功");
    };
    let reason = match outcome {
        Some(Failure::Protocol(text)) => text,
        other => panic!("应为协议失败，实际：{other:?}"),
    };
    assert!(
        reason.contains("Settings"),
        "失败原因应可读，实际：{reason}"
    );
    assert_eq!(stats.alerts_sent, 1, "恰好一条 Alert");
    assert!(
        stats.streams_opened.is_empty() && stats.syn_acks_sent == 0,
        "违规会话不得有流统计"
    );
    support::remove_temp(&dir);
}

/// 错误 SNI 名称必须被拒绝（证书校验有效，不因自签而放行名称不匹配）。
#[tokio::test]
async fn tls_client_rejects_wrong_server_name() {
    let wait = support::WAIT;
    let dir = support::temp_dir("wrong-name-dir");
    let pki = tls::generate_test_pki(&dir).expect("openssl 测试 PKI（CA+叶子证书）");
    let acceptor = tls::acceptor(&pki).expect("TLS 服务端配置");
    let (port, _observed) = harness::spawn_tls_server(support::PASSWORD.as_bytes(), acceptor, wait);

    let connector = tls::verifying_connector(&pki.ca).expect("TLS 客户端配置");
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("连接 TLS 端口");
    let outcome = tls::client_handshake(&connector, "evil.example", socket, wait).await;
    match outcome {
        Err(err) => println!("名称不匹配被拒：{err:?}"),
        Ok(_) => panic!("错误 SNI 名称竟然通过证书校验"),
    }
    support::remove_temp(&dir);
}
