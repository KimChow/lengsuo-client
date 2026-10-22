// 传输层（TLS）篡改的 2 条用例正文。
//
// 本文件由 `tests/tamper_matrix/tls_tamper.rs` 用 `include!` 文本并入同一模块；
// `use` 与全部助手（中间人 / TLS 服务端 / 记录解析）都在入口文件。

/// 帧载荷在 TLS 记录内被改 1 bit ⇒ 服务端必须中止连接，篡改数据不得交给上层。
///
/// 判据：TLS 的 AEAD 记录认证（TLS 1.3 记录认证标签）——由 rustls 承担，
/// 记录校验失败即返回错误；`src/server/session.rs:108-109` 把读错误向上传播
/// ⇒ 会话以失败结束（fail-closed）。
#[tokio::test]
async fn on_path_payload_tampering_is_rejected() {
    timeout(TOTAL * 3, async {
        let Some(pki) = crate::pki::generate() else {
            eprintln!("跳过：无 openssl，无法生成测试 PKI");
            return;
        };
        let target = spawn_target().await;
        let server_port = spawn_tls_server(&pki).await;
        let server_addr = SocketAddr::from(([127, 0, 0, 1], server_port));

        // 记录明文布局：SYN(7) | PUSH 头(7) | SOCKS 地址(7) | 应用载荷。
        let syn_frame = Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        }
        .encode()
        .expect("编码 SYN");
        let app_payload = b"tls-tamper-payload-probe";
        let push_frame = Frame {
            command: Command::Push,
            stream_id: 1,
            data: push_with_target(target.addr, app_payload),
        }
        .encode()
        .expect("编码 PUSH");
        // 被翻位字节在记录体中的下标 = SYN + PUSH 头 + SOCKS 地址。
        let payload_offset = syn_frame.len() + 7 + 7;
        let body_len = syn_frame.len() + push_frame.len() + TLS13_BODY_OVERHEAD;

        let (mitm_port, report) = spawn_mitm(server_addr, body_len, payload_offset).await;

        // 被测客户端：连中间人（TLS 直通中间人，密钥只有两端知道）。
        let client_config = ClientTrust::new(&pki.ca_pem, SERVER_NAME).expect("客户端信任");
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
        let socket = TcpStream::connect(("127.0.0.1", mitm_port))
            .await
            .expect("连接中间人");
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from(SERVER_NAME.to_owned())
            .expect("服务名");
        let mut stream = timeout(WAIT, connector.connect(name, socket))
            .await
            .expect("握手超时")
            .expect("TLS 握手（含 CA + 名称校验）");
        assert_eq!(
            stream.get_ref().1.protocol_version(),
            Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3),
            "本用例的记录布局推导只对 TLS 1.3 成立"
        );

        // 第 1 条应用数据记录：认证块 + Settings（合成一次 write ⇒ 一条记录）。
        let mut auth = Vec::new();
        Credential::new(PASSWORD_BYTES)
            .send(&mut auth, b"", WAIT)
            .await
            .expect("认证块");
        let mut first = auth;
        first.extend_from_slice(&settings_bytes());
        stream.write_all(&first).await.expect("写认证与 Settings");
        stream.flush().await.expect("刷新");
        let server_settings = next_semantic(&mut stream).await;
        assert_eq!(
            server_settings.command,
            Command::ServerSettings,
            "协商到 v2"
        );

        // 第 2 条应用数据记录：SYN + PUSH（中间人在这条记录里翻 1 bit）。
        let mut second = syn_frame.clone();
        second.extend_from_slice(&push_frame);
        stream.write_all(&second).await.expect("写 SYN 与 PUSH");
        stream.flush().await.expect("刷新");

        // 服务端必须因记录校验失败而中止：客户端读不到任何语义帧。
        // 注意：`timeout(...)` 成功时返回 `Ok(inner)`，故要判**内层**结果。
        let read = timeout(WAIT, try_next_semantic(&mut stream)).await;
        match read {
            Err(_elapsed) => {}
            Ok(Err(err)) => assert!(
                matches!(err, Error::Io(_)),
                "记录校验失败后服务端只能断开，不得回语义帧，实际错误：{err}"
            ),
            Ok(Ok(frame)) => panic!(
                "载荷被改 1 bit 后服务端不得回任何语义帧，实际收到 {:?} sid={} len={}",
                frame.command,
                frame.stream_id,
                frame.data.len()
            ),
        }

        // 篡改事实：中间人确实在目标记录里翻了 1 bit，且长度与推导一致。
        let observed = report.lock().expect("报告锁").clone();
        let observed = observed.expect("中间人未报告篡改");
        println!(
            "tamper report: outer_type={} body_len={} flipped_index={} candidates={}",
            observed.outer_type, observed.body_len, observed.flipped_index, observed.candidates
        );
        assert_eq!(
            observed.outer_type, OUTER_ENCRYPTED,
            "被篡改记录必须是加密记录"
        );
        assert_eq!(
            observed.body_len, body_len,
            "记录体长度必须等于 明文 + 内层类型(1) + 标签(16)"
        );
        assert_eq!(
            observed.flipped_index, payload_offset,
            "翻位落在 PUSH 载荷内"
        );
        assert_eq!(
            observed.candidates, 1,
            "承载 PUSH 的记录必须唯一：长度推导有歧义则本用例的篡改点不可信"
        );

        // 核心断言：篡改后的数据不得交给上层——目标既没被拨号，也没收到字节。
        assert_eq!(
            target.accepted.load(Ordering::SeqCst),
            0,
            "载荷被篡改的帧不得触发拨号"
        );
        assert!(
            target.received().is_empty(),
            "载荷被篡改的帧不得把数据交给上层"
        );
    })
    .await
    .expect("用例超时");
}

/// 篡改后**新开一条连接**必须能正常往返：证明拒绝路径没有污染后续会话。
///
/// 判据：服务端每条连接独立（`src/server/session.rs:72-88` 每次 `serve` 新建
/// 状态机），拒绝路径不写全局状态。
#[tokio::test]
async fn fresh_connection_after_tamper_round_trips_normally() {
    timeout(TOTAL * 3, async {
        let Some(pki) = crate::pki::generate() else {
            eprintln!("跳过：无 openssl，无法生成测试 PKI");
            return;
        };
        let target = spawn_target().await;
        let server_port = spawn_tls_server(&pki).await;
        let server_addr = SocketAddr::from(([127, 0, 0, 1], server_port));

        let syn_frame = Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        }
        .encode()
        .expect("编码 SYN");
        let push_frame = Frame {
            command: Command::Push,
            stream_id: 1,
            data: push_with_target(target.addr, b"tampered-then-fresh"),
        }
        .encode()
        .expect("编码 PUSH");
        let payload_offset = syn_frame.len() + 7 + 7;
        let body_len = syn_frame.len() + push_frame.len() + TLS13_BODY_OVERHEAD;
        let (mitm_port, report) = spawn_mitm(server_addr, body_len, payload_offset).await;

        let client_config = ClientTrust::new(&pki.ca_pem, SERVER_NAME).expect("客户端信任");
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from(SERVER_NAME.to_owned())
            .expect("服务名");

        // 第 1 条连接：经中间人，载荷被改 1 bit。
        {
            let socket = TcpStream::connect(("127.0.0.1", mitm_port))
                .await
                .expect("连接中间人");
            let mut stream = timeout(WAIT, connector.connect(name.clone(), socket))
                .await
                .expect("握手超时")
                .expect("TLS 握手");
            let mut auth = Vec::new();
            Credential::new(PASSWORD_BYTES)
                .send(&mut auth, b"", WAIT)
                .await
                .expect("认证块");
            let mut first = auth;
            first.extend_from_slice(&settings_bytes());
            stream.write_all(&first).await.expect("写认证与 Settings");
            stream.flush().await.expect("刷新");
            assert_eq!(
                next_semantic(&mut stream).await.command,
                Command::ServerSettings
            );
            let mut second = syn_frame.clone();
            second.extend_from_slice(&push_frame);
            stream.write_all(&second).await.expect("写 SYN 与 PUSH");
            stream.flush().await.expect("刷新");
            match timeout(WAIT, try_next_semantic(&mut stream)).await {
                Err(_elapsed) => {}
                Ok(Err(err)) => assert!(
                    matches!(err, Error::Io(_)),
                    "记录校验失败后只能断开，实际错误：{err}"
                ),
                Ok(Ok(_frame)) => panic!("被篡改的连接不得收到任何语义帧"),
            }
            assert!(report.lock().expect("报告锁").is_some(), "中间人未报告篡改");
            let observed = report.lock().expect("报告锁").clone().expect("篡改报告");
            assert_eq!(
                observed.candidates, 1,
                "承载 PUSH 的记录必须唯一：长度推导有歧义则篡改点不可信"
            );
        }

        // 第 2 条连接：直连真实服务端（不经中间人），必须正常往返。
        let payload = b"fresh-connection-after-tamper";
        {
            let socket = TcpStream::connect(server_addr).await.expect("连接服务端");
            let mut fresh = timeout(WAIT, connector.connect(name, socket))
                .await
                .expect("握手超时")
                .expect("TLS 握手");
            let mut auth = Vec::new();
            Credential::new(PASSWORD_BYTES)
                .send(&mut auth, b"", WAIT)
                .await
                .expect("认证块");
            let mut first = auth;
            first.extend_from_slice(&settings_bytes());
            fresh.write_all(&first).await.expect("写认证与 Settings");
            fresh.flush().await.expect("刷新");
            assert_eq!(
                next_semantic(&mut fresh).await.command,
                Command::ServerSettings
            );
            let mut second = syn_frame.clone();
            second.extend_from_slice(
                &Frame {
                    command: Command::Push,
                    stream_id: 1,
                    data: push_with_target(target.addr, payload),
                }
                .encode()
                .expect("编码 PUSH"),
            );
            fresh.write_all(&second).await.expect("写 SYN 与 PUSH");
            fresh.flush().await.expect("刷新");
            let ack = next_semantic(&mut fresh).await;
            assert_eq!(ack.command, Command::SynAck, "新连接必须正常建流");
            let echoed = next_semantic(&mut fresh).await;
            assert_eq!(echoed.command, Command::Push);
            assert_eq!(echoed.data, payload, "新连接必须逐字节往返一致");
        }
        assert_eq!(
            target.accepted.load(Ordering::SeqCst),
            1,
            "只有第二条（干净）连接才允许拨号"
        );
        assert_eq!(target.received(), payload.to_vec(), "目标只收到干净载荷");
    })
    .await
    .expect("用例超时");
}
