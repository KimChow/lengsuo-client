// 正向路径用例（完整往返 / 跨帧地址 / 心跳）+ 真 TLS 装配那条。
//
// 本文件由 `tests/server_roundtrip.rs` 用 `include!` 文本并入同一模块；`use` 与
// 共享助手（`Harness` / `spawn_echo` / `settings` / `push_with_target`）都在入口
// 文件，本文件只放本主题专属的助手。

/// 完整正向路径：Settings → ServerSettings → SYN → PUSH（目标+载荷）→ SYNACK →
/// 回程 PUSH 逐字节一致 → FIN → 干净收尾，并核对统计。
#[tokio::test]
async fn echo_roundtrip_with_settings_synack_and_fin() {
    let mut harness = Harness::start(PASSWORD).await;
    let echo = spawn_echo().await;
    let md5 = PaddingScheme::default_scheme().md5().to_owned();

    harness.send(settings(&md5)).await;
    // 参考：客户端 v>=2 → 服务端回 ServerSettings("v=2")。
    let server_settings = harness.expect(Command::ServerSettings).await;
    assert_eq!(server_settings.data, b"v=2", "ServerSettings 载荷");
    assert_eq!(server_settings.stream_id, 0, "控制帧 stream id 为 0");

    harness
        .send(Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        })
        .await;
    // 一帧内既含目标地址又含载荷：服务端应解析地址后剩余字节直接转发。
    let payload = b"rust-rust-single-frame-echo";
    harness
        .send(Frame {
            command: Command::Push,
            stream_id: 1,
            data: push_with_target(echo, payload),
        })
        .await;

    let ack = harness.expect(Command::SynAck).await;
    assert_eq!(ack.stream_id, 1, "SYNACK 绑定同一流");
    assert!(ack.data.is_empty(), "成功 SYNACK 无载荷");
    let echoed = harness.expect(Command::Push).await;
    assert_eq!(echoed.stream_id, 1, "回程 PUSH 绑定同一流");
    assert_eq!(echoed.data, payload, "回程逐字节一致");

    harness
        .send(Frame {
            command: Command::Fin,
            stream_id: 1,
            data: Vec::new(),
        })
        .await;
    // 客户端 FIN 后服务端不再补发 FIN（参考 closeLocally 语义）：关闭客户端即收尾。
    let stats = harness.finish().await.expect("干净收尾");
    assert_eq!(stats.peer_version, Some(2), "协商到 v2");
    assert_eq!(stats.streams_opened, 1, "打开一条流");
    assert_eq!(stats.streams_closed, 1, "关闭一条流");
    assert_eq!(
        stats.syn_acks_sent, 0,
        "SYNACK 计数由上层维护，这里不重复计"
    );
    assert_eq!(stats.bytes_to_target, payload.len(), "转发字节数");
    assert_eq!(stats.bytes_to_client, payload.len(), "回程字节数");
}

/// 目标地址跨帧：首帧 PUSH 只放半截地址，服务端必须缓存等下一帧，不得拨号或报错。
#[tokio::test]
async fn target_address_split_across_frames_is_buffered() {
    let mut harness = Harness::start(PASSWORD).await;
    let echo = spawn_echo().await;
    let md5 = PaddingScheme::default_scheme().md5().to_owned();
    harness.send(settings(&md5)).await;
    let _ = harness.expect(Command::ServerSettings).await;
    harness
        .send(Frame {
            command: Command::Syn,
            stream_id: 1,
            data: Vec::new(),
        })
        .await;

    let full = push_with_target(echo, b"split-address");
    let (head, tail) = full.split_at(4); // 半截地址（IPv4 地址共 7 字节）
    harness
        .send(Frame {
            command: Command::Push,
            stream_id: 1,
            data: head.to_vec(),
        })
        .await;
    // 此刻不应有 SYNACK（地址未完整）；给一点时间确认——超时或只读到 Waste 都算通过。
    let early = timeout(Duration::from_millis(150), harness.recv()).await;
    assert!(early.is_err(), "地址未完整时不应有语义帧（尤其 SYNACK）");

    harness
        .send(Frame {
            command: Command::Push,
            stream_id: 1,
            data: tail.to_vec(),
        })
        .await;
    let ack = harness.expect(Command::SynAck).await;
    assert_eq!(ack.stream_id, 1);
    let echoed = harness.expect(Command::Push).await;
    assert_eq!(echoed.data, b"split-address", "跨帧地址后载荷仍需回程");
    let stats = harness.finish().await.expect("干净收尾");
    assert_eq!(stats.bytes_to_target, b"split-address".len());
}

/// 心跳：任意关联值原样回传 HeartResponse（参考 cmdHeartRequest 分支）。
#[tokio::test]
async fn heartbeat_request_is_answered_with_same_id() {
    let mut harness = Harness::start(PASSWORD).await;
    let md5 = PaddingScheme::default_scheme().md5().to_owned();
    harness.send(settings(&md5)).await;
    let _ = harness.expect(Command::ServerSettings).await;

    harness
        .send(Frame {
            command: Command::HeartRequest,
            stream_id: 37,
            data: Vec::new(),
        })
        .await;
    let response = harness.expect(Command::HeartResponse).await;
    assert_eq!(response.stream_id, 37, "关联值原样回传");
    assert!(response.data.is_empty(), "心跳无载荷");
    let stats = harness.finish().await.expect("干净收尾");
    assert_eq!(stats.heartbeats, 1);
}

/// 真 TLS 装配：`server::tls::acceptor` + `server::serve` 在真实握手后跑通 echo。
/// 证书由测试用 openssl 现签（无产品凭据）；若环境无 openssl 则跳过。
#[tokio::test]
async fn tls_acceptor_serves_echo_after_handshake() {
    let Some(pki) = test_pki() else {
        eprintln!("跳过：环境无 openssl，无法生成测试 PKI");
        return;
    };
    let acceptor = tls::acceptor(pki.chain.clone(), pki.key_der()).expect("TLS 接受器");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("监听");
    let port = listener.local_addr().expect("地址").port();
    tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            if let Ok(stream) = tls::handshake(&acceptor, socket, WAIT).await {
                let _ = server::serve(stream, ServerConfig::new(PASSWORD, WAIT)).await;
            }
        }
    });
    let echo = spawn_echo().await;

    // 客户端：用测试 CA 校验服务端，再做认证 + 单流 echo。
    let connector = tls_client(&pki.ca).expect("TLS 客户端");
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("连接");
    let mut stream = timeout(
        WAIT,
        connector.connect(
            tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").expect("名称"),
            socket,
        ),
    )
    .await
    .expect("握手超时")
    .expect("TLS 握手（含证书校验）");

    Credential::new(PASSWORD)
        .send(&mut stream, b"", WAIT)
        .await
        .expect("认证");
    let md5 = PaddingScheme::default_scheme().md5().to_owned();
    settings(&md5)
        .write(&mut stream, WAIT)
        .await
        .expect("Settings");
    let _ = next_semantic(&mut stream).await;
    Frame {
        command: Command::Syn,
        stream_id: 1,
        data: Vec::new(),
    }
    .write(&mut stream, WAIT)
    .await
    .expect("SYN");
    let payload = b"tls-server-echo-check";
    Frame {
        command: Command::Push,
        stream_id: 1,
        data: push_with_target(echo, payload),
    }
    .write(&mut stream, WAIT)
    .await
    .expect("PUSH");
    let ack = next_semantic(&mut stream).await;
    assert_eq!(ack.command, Command::SynAck, "真实 TLS 下也要回 SYNACK");
    let echoed = next_semantic(&mut stream).await;
    assert_eq!(echoed.command, Command::Push);
    assert_eq!(echoed.data, payload, "真实 TLS 下回程逐字节一致");
}

/// 读下一帧并跳过 Waste 填充（与 `Harness::recv` 同语义，供裸流用例复用）。
async fn next_semantic<S: AsyncReadExt + Unpin>(stream: &mut S) -> Frame {
    loop {
        let frame = Frame::read(stream, u16::MAX, WAIT).await.expect("读帧");
        if frame.command != Command::Waste {
            return frame;
        }
    }
}

/// 测试 PKI（openssl 现签两级链）。
struct TestPki {
    chain: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    key: Vec<u8>,
    ca: Vec<u8>,
}

impl TestPki {
    fn key_der(&self) -> tokio_rustls::rustls::pki_types::PrivateKeyDer<'static> {
        tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
            tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(self.key.clone()),
        )
    }
}

/// 在临时目录用 openssl 生成 CA + 叶子（SAN=localhost/127.0.0.1）；无 openssl 返回 None。
fn test_pki() -> Option<TestPki> {
    use std::process::Command;
    let dir = std::env::temp_dir().join(format!("lengsuo-anytls-unit-pki-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let p = |name: &str| dir.join(name).to_str().unwrap_or_default().to_owned();
    let ok = |args: &[&str]| {
        Command::new("openssl")
            .args(args)
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    };
    let ca_key = p("ca-key.pem");
    let ca_pem = p("ca.pem");
    let ca_der = p("ca.der");
    let csr = p("leaf.csr");
    let leaf_key = p("leaf-key.pem");
    let leaf_der = p("leaf.der");
    let leaf_key_der = p("leaf-key.der");
    let ext = p("leaf.ext");

    let ready = ok(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        &ca_key,
        "-out",
        &ca_pem,
        "-days",
        "1",
        "-subj",
        "/CN=lengsuo-unit-test-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ]) && ok(&["x509", "-in", &ca_pem, "-outform", "DER", "-out", &ca_der])
        && ok(&[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            &leaf_key,
            "-out",
            &csr,
            "-subj",
            "/CN=localhost",
        ]);
    if !ready {
        let _ = std::fs::remove_dir_all(&dir);
        return None;
    }
    let ext_body = "subjectAltName=DNS:localhost,IP:127.0.0.1\n\
                    basicConstraints=critical,CA:FALSE\n\
                    keyUsage=critical,digitalSignature,keyEncipherment\n\
                    extendedKeyUsage=serverAuth\n";
    std::fs::write(&ext, ext_body).ok()?;
    let signed = ok(&[
        "x509",
        "-req",
        "-in",
        &csr,
        "-CA",
        &ca_pem,
        "-CAkey",
        &ca_key,
        "-set_serial",
        "01",
        "-days",
        "1",
        "-extfile",
        &ext,
        "-outform",
        "DER",
        "-out",
        &leaf_der,
    ]) && ok(&[
        "pkcs8",
        "-topk8",
        "-nocrypt",
        "-in",
        &leaf_key,
        "-outform",
        "DER",
        "-out",
        &leaf_key_der,
    ]);
    if !signed {
        let _ = std::fs::remove_dir_all(&dir);
        return None;
    }
    let pki = TestPki {
        chain: vec![
            tokio_rustls::rustls::pki_types::CertificateDer::from(std::fs::read(&leaf_der).ok()?),
            tokio_rustls::rustls::pki_types::CertificateDer::from(std::fs::read(&ca_der).ok()?),
        ],
        key: std::fs::read(&leaf_key_der).ok()?,
        ca: std::fs::read(&ca_der).ok()?,
    };
    let _ = std::fs::remove_dir_all(&dir);
    Some(pki)
}

/// 会校验服务端的 TLS 客户端（唯一信任锚 = 测试 CA）。
fn tls_client(ca_der: &[u8]) -> Result<tokio_rustls::TlsConnector, Box<dyn std::error::Error>> {
    let mut store = tokio_rustls::rustls::RootCertStore::empty();
    store.add(tokio_rustls::rustls::pki_types::CertificateDer::from(
        ca_der.to_vec(),
    ))?;
    let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(store)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        config,
    )))
}
