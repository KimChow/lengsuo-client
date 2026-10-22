// ② 用例：主链路贯通 / 不配 REALITY 时保持裸 TCP / 非法配置启动即拒。
/// **1. 主链路贯通**：本仓 VLESS 服务端为对端，本仓 REALITY 客户端经
/// `RealityStream` 走主链路（`stream::send_request` → 载荷 → `receive_response`）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reality_main_link_roundtrip_to_own_server() {
    timeout(DEADLINE, async {
        let server = Arc::new(Server::new());
        let server_port = free_ports(1)[0];
        let server_task = start_server(server.clone(), server_port).await;

        // 配置（参考格式的 base64 raw-url 公钥 + 十六进制短 ID）。
        let config = RealityConfig::from_settings(server.client_settings()).expect("合法配置");
        // 建流：TCP → REALITY ClientHello → TLS 1.3 → 记录层。
        let mut reality =
            RealityStream::connect(&format!("127.0.0.1:{server_port}"), &config, HANDSHAKE)
                .await
                .expect("REALITY 建流");

        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], 9),
        };
        stream::send_request(&mut reality, &request, &KEY, WAIT)
            .await
            .expect("VLESS 请求头");
        reality.write_all(PAYLOAD).await.expect("载荷");
        stream::receive_response(&mut reality, WAIT)
            .await
            .expect("VLESS 成功响应头");
        let mut received = vec![0u8; PAYLOAD.len()];
        timeout(WAIT, reality.read_exact(&mut received))
            .await
            .expect("读载荷超时")
            .expect("读载荷");
        assert_eq!(received, PAYLOAD, "回环载荷必须逐字节一致");
        assert_eq!(server_task.await.unwrap(), PAYLOAD);
        println!("REALITY 主链路贯通：{} 字节逐字节一致", received.len());
    })
    .await
    .expect("用例总超时");
}

/// **2. 配置缺省不变**：不配置 REALITY 时，主链路仍按「裸 TCP」走通——
/// 连接由调用方直接给出（这里是参考端 VLESS 入站、`security: "none"`），
/// `stream::*` 不感知安全层，与既有默认套件同一条路径。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn main_link_without_reality_stays_bare_tcp() {
    timeout(DEADLINE, async {
        // 裸 TCP 对端：只做「按 VLESS 头读请求 → 回响应头 → 回显载荷」。
        // 不依赖参考二进制（`LENGSUO_XRAY`）——本用例验证的是**默认路径不变**，
        // 即不配置 REALITY 时主链路仍是「调用方给定裸连接 + 既有 stream 读写」。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = stream::receive_request(&mut socket, &KEY, WAIT)
                .await
                .expect("读 VLESS 请求头");
            assert!(matches!(request.command, Command::Tcp));
            let mut received = vec![0u8; PAYLOAD.len()];
            socket.read_exact(&mut received).await.expect("读载荷");
            stream::send_response(&mut socket, WAIT)
                .await
                .expect("写 VLESS 响应头");
            socket.write_all(&received).await.expect("回显载荷");
            socket.flush().await.expect("flush");
            received
        });
        // 不经 REALITY：调用方直接给出裸 TCP 连接交给主链路。
        let mut plain = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let request = Request {
            command: Command::Tcp,
            target: TargetAddr::V4([127, 0, 0, 1], 9),
        };
        stream::send_request(&mut plain, &request, &KEY, WAIT)
            .await
            .unwrap();
        plain.write_all(PAYLOAD).await.unwrap();
        stream::receive_response(&mut plain, WAIT).await.unwrap();
        let mut received = vec![0u8; PAYLOAD.len()];
        timeout(WAIT, plain.read_exact(&mut received))
            .await
            .expect("读载荷超时")
            .unwrap();
        assert_eq!(received, PAYLOAD, "默认路径载荷必须逐字节一致");
        assert_eq!(server_task.await.unwrap(), PAYLOAD);
        println!(
            "默认路径（无 REALITY）：裸 TCP 逐字节一致 {}",
            received.len()
        );
    })
    .await
    .expect("用例总超时");
}

/// **3. 非法配置 fail-closed**：启动即报错，**不**降级成「无 REALITY 直连」。
#[test]
fn invalid_reality_config_fails_at_startup() {
    let server = Server::new();
    let valid = server.client_settings();

    let mut bad_base64 = valid.clone();
    bad_base64.public_key = "not*base64*at*all".to_owned();
    let mut short_key = valid.clone();
    short_key.public_key = base64_url(&[7u8; 31]);
    let mut long_key = valid.clone();
    long_key.public_key = base64_url(&[7u8; 33]);
    let mut empty_key = valid.clone();
    empty_key.public_key.clear();
    let mut unknown_fp = valid.clone();
    unknown_fp.fingerprint = "curl".to_owned();
    let mut unsafe_fp = valid.clone();
    unsafe_fp.fingerprint = "unsafe".to_owned();
    let mut bad_short_id = valid.clone();
    bad_short_id.short_id = "zz".to_owned();

    let cases = [
        (bad_base64, ConfigError::InvalidPublicKey),
        (short_key, ConfigError::InvalidPublicKey),
        (long_key, ConfigError::InvalidPublicKey),
        (empty_key, ConfigError::EmptyPublicKey),
        (unknown_fp, ConfigError::UnknownFingerprint),
        (unsafe_fp, ConfigError::InvalidFingerprint),
        (bad_short_id, ConfigError::InvalidShortId),
    ];
    for (settings, expected) in cases {
        let error = RealityConfig::from_settings(settings).expect_err("必须拒绝");
        assert_eq!(error, expected);
        println!("fail-closed：{error}");
    }
    // 合法配置仍可解析（证明上面的失败只来自被改坏的字段）。
    assert!(RealityConfig::from_settings(valid).is_ok());
}
