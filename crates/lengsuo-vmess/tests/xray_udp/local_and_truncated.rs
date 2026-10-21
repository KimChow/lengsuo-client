// 用例 C1（构造期异常）与 C2（截断流）：本地 fail-closed / 截断流被关闭。
// 本文件由 `tests/xray_udp.rs` 用 `include!` 文本并入同一模块（用例名不带
// 模块前缀，与拆分前逐字一致）；`use`、常量与共享助手都在入口文件。

/// 用例 C1（构造期异常）：载荷 > `MAX_UDP_PAYLOAD` → 本端 fail-closed。
#[test]
fn oversized_payload_is_rejected_before_write() {
    let huge = vec![0u8; MAX_UDP_PAYLOAD + 1];
    let packet = lengsuo_vmess::udp::UdpPacket {
        target: TargetAddr::V4([127, 0, 0, 1], 9),
        payload: huge,
    };
    let err = lengsuo_vmess::udp::encode_udp_packet(&packet).expect_err("超限载荷必须构造期报错");
    eprintln!("OK: 用例 C1 超限载荷构造期拒绝（{err:?}），未写出任何字节。");
}

/// 用例 C2（截断）：请求头 + 半个数据报后关闭写端 → 后端不得收到数据报；
/// 读侧必须在超时内观察到服务端关闭（EOF/RST，超时不算通过）。
/// 夹具把 connIdle 调到 5s（参考默认 300s，`features/policy/policy.go:121`），
/// 让 inactivity 链条在判据窗口内到期。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn truncated_write_stream_is_rejected() {
    let Some(bin) = xray_bin() else { return };
    let (echo_addr, echo) = spawn_udp_echo().await;

    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = match XrayFixture::start_with_idle_timeout(&bin, &uuid, 5) {
        Ok(f) => f,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败（UUID 已打码）");
        }
    };

    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());
    let (mut stream, mut cipher) = open_classic_association(&fixture, &cmd_key, &keys, &target)
        .await
        .unwrap_or_else(|msg| panic!("{msg}"));

    // 完整数据报密文的前半段（长度前缀 + 一半密文体），随后关闭写端。
    let mut wire = Vec::new();
    chunkframe::seal_data_chunk(&mut cipher, None, &mut wire, b"truncated-payload").expect("封帧");
    let half = wire.len() / 2;
    stream
        .write_all(&wire[..half])
        .await
        .map_err(|e| format!("写半帧失败: {e:?}"))
        .unwrap_or_else(|msg| panic!("{msg}"));
    let _ = stream.shutdown().await;

    // 判据 1：后端不应收到任何数据报（半帧不可解）。
    let mut probe = vec![0u8; 65536];
    let backend_quiet =
        tokio::time::timeout(Duration::from_secs(3), echo.recv_from(&mut probe)).await;
    assert!(
        backend_quiet.is_err(),
        "截断流不应产生任何到达后端的数据报\n{}",
        fixture.report()
    );

    // 判据 2：读侧观察到服务端关闭（EOF/RST）才算通过；超时即失败。
    let outcome = tokio::time::timeout(RESPONSE_TIMEOUT, async {
        let mut cipher = body_cipher(&keys);
        loop {
            match codec::read_chunk(&mut cipher, &mut stream).await {
                Ok(Some(_)) => continue,
                other => break other,
            }
        }
    })
    .await;
    match outcome {
        Err(_) => panic!(
            "截断后 {}s 内连接未被服务端关闭（读侧无 EOF）\n{}",
            RESPONSE_TIMEOUT.as_secs(),
            fixture.report()
        ),
        Ok(closed) => {
            eprintln!("OK: 用例 C2 截断流被服务端关闭（读侧观察 {closed:?}），后端无数据报。");
        }
    }
}
