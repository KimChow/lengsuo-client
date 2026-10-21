// 用例 C3（错误 UUID）：完整头 + drain 预算 → 服务端必须关闭且无有效应答。
// 本文件由 `tests/xray_udp.rs` 用 `include!` 文本并入同一模块（用例名不带
// 模块前缀，与拆分前逐字一致）；`use`、常量与共享助手都在入口文件。

/// 用例 C3（错误 UUID）：完整头 + 8KiB（drain 预算，见 xray_tcp.rs 头注）→
/// 服务端必须关闭且无有效应答。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn udp_wrong_uuid_is_rejected() {
    let Some(bin) = xray_bin() else { return };
    let (echo_addr, _echo) = spawn_udp_echo().await;

    let fixture_uuid_bytes = codec::generate_uuid_bytes();
    let fixture_uuid = codec::uuid_string(&fixture_uuid_bytes);
    let fixture = match XrayFixture::start(&bin, &fixture_uuid) {
        Ok(f) => f,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败（UUID 已打码）");
        }
    };

    let wrong_uuid_bytes = codec::generate_uuid_bytes();
    let wrong_cmd_key = codec::cmd_key_from_uuid(&wrong_uuid_bytes);
    let keys = KeySource::generate().expect("生成会话密钥");
    let target = TargetAddr::V4([127, 0, 0, 1], echo_addr.port());

    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(fixture.address()))
        .await
        .expect("连接超时")
        .expect("连接 Xray 失败");
    let header = codec::seal_request_header(&wrong_cmd_key, &keys, &target).expect("封装请求头");
    let filler = vec![0u8; 8192];
    let write = async {
        stream
            .write_all(&header)
            .await
            .map_err(|e| format!("写头失败: {e:?}"))?;
        stream
            .write_all(&filler)
            .await
            .map_err(|e| format!("写 filler 失败: {e:?}"))?;
        stream
            .flush()
            .await
            .map_err(|e| format!("flush 失败: {e:?}"))
    };
    match write.await {
        Err(msg) if msg.contains("BrokenPipe") || msg.contains("ConnectionReset") => {
            eprintln!("OK: 用例 C3 错误 UUID 在写入阶段即被服务端关闭。");
            return;
        }
        Err(msg) => panic!("写请求以意外错误失败: {msg}\n{}", fixture.report()),
        Ok(()) => {}
    }

    let read = tokio::time::timeout(
        RESPONSE_TIMEOUT,
        codec::read_chunk(&mut body_cipher(&keys), &mut stream),
    )
    .await;
    match read {
        Err(_) => panic!(
            "错误 UUID 后 {}s 内连接未被关闭\n{}",
            RESPONSE_TIMEOUT.as_secs(),
            fixture.report()
        ),
        Ok(Err(e)) if codec::is_clean_close(&e) => {
            eprintln!("OK: 用例 C3 错误 UUID 被拒绝（连接被关闭，无有效应答）。");
        }
        Ok(Ok(Some(data))) => panic!(
            "错误 UUID 却收到 {} 字节数据\n{}",
            data.len(),
            fixture.report()
        ),
        Ok(Ok(None)) => panic!("错误 UUID 却收到有效 EOF 帧\n{}", fixture.report()),
        Ok(Err(e)) => panic!("错误 UUID 读到非关闭错误 {e:?}\n{}", fixture.report()),
    }
}
