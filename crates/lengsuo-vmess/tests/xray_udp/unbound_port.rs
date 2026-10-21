// 用例 C4（目标端口无监听）：不挂死，≤30s 内如实记录观察到的行为。
// 本文件由 `tests/xray_udp.rs` 用 `include!` 文本并入同一模块（用例名不带
// 模块前缀，与拆分前逐字一致）；`use`、常量与共享助手都在入口文件。

/// 用例 C4（目标端口无监听）：传统关联发一个数据报到已释放的回环 UDP 端口。
/// 判据 = 不挂死：≤30s 内如实记录观察到的行为（freedom 对 ICMP 不可达静默
/// 丢弃、连接保持；服务端主动关闭同样记录）。
#[tokio::test]
#[ignore = "requires real Xray binary via LENGSUO_XRAY"]
async fn udp_unbound_port_does_not_hang() {
    let Some(bin) = xray_bin() else { return };

    let uuid_bytes = codec::generate_uuid_bytes();
    let uuid = codec::uuid_string(&uuid_bytes);
    let cmd_key = codec::cmd_key_from_uuid(&uuid_bytes);
    let fixture = match XrayFixture::start(&bin, &uuid) {
        Ok(f) => f,
        Err(report) => {
            eprintln!("{report}");
            panic!("启动 Xray 失败（UUID 已打码）");
        }
    };

    let keys = KeySource::generate().expect("生成会话密钥");
    // 「先绑定再释放」拿真实空闲端口（禁 free_port()+1 的猜测式端口）。
    let dead_port = {
        let listener = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("探测空闲 UDP 端口");
        let port = listener.local_addr().expect("本地地址").port();
        drop(listener);
        port
    };
    let target = TargetAddr::V4([127, 0, 0, 1], dead_port);

    let (mut stream, mut cipher) = open_classic_association(&fixture, &cmd_key, &keys, &target)
        .await
        .unwrap_or_else(|msg| panic!("{msg}"));
    tokio::time::timeout(
        RESPONSE_TIMEOUT,
        codec::write_chunk(&mut cipher, &mut stream, b"nobody-home"),
    )
    .await
    .map_err(|_| "无监听用例写出超时".to_string())
    .unwrap_or_else(|msg| panic!("{msg}\n{}", fixture.report()))
    .unwrap_or_else(|e| panic!("无监听用例写出失败: {e:?}\n{}", fixture.report()));

    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(UNBOUND_TIMEOUT, async {
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
        Err(_) => eprintln!(
            "OBSERVED: 用例 C4 {}s 内无应答且连接未关闭（freedom 对无监听 ICMP 不可达静默丢弃，\
             连接保持到 inactivity 计时到期）；按任务书「不挂死」口径判通过（上限内返回）。",
            UNBOUND_TIMEOUT.as_secs()
        ),
        Ok(Ok(None)) => eprintln!(
            "OBSERVED: 用例 C4 {:.1?} 服务端回 EOF 帧后连接终止。",
            started.elapsed()
        ),
        Ok(Err(e)) if codec::is_clean_close(&e) => eprintln!(
            "OBSERVED: 用例 C4 {:.1?} 服务端关闭连接（{e:?}），无应答。",
            started.elapsed()
        ),
        Ok(Ok(Some(data))) => panic!(
            "无监听端口却收到 {} 字节应答\n{}",
            data.len(),
            fixture.report()
        ),
        Ok(Err(e)) => panic!("无监听端口读到意外错误 {e:?}\n{}", fixture.report()),
    }
}
