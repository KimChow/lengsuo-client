// ③ 出站原语 `XelStream`：真实回环 TCP 上的端到端行为。
/// 出站原语：真实回环 TCP 上双向字节流逐字节还原。
#[tokio::test]
async fn xel_stream_roundtrips_over_loopback_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("绑定回环");
    let address = listener.local_addr().expect("本端地址");
    let server = tokio::spawn(async move {
        let (transport, _) = listener.accept().await.expect("接受连接");
        // 服务端方向与客户端对调：服务端的发送 = 客户端的接收。
        let config = XelWireConfig {
            cipher: XelCipher::Aes256Gcm,
            uplink_key: downlink_key(),
            downlink_key: uplink_key(),
            xor: Some(
                XorLayer::new(downlink_key(), &IV_DOWN, uplink_key(), &IV_UP).expect("IV 合法"),
            ),
        };
        let mut stream = XelStream::new(transport, config).expect("构造出站原语");
        let mut buffer = vec![0u8; 4096];
        let read = stream.read(&mut buffer).await.expect("服务端读");
        // 回声：把读到的原样写回。
        stream.write_all(&buffer[..read]).await.expect("服务端写");
        stream.shutdown().await.expect("服务端关写");
        stream.close().await.expect("服务端收尾")
    });

    let transport = tokio::net::TcpStream::connect(address)
        .await
        .expect("连接回环");
    let config = XelWireConfig {
        cipher: XelCipher::Aes256Gcm,
        uplink_key: uplink_key(),
        downlink_key: downlink_key(),
        xor: Some(XorLayer::new(uplink_key(), &IV_UP, downlink_key(), &IV_DOWN).expect("IV 合法")),
    };
    let mut stream = XelStream::new(transport, config).expect("构造出站原语");
    let message = b"xel wire over real loopback tcp";
    stream.write_all(message).await.expect("客户端写");
    let mut buffer = vec![0u8; 4096];
    let read = timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .expect("读不得超时")
        .expect("客户端读");
    assert_eq!(&buffer[..read], message, "回环载荷必须逐字节一致");
    stream.shutdown().await.expect("客户端关写");
    stream.close().await.expect("客户端收尾");
    server.await.expect("服务端任务不得 panic");
}

/// 出站原语：错钥时客户端读到的必须是失败，不是垃圾数据。
#[tokio::test]
async fn xel_stream_with_wrong_key_fails_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("绑定回环");
    let address = listener.local_addr().expect("本端地址");
    let server = tokio::spawn(async move {
        let (transport, _) = listener.accept().await.expect("接受连接");
        // 服务端用**错钥**发送 ⇒ 客户端的接收方向必然认证失败。
        let config = XelWireConfig {
            cipher: XelCipher::Aes256Gcm,
            uplink_key: wrong_key(),
            downlink_key: uplink_key(),
            xor: None,
        };
        let mut stream = XelStream::new(transport, config).expect("构造出站原语");
        // 不等客户端数据，直接发一条 ⇒ 客户端立刻撞上认证失败。
        let _ = stream
            .write_all(b"payload sealed under the wrong key")
            .await;
        let _ = stream.shutdown().await;
        let _ = stream.close().await;
    });

    let transport = tokio::net::TcpStream::connect(address)
        .await
        .expect("连接回环");
    let config = XelWireConfig {
        cipher: XelCipher::Aes256Gcm,
        uplink_key: uplink_key(),
        downlink_key: downlink_key(),
        xor: None,
    };
    let mut stream = XelStream::new(transport, config).expect("构造出站原语");
    let mut buffer = vec![0u8; 4096];
    let outcome = timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .expect("错钥下读必须快速失败，而不是等到超时");
    // 读到的必须是「没有明文」：要么报错，要么 EOF，绝不产出垃圾。
    match outcome {
        Ok(0) => {}
        Ok(n) => panic!("错钥下不得产出明文，实际读出 {n} 字节"),
        Err(_) => {}
    }
    // 收尾必须报出读取方向的失败（fail-closed 的可见出口），且必须**快速**返回
    // （关掉写半后对端立刻看到 EOF，不靠超时兜底）。
    let closed = timeout(Duration::from_secs(5), stream.close())
        .await
        .expect("close 不得靠超时兜底");
    assert!(closed.is_err(), "错钥下 close 必须报出读取方向的失败");
    let _ = server.await;
}

/// 出站原语：`close()` 在对端关闭后必须成功返回（无残字节）。
#[tokio::test]
async fn xel_stream_close_succeeds_on_clean_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("绑定回环");
    let address = listener.local_addr().expect("本端地址");
    let server = tokio::spawn(async move {
        let (mut transport, _) = listener.accept().await.expect("接受连接");
        // 服务端只封一条记录然后关闭（用客户端的下行密钥 ⇒ 客户端能解）。
        let mut writer = RecordWriter::new(XelCipher::Aes256Gcm, downlink_key());
        let record = writer.seal(b"goodbye").unwrap();
        transport.write_all(&record).await.expect("服务端写");
        transport.shutdown().await.expect("服务端关写");
    });

    let transport = tokio::net::TcpStream::connect(address)
        .await
        .expect("连接回环");
    let config = XelWireConfig {
        cipher: XelCipher::Aes256Gcm,
        uplink_key: uplink_key(),
        downlink_key: downlink_key(),
        xor: None,
    };
    let mut stream = XelStream::new(transport, config).expect("构造出站原语");
    let mut buffer = vec![0u8; 4096];
    let read = timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .expect("读不得超时")
        .expect("客户端读");
    assert_eq!(&buffer[..read], b"goodbye", "载荷必须逐字节一致");
    // 对端已关写 ⇒ 再读一次必须得到 EOF，而不是挂死。
    let eof = timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .expect("EOF 不得挂死")
        .expect("EOF 读取");
    assert_eq!(eof, 0, "对端关闭后必须读到 EOF");
    stream.shutdown().await.expect("客户端关写");
    stream.close().await.expect("干净 EOF 下 close 必须成功");
    server.await.expect("服务端任务不得 panic");
}

/// 出站原语：读方向的失败必须在**读操作本身**报出，不能只藏在 `close()` 里。
///
/// 回归用例（fail-open 缺陷）：读任务失败时会把失败原因放进失败槽并关闭管道
/// 写端。管道只能表达 EOF ⇒ 若读操作不把失败槽里的原因报出来，应用侧读到的是
/// 一个**干净的 EOF**，「认证失败的流」被误读成「对端正常结束」（静默降级）。
/// 只调用 `read()` 不调用 `close()` 的调用方（流式读取、只读一次载荷）根本不会
/// 发现异常。
///
/// 判据：错钥下 `read()` 必须返回**错误**（`Err`），不得返回 `Ok(0)`（干净 EOF）。
#[tokio::test]
async fn xel_stream_read_surfaces_read_direction_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("绑定回环");
    let address = listener.local_addr().expect("本端地址");
    let server = tokio::spawn(async move {
        let (transport, _) = listener.accept().await.expect("接受连接");
        // 服务端用**错钥**发送 ⇒ 客户端的接收方向必然认证失败。
        let config = XelWireConfig {
            cipher: XelCipher::Aes256Gcm,
            uplink_key: wrong_key(),
            downlink_key: uplink_key(),
            xor: None,
        };
        let mut stream = XelStream::new(transport, config).expect("构造出站原语");
        let _ = stream
            .write_all(b"payload sealed under the wrong key")
            .await;
        let _ = stream.shutdown().await;
        let _ = stream.close().await;
    });

    let transport = tokio::net::TcpStream::connect(address)
        .await
        .expect("连接回环");
    let config = XelWireConfig {
        cipher: XelCipher::Aes256Gcm,
        uplink_key: uplink_key(),
        downlink_key: downlink_key(),
        xor: None,
    };
    let mut stream = XelStream::new(transport, config).expect("构造出站原语");
    let mut buffer = vec![0u8; 4096];
    // 只调 `read()`，**不**调 `close()`：失败必须在这里就可见。
    let outcome = timeout(Duration::from_secs(10), stream.read(&mut buffer))
        .await
        .expect("错钥下读必须快速失败，而不是等到超时");
    assert!(
        outcome.is_err(),
        "读方向的认证失败必须在 read() 里报出（不得返回干净的 EOF）"
    );
    // 显式丢弃客户端流：关掉传输，服务端的 `close()` 才能立刻收尾（不靠超时兜底）。
    drop(stream);
    let _ = server.await;
}
