// 畸形帧：残缺 TCPRequest 不得放行（不建出站连接、无响应残留）。
/// B3：畸形帧 ⇒ 服务端不残留会话（且不 panic）。
///
/// 「畸形帧」= 一条**残缺的 TCPRequest**：帧类型 `0x401` 正确，但请求体
/// 只写了一半（地址长度声明 64 字节、只给 4 字节）就结束流。
///
/// 对应参考 `protocol.go` `ReadTCPRequest` 的 `io.ReadFull` 短读 ⇒ 错误；
/// 本仓 `proxy::server_read_tcp_request` 短读 ⇒ `Truncated` ⇒
/// `recv.read()` 得 `None` ⇒ `ProxyError::PrematureEof` ⇒ **不建立出站
/// 连接**、不建承载。
///
/// 判据：
/// 1. 服务端**没有**建立任何出站 TCP 连接（`target.accepts() == 0`）⇒
///    畸形帧没被当成合法请求放行；
/// 2. 客户端读到的是**干净 EOF**（服务端没写任何响应帧 ⇒ 缓冲空），
///    而不是「EOF 且有残留」；
/// 3. 断开后服务端会话表归零。
#[tokio::test]
async fn cleanup_server_rejects_malformed_frame_without_residue() {
    let server = start_server("cl3", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    let connected = wait_until(RECLAIM_DEADLINE, || async {
        server.open_connections() >= 1
    })
    .await;
    assert!(connected, "建连后服务端应至少有一条连接");

    // 本地目标：只要服务端**建立**了出站连接，这里就会被接入一次。
    let target = spawn_tcp_target(TargetScript::CloseAfterFirstRead).await;

    // 开一条双向流，写一条**残缺的 TCPRequest** 后立刻结束流。
    let (mut send, recv) = client.open_tcp().await.expect("开流失败");
    // 帧类型 0x401（TCPRequest）= varint 编码 [0x44, 0x01]；
    // 地址长度 varint：64（2 字节编码 [0x40, 0x40]）；
    // 只给 4 字节地址（声明要 64 字节）⇒ 残帧。
    let mut malformed = vec![0x44, 0x01, 0x40, 0x40];
    malformed.extend_from_slice(b"127.");
    let write_fut = async {
        send.write_all(&malformed).await.expect("写入畸形帧失败");
        send.finish().expect("关闭流失败");
    };
    tokio::time::timeout(IO_TIMEOUT, write_fut)
        .await
        .expect("写入畸形帧超时");

    // 服务端应结束这条流，且**没写任何响应帧** ⇒ 客户端读到干净 EOF。
    let outcome = tokio::time::timeout(IO_TIMEOUT, super::read_to_eof(recv))
        .await
        .expect("等待畸形帧流结束超时");
    match outcome {
        super::ReadOutcome::CleanEof { data } => assert!(
            data.is_empty(),
            "畸形帧路径服务端不应写出任何响应帧（读到 {} 字节）",
            data.len()
        ),
        super::ReadOutcome::EofWithResidue { data } => {
            panic!("畸形帧被当成了带响应的请求（残留 {data:?}）——协议错误被放行")
        }
        super::ReadOutcome::ReadError { err, .. } => {
            panic!("畸形帧路径应读到干净 EOF，而不是读错误：{err}");
        }
    }

    // 判据 1：服务端**没有**建立出站连接（畸形帧没被当成合法请求）。
    assert_eq!(
        target.accepts(),
        0,
        "残缺 TCPRequest 不得让服务端建立出站连接（不得放行）"
    );

    // 断开连接后，服务端会话表归零。
    client
        .connection()
        .close(quinn::VarInt::from_u32(super::CLOSE_ERR_CODE_OK), b"");
    let reclaimed = wait_until(RECLAIM_DEADLINE, || async {
        server.open_connections() == 0
    })
    .await;
    assert!(
        reclaimed,
        "畸形帧后断开，服务端不应残留会话，实际连接数 = {}",
        server.open_connections()
    );
    assert_eq!(server.open_connections(), 0, "服务端会话表应归零");
}
