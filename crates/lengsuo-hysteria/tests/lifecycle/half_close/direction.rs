// 半关闭的两个方向：客户端关写端后读方向仍活 / 对端关写端后读到干净 EOF。
/// A1：客户端单向半关闭 ⇒ 对端仍能收到**完整**载荷，且读方向仍可继续收。
///
/// 断言语义：
/// 1. 客户端写完载荷后 `finish()`（只关写端），目标端必须**完整**收到
///    全部载荷（不是被当成连接断开而截断/丢失）；
/// 2. 目标端在客户端半关闭之后才回写数据 ⇒ 客户端**仍能读到**回包
///    （半关闭不是全关闭）；
/// 3. 目标端读到 EOF（干净 EOF，`Ok(0)`）⇒ 目标端确实看到了 FIN。
#[tokio::test]
async fn half_close_client_write_side_keeps_read_direction_alive() {
    let server = start_server("hc1", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    // 目标：先读完，等 EOF（客户端半关闭）之后才回写。
    let payload = pattern(64 * 1024);
    let reply = pattern(4096);
    let target = spawn_tcp_target(TargetScript::ReplyAfterEof(reply.clone())).await;

    let mut stream = proxy::tcp_connect(&client, &target.addr.to_string())
        .await
        .expect("tcp_connect 失败");

    // 写入载荷 → 半关闭（只关写端）。
    let write_fut = async {
        stream.write_all(&payload).await.expect("写入失败");
        stream.finish().expect("半关闭失败");
    };
    tokio::time::timeout(IO_TIMEOUT, write_fut)
        .await
        .expect("写入 + 半关闭超时");

    // 断言 1：目标端完整收到载荷（半关闭没有把数据截断）。
    let got = tokio::time::timeout(IO_TIMEOUT, async {
        loop {
            let got = target.received();
            if got.len() >= payload.len() {
                break got;
            }
            // 让出调度（`#[tokio::test]` 是单线程运行时，忙等会饿死它）。
            tokio::time::sleep(super::POLL_INTERVAL).await;
        }
    })
    .await
    .expect("等待目标收全载荷超时");
    assert_eq!(
        got.len(),
        payload.len(),
        "半关闭后目标端应收全载荷，实际收到 {} / {} 字节",
        got.len(),
        payload.len()
    );
    assert_eq!(got, payload, "半关闭后目标端收到的载荷内容不符");

    // 断言 2：目标端在客户端半关闭之后才回写 ⇒ 客户端读方向仍可继续收。
    let mut buf = vec![0u8; 4096];
    let mut received = Vec::new();
    let read_fut = async {
        while received.len() < reply.len() {
            let n = stream.read(&mut buf).await.expect("读取失败");
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        received
    };
    let received = tokio::time::timeout(IO_TIMEOUT, read_fut)
        .await
        .expect("半关闭后读取回包超时");
    assert_eq!(
        received, reply,
        "半关闭后读方向应仍能收到完整回包（半关闭不是全关闭）"
    );
}

/// A2：对端半关闭的对称性 —— 服务端侧先关写端 ⇒ 客户端读到**干净 EOF**，
/// 不是 `Err(UnexpectedEof)` / `ConnectionReset`。
///
/// ⚠️ 关键区分：目标端在读到第一批数据后回写一段数据，然后
/// `shutdown(Write)`（**半关闭写端**），但**继续读**。于是：
/// - 客户端 `read` 必须先返回 `Ok(n)` 拿到数据，**随后**返回 `Ok(0)`
///   （干净 EOF，且缓冲已空）；
/// - 客户端**不得**收到任何读错误（`Err(UnexpectedEof)` / `Err(Reset)` /
///   `Err(ConnectionLost)`）—— 那才叫「把半关闭当成了连接断开」。
/// - 也**不得**是「EOF 但缓冲里还有残留字节」（那是残帧被误当干净 EOF）。
#[tokio::test]
async fn half_close_peer_write_side_yields_clean_eof() {
    let server = start_server("hc2", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    // 目标：读到第一批数据后回写，再半关闭写端（但继续读）。
    let reply = pattern(64);
    let mut target = spawn_tcp_target(TargetScript::ReplyThenHalfClose(reply.clone())).await;

    let mut stream = proxy::tcp_connect(&client, &target.addr.to_string())
        .await
        .expect("tcp_connect 失败");

    let payload = pattern(1024);
    let write_fut = async {
        stream.write_all(&payload).await.expect("写入失败");
        stream.finish().expect("半关闭失败");
    };
    tokio::time::timeout(IO_TIMEOUT, write_fut)
        .await
        .expect("写入 + 半关闭超时");

    // 客户端读：先拿到数据，再拿到干净 EOF（缓冲空）。
    let mut buf = vec![0u8; 4096];
    let mut received = Vec::new();
    let mut eof = false;
    let read_fut = async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(e) => panic!("半关闭的读方向不应报错（干净 EOF 才是期望）：{e:?}"),
            }
        }
    };
    tokio::time::timeout(IO_TIMEOUT, read_fut)
        .await
        .expect("等待干净 EOF 超时");

    assert!(eof, "对端半关闭写端后，客户端应读到干净 EOF（Ok(0)）");
    assert_eq!(
        received,
        reply,
        "干净 EOF 之前的数据必须完整送达（收到 {} 字节，期望 {} 字节）",
        received.len(),
        reply.len()
    );

    // 目标端确实观察到了客户端的 FIN（客户端半关闭的写端）。
    let saw_eof = target.wait_event(|ev| ev == TargetEvent::Eof).await;
    assert!(saw_eof, "目标端应读到客户端半关闭产生的 EOF");
}
