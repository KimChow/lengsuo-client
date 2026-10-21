// 共享脚手架：计数读端、回环 TCP 对、注入 salt 的请求开场、拒绝断言辅助、
// 反向矩阵观测行、反向矩阵的一条连接处理。
//
// 本文件由 `tests/xray_tcp_matrix.rs` 用 `include!` 文本并入同一模块；
// 共享常量与 `use` 全部留在 `tests/xray_tcp_matrix.rs` 入口文件。
/// 计数读端：对下层 `AsyncRead` 透明计数，实测一方实际读走的字节数。
/// `Reader::open` 读走多少字节，就是首个 SS2022 写块（salt+固定头+变长头）的长度。
struct CountingReader<R> {
    inner: R,
    count: usize,
}

impl<R> CountingReader<R> {
    fn new(inner: R) -> Self {
        Self { inner, count: 0 }
    }
    fn count(&self) -> usize {
        self.count
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let ready = Pin::new(&mut this.inner).poll_read(cx, buf);
        this.count += buf.filled().len() - before;
        ready
    }
}

/// 回环 TCP 对：client 端写、server 端读，异常路径用真实 TCP 截断/EOF 语义。
async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("回环可监听");
    let client = TcpStream::connect(listener.local_addr().expect("有地址"))
        .await
        .expect("回环可连接");
    let (server, _peer) = listener.accept().await.expect("回环可接受");
    (client, server)
}

/// 用注入 salt 的 Writer 一次性产出请求开场写块（salt+固定头+变长头）。
async fn sealed_request(
    key: &Key,
    salt: &[u8],
    target: &TargetAddr,
    payload: &[u8],
    now: u64,
) -> Vec<u8> {
    let mut writer = Writer::new(
        key,
        Direction::Request,
        lengsuo_ss2022::tcp::Opening::injected(salt),
    )
    .expect("注入 salt 长度应合法");
    let mut wire = Vec::new();
    writer
        .write_request_header(&mut wire, target, payload, now, 8)
        .await
        .expect("请求开场可密封");
    wire
}

/// `Opened` 故意不实现 `Debug`（目标地址不得进日志），不能直接 `expect_err`。
/// 成功即 panic，失败交出错误。
fn rejected_tcp(outcome: Result<lengsuo_ss2022::tcp::Opened, Error>, what: &str) -> Error {
    match outcome {
        Ok(_) => panic!("{what}：必须失败却返回了已通过校验的开场"),
        Err(error) => error,
    }
}

/// 反向矩阵的一条连接观测结果（无 Debug，避免目标地址进日志）。
struct Row {
    first_packet_len: usize,
    request: Vec<u8>,
    reply: Vec<u8>,
    request_chunks: usize,
    response_chunks: usize,
}

/// Xray 客户端→Rust 服务端：解请求→中继 echo→回写响应→半关闭。`wait_peer` 决定写完后
/// 是否等待请求方向对端 EOF；关闭 EOF 用例传 false，写完整条响应即释放，让对端读端见 EOF。
async fn serve_one_matrix(
    stream: TcpStream,
    key: Key,
    replay: &mut SessionReplay,
    wait_peer: bool,
) -> Row {
    let (read_half, mut write_half) = stream.into_split();
    let mut counted = CountingReader::new(read_half);
    let mut reader = Reader::new(key.clone(), Direction::Request, IDLE).expect("可构造读端");
    let opened = timeout(WAIT, reader.open(&mut counted, replay, clock(), None))
        .await
        .expect("开场读取超时")
        .expect("Xray 请求开场应通过全部校验");
    let first_packet_len = counted.count();
    let target = match opened.association {
        Association::Request(target) => Some(target),
        Association::Response(_) => panic!("请求方向不得携带响应关联块"),
    };

    let mut request = opened.payload.clone();
    let mut request_chunks = usize::from(!opened.payload.is_empty());
    for _ in 0..MAX_CHUNKS {
        if request.last() == Some(&b'\n') {
            break;
        }
        let chunk = timeout(WAIT, reader.read_payload(&mut counted))
            .await
            .expect("读载荷超时")
            .expect("读载荷失败");
        let Some(chunk) = chunk else {
            panic!("请求方向在收满一行前就看到 EOF");
        };
        assert!(
            chunk.len() <= MAX_CHUNK_PAYLOAD,
            "Xray 写出的 chunk 超过单块上限 {}",
            chunk.len()
        );
        request_chunks += 1;
        request.extend_from_slice(&chunk);
        assert!(request.len() <= ECHO_LIMIT, "请求载荷超出测试上限");
    }
    assert!(request.last() == Some(&b'\n'), "请求方向未收满一行");

    let address = socket_addr(target.as_ref().expect("应有目标地址"));
    let mut upstream = timeout(WAIT, TcpStream::connect(address))
        .await
        .expect("连接 echo 目标超时")
        .expect("应可连接 echo 目标");
    timeout(WAIT, upstream.write_all(&request))
        .await
        .expect("写 echo 目标超时")
        .expect("写 echo 目标失败");
    let reply = read_line(&mut upstream, ECHO_LIMIT).await;
    assert_eq!(reply, request, "echo 目标应原样回写同一行");

    // 响应首批载荷不得超过单 chunk 上限：对 262144 字节取 65535 为界，余下走载荷帧。
    let split = reply.len().min(MAX_CHUNK_PAYLOAD);
    let mut writer = Writer::random(&key, Direction::Response).expect("可构造写端");
    timeout(
        WAIT,
        writer.write_response_header(
            &mut write_half,
            &opened.request_salt,
            &reply[..split],
            now_secs(),
        ),
    )
    .await
    .expect("响应头写出超时")
    .expect("响应头应可写出");
    let mut response_chunks = usize::from(!reply[..split].is_empty());
    for piece in reply[split..].chunks(MAX_CHUNK_PAYLOAD) {
        if piece.is_empty() {
            continue;
        }
        timeout(WAIT, writer.write_payload(&mut write_half, piece))
            .await
            .expect("响应载荷写出超时")
            .expect("响应载荷应可写出");
        response_chunks += 1;
    }
    timeout(WAIT, writer.write_finish(&mut write_half))
        .await
        .expect("响应 EOF 帧写出超时")
        .expect("响应 EOF 帧应可写出");
    timeout(WAIT, write_half.shutdown())
        .await
        .expect("关闭写半超时")
        .expect("应可半关闭");
    drop(upstream);

    if wait_peer {
        for _ in 0..MAX_CHUNKS {
            match timeout(WAIT, reader.read_payload(&mut counted)).await {
                Ok(Ok(None)) => break,
                Ok(Ok(Some(chunk))) => {
                    request.extend_from_slice(&chunk);
                    assert!(request.len() <= ECHO_LIMIT, "收尾阶段载荷超出上限");
                }
                Ok(Err(_)) => break,
                Err(_) => panic!("等待对端 EOF 超时"),
            }
        }
    }
    // wait_peer=false 时函数返回即释放两端，读端实测 EOF 即由此而来。
    Row {
        first_packet_len,
        request,
        reply,
        request_chunks,
        response_chunks,
    }
}
