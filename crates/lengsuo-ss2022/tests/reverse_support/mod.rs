//! 反向互通的回环服务与有限超时辅助。

use super::*;

/// 只绑回环。
pub(super) const BIND: &str = "127.0.0.1:0";
pub(super) const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
/// 单个测试（含 spawn Xray 与全部套件）的总超时。
pub(super) const OVERALL: Duration = Duration::from_secs(120);
/// 一个方向最多取多少个 chunk，避免测试自身陷入无限读取。
pub(super) const MAX_CHUNKS: usize = 32;
/// echo 单行载荷上限，超出即判定测试跑偏。
pub(super) const ECHO_LIMIT: usize = 1 << 20;
/// SOCKS5 回程地址尾部最大长度（最长域名 + 端口，不含已读头部与长度）。
pub(super) const SOCKS5_RESPONSE_MAX: usize = 255 + 2;
/// 单次读的空闲超时；响应与请求方向都不得无限等待对端。
pub(super) const IDLE: Duration = Duration::from_secs(10);

pub(super) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时钟应晚于纪元")
        .as_secs()
}

pub(super) fn clock() -> lengsuo_ss2022::receiver::Clock {
    clock_at(now_secs(), Instant::now())
}

pub(super) fn methods() -> [(Method, &'static str); 2] {
    [
        (Method::Aes128, "2022-blake3-aes-128-gcm"),
        (Method::Aes256, "2022-blake3-aes-256-gcm"),
    ]
}

/// 载荷规格：1、512（Xray 必带随机 padding）、1200（≥900，padding 为 0）。
pub(super) fn sizes() -> [usize; 3] {
    [1, 512, 1200]
}

/// 长度恰为 `size`、以 `\n` 结尾的可打印载荷；换行提供与 EOF 时序无关的结束判据。
pub(super) fn line(size: usize) -> Vec<u8> {
    assert!(size >= 1, "载荷至少要放得下换行符");
    let mut payload = vec![0u8; size];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = b'!' + (index % 90) as u8;
    }
    payload[size - 1] = b'\n';
    payload
}

/// 本测试只用 IPv4 回环目标，其余地址族一律拒绝而不是悄悄连错地方。
pub(super) fn socket_addr(target: &TargetAddr) -> SocketAddr {
    match target {
        TargetAddr::V4(ip, port) => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), *port)
        }
        other => panic!("测试目标只支持 IPv4 回环，实际 {other:?}"),
    }
}

/// 读到换行为止（含换行）；每次读都受超时约束，EOF 提前即失败。
pub(super) async fn read_line<R: AsyncRead + Unpin>(stream: &mut R, limit: usize) -> Vec<u8> {
    let mut got: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let got_bytes = timeout(WAIT, stream.read(&mut buffer))
            .await
            .expect("读一行超时")
            .expect("读一行失败");
        assert!(got_bytes > 0, "在收满一行前就看到 EOF");
        got.extend_from_slice(&buffer[..got_bytes]);
        assert!(got.len() <= limit, "载荷超出测试上限 {limit}");
        if got.last() == Some(&b'\n') {
            return got;
        }
    }
}

/// echo 目标：每条连接读满一行后原样回写，再关写半，让本端看到干净结束。
pub(super) async fn serve_echo(listener: TcpListener, connections: usize) {
    for _ in 0..connections {
        let (mut conn, _peer) = timeout(WAIT, listener.accept())
            .await
            .expect("echo 接受超时")
            .expect("echo 应可接受");
        let request = read_line(&mut conn, ECHO_LIMIT).await;
        timeout(WAIT, conn.write_all(&request))
            .await
            .expect("echo 回写超时")
            .expect("echo 回写失败");
        timeout(WAIT, conn.shutdown())
            .await
            .expect("echo 关闭写半超时")
            .expect("echo 关闭写半失败");
    }
}

/// 最小 SOCKS5 客户端（no-auth）：拨 Xray 入站、握手、发出 CONNECT 目标请求。
pub(super) async fn socks5_connect(proxy_port: u16, target: &TargetAddr) -> TcpStream {
    let mut stream = timeout(WAIT, TcpStream::connect((Ipv4Addr::LOCALHOST, proxy_port)))
        .await
        .expect("连接 SOCKS 入站超时")
        .expect("应可连接 SOCKS 入站");
    timeout(WAIT, stream.write_all(&[0x05, 0x01, 0x00]))
        .await
        .expect("SOCKS greeting 超时")
        .expect("SOCKS greeting 失败");
    let mut choice = [0u8; 2];
    timeout(WAIT, stream.read_exact(&mut choice))
        .await
        .expect("SOCKS 认证选择超时")
        .expect("SOCKS 认证选择失败");
    assert_eq!(choice, [0x05, 0x00], "Xray 应选中 no-auth");

    let mut message: Vec<u8> = vec![0x05, 0x01, 0x00];
    target
        .encode_checked(&mut message)
        .expect("IPv4 回环目标可编码");
    timeout(WAIT, stream.write_all(&message))
        .await
        .expect("SOCKS 请求超时")
        .expect("SOCKS 请求失败");
    let mut head = [0u8; 4];
    timeout(WAIT, stream.read_exact(&mut head))
        .await
        .expect("SOCKS 响应头超时")
        .expect("SOCKS 响应头失败");
    assert_eq!(
        &head[..2],
        &[0x05, 0x00],
        "SOCKS CONNECT 应被接受：{head:?}"
    );
    let trailing = match head[3] {
        0x01 => 4 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            timeout(WAIT, stream.read_exact(&mut len))
                .await
                .expect("SOCKS 域名长度超时")
                .expect("SOCKS 域名长度截断");
            usize::from(len[0]) + 2
        }
        0x04 => 16 + 2,
        other => panic!("SOCKS 响应未知 ATYP：{other:#04x}"),
    };
    assert!(
        trailing <= SOCKS5_RESPONSE_MAX,
        "SOCKS 响应长度越界：{trailing}"
    );
    let mut bound = vec![0u8; trailing];
    timeout(WAIT, stream.read_exact(&mut bound))
        .await
        .expect("SOCKS 响应地址超时")
        .expect("SOCKS 响应地址失败");
    stream
}

/// 服务端视角一条连接的观测结果；不含 Debug，避免目标地址进日志。
pub(super) struct Served {
    /// 从变长头解出的目标地址。
    pub(super) target: Option<TargetAddr>,
    /// 请求方向重组出的载荷。
    pub(super) request: Vec<u8>,
    /// 请求方向除变长头首批载荷之外的 chunk 长度。
    pub(super) chunk_lens: Vec<usize>,
    /// 请求方向是否在对端关写半后干净收尾。
    pub(super) peer_closed: bool,
}

/// 一条连接的服务端一半：解请求 → 中继 echo → 回写响应 → 半关闭 → 等 EOF。
pub(super) async fn serve_one(stream: TcpStream, key: Key, replay: &mut SessionReplay) -> Served {
    let (mut read_half, mut write_half) = stream.into_split();
    let mut reader = Reader::new(key.clone(), Direction::Request, IDLE).expect("应可构造读端");
    let opened = timeout(WAIT, reader.open(&mut read_half, replay, clock(), None))
        .await
        .expect("开场读取超时")
        .expect("Xray 请求开场应通过全部校验");
    let target = match opened.association {
        Association::Request(target) => Some(target),
        Association::Response(_) => panic!("请求方向不得携带 request salt 关联块"),
    };
    assert!(
        reader.is_opened() && !reader.is_poisoned(),
        "开场通过后状态应自洽"
    );
    assert!(
        opened.payload.len() <= MAX_CHUNK_PAYLOAD,
        "变长头首批载荷超出单 chunk 上限：{}",
        opened.payload.len()
    );

    // 请求载荷：首批载荷在变长头内，其余按载荷帧补齐到换行。
    let mut request = opened.payload.clone();
    let mut chunk_lens: Vec<usize> = Vec::new();
    for _ in 0..MAX_CHUNKS {
        if request.last() == Some(&b'\n') {
            break;
        }
        let chunk = timeout(WAIT, reader.read_payload(&mut read_half))
            .await
            .expect("读载荷帧超时")
            .expect("读载荷帧失败");
        let Some(chunk) = chunk else {
            panic!("请求方向在收满一行前就看到 EOF");
        };
        assert!(
            chunk.len() <= MAX_CHUNK_PAYLOAD,
            "Xray 写出的 chunk 超过单块上限 {MAX_CHUNK_PAYLOAD}：{}",
            chunk.len()
        );
        chunk_lens.push(chunk.len());
        request.extend_from_slice(&chunk);
        assert!(request.len() <= ECHO_LIMIT, "请求载荷超出测试上限");
    }
    assert!(
        request.last() == Some(&b'\n'),
        "请求方向未在 chunk 上限内收满一行"
    );

    // 中继到本仓 spawn 的 echo 目标，取回同一行。
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

    // 响应方向：自己的随机 salt + 固定头回指请求 salt；首批载荷必须非空，
    // 否则参考实现的第一个 length chunk 会错位。故意只带前半，余下走载荷帧。
    let split = reply.len().div_ceil(2);
    let mut writer = Writer::random(&key, Direction::Response).expect("应可构造写端");
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
    assert!(
        writer.is_opened() && !writer.is_poisoned(),
        "响应头写出后状态应自洽"
    );
    for piece in reply[split..].chunks(MAX_CHUNK_PAYLOAD) {
        if !piece.is_empty() {
            timeout(WAIT, writer.write_payload(&mut write_half, piece))
                .await
                .expect("响应载荷写出超时")
                .expect("响应载荷应可写出");
        }
    }
    // 半关闭：写完 EOF chunk 即关写半，之后才等请求方向 EOF。
    timeout(WAIT, writer.write_finish(&mut write_half))
        .await
        .expect("响应 EOF 帧写出超时")
        .expect("响应 EOF 帧应可写出");
    timeout(WAIT, write_half.shutdown())
        .await
        .expect("关闭写半超时")
        .expect("应可半关闭");
    drop(upstream);

    // 请求方向收尾：参考实现不发 EOF chunk，靠对端关写半给出 EOF。
    let mut peer_closed = false;
    for _ in 0..MAX_CHUNKS {
        match timeout(WAIT, reader.read_payload(&mut read_half)).await {
            Ok(Ok(None)) => {
                peer_closed = true;
                break;
            }
            Ok(Ok(Some(chunk))) => {
                request.extend_from_slice(&chunk);
                assert!(request.len() <= ECHO_LIMIT, "收尾阶段载荷超出上限");
            }
            Ok(Err(error)) => {
                // EOF 或参考实现收尾时的连接重置都算对端已关写半；认证类失败不算。
                let io_eof = matches!(
                    &error,
                    lengsuo_ss2022::Error::Io(inner)
                        if matches!(inner.kind(), ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe)
                );
                assert!(
                    io_eof || matches!(error, lengsuo_ss2022::Error::Length),
                    "请求方向收尾出现非 EOF 失败：{error:?}"
                );
                peer_closed = true;
                break;
            }
            Err(_) => panic!("等待对端 EOF 超时"),
        }
    }
    Served {
        target,
        request,
        chunk_lens,
        peer_closed,
    }
}

pub(super) async fn rust_server(
    listener: TcpListener,
    key: Key,
    connections: usize,
) -> Vec<Served> {
    let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
    let mut served: Vec<Served> = Vec::new();
    for _ in 0..connections {
        let (stream, _peer) = timeout(OVERALL, listener.accept())
            .await
            .expect("本端监听器接受超时")
            .expect("本端监听器应可接受连接");
        served.push(serve_one(stream, key.clone(), &mut replay).await);
    }
    served
}
