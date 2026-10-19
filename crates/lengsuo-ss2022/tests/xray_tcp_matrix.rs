//! SS2022 TCP 三算法双向矩阵与半关闭/异常路径验收（仅回环、测试专用假密钥）。
//!
//! 三套件 `2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` /
//! `2022-blake3-chacha20-poly1305` × 两方向（Rust 客户端→Xray 服务端；Xray 客户端
//! SOCKS→Rust 服务端）× 载荷 1 / 4096 / 262144 字节，逐字节回比较；每个单元格记录
//! **首个 SS2022 写块长度**（请求开场 salt+固定头+变长头，方向一由本 crate 写出、方向二
//! 由计数读端实测）与**请求/响应载荷 chunk 数**。
//!
//! 半关闭两项：客户端 `shutdown(Write)` 后仍按有限超时读到完整响应；Rust 服务端写完
//! 即释放连接，Xray 客户端读端在有限超时内拿到 EOF（0 字节）而非悬挂。
//!
//! 异常路径四项判据全部针对本 crate 接收侧 [`Reader`]/[`SessionReplay`] 语义，纯 Rust
//! 原语即可判定，不依赖 Xray：错误 PSK 报 [`Error::Authentication`]、截断头报
//! [`Error::Length`]、篡改 AEAD tag 报 [`Error::Authentication`]、同 salt 二次开场报
//! [`Error::Replay`]；每项都注有限超时。文件随参考套件一起以 `--ignored` 运行。

// 复用 `reverse_support` 时本文件只用到其中一部分，其余辅助函数自然成为死代码。
#![allow(dead_code)]

mod reverse_support;
#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;

use base64::{engine::general_purpose::STANDARD, Engine};
use lengsuo_ss2022::{
    crypto::{Key, Method},
    tcp::{
        receive::clock_at, Association, Direction, Reader, SessionReplay, Writer, MAX_CHUNK_PAYLOAD,
    },
    Error,
};
use reverse_support::*;
use serde_json::json;
use ss_core::target::TargetAddr;
use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 三套件矩阵（含 ChaCha20；`reverse_support::methods` 只到 AES-256）。
fn matrix_methods() -> [(Method, &'static str); 3] {
    [
        (Method::Aes128, "2022-blake3-aes-128-gcm"),
        (Method::Aes256, "2022-blake3-aes-256-gcm"),
        (Method::ChaCha20, "2022-blake3-chacha20-poly1305"),
    ]
}

/// 载荷规格：1、4096、262144（跨多个 65535 上限 chunk）。
fn matrix_sizes() -> [usize; 3] {
    [1, 4096, 262_144]
}

fn server_config(port: u16, method: &str, psk: &[u8]) -> serde_json::Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"shadowsocks",
            "settings":{"method":method,"password":STANDARD.encode(psk),"network":"tcp"}}],
        "outbounds":[{"protocol":"freedom"}]})
}

fn xray_client_config(port: u16, rust_port: u16, method: &str, psk: &[u8]) -> serde_json::Value {
    json!({"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"socks",
            "settings":{"auth":"noauth","udp":false}}],
        "outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{
            "address":"127.0.0.1","port":rust_port,"method":method,
            "password":STANDARD.encode(psk)}]}}]})
}

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

/// 方向一：Rust 客户端 → Xray SS2022 服务端。三套件 × 三载荷，记录首包长与双向 chunk 数。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn matrix_forward_rust_client_to_xray() {
    timeout(OVERALL, async {
        for (method, name) in matrix_methods() {
            let psk = vec![0x11; method.key_len()];
            let key = Key::new(method, &psk).expect("假 PSK 应可用");
            let port = free_port();
            let reference = launch(server_config(port, name, &psk), port).await;
            for size in matrix_sizes() {
                let echo = TcpListener::bind(BIND).await.expect("echo 应可监听");
                let echo_port = echo.local_addr().expect("echo 应有地址").port();
                let echo_task = tokio::spawn(serve_echo(echo, 1));
                let target = TargetAddr::V4(LOOPBACK, echo_port);

                let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    .await
                    .expect("连接 Xray");
                let mut writer = Writer::random(&key, Direction::Request).expect("可构造写端");
                // 首个 SS2022 写块整体成型，量出其线长即为首包长。
                let mut opening = Vec::new();
                writer
                    .write_request_header(&mut opening, &target, b"", now_secs(), 8)
                    .await
                    .unwrap_or_else(|error| panic!("{name}/{size} 请求开场写出：{error:?}"));
                let first_packet_len = opening.len();
                // IPv4 变长头 = 7(ATYP+addr+port)+2(padding 字段)+8(padding)+0(首批载荷)；
                // 加 16B AEAD tag 与固定头 11+16B。锁定首包线长即锁定线格式。
                assert_eq!(
                    first_packet_len,
                    method.key_len() + 60,
                    "{name}/{size} 请求开场线长偏离规范"
                );
                client.write_all(&opening).await.expect("开场应可落盘");

                let want = line(size);
                let mut request_chunks = 0usize;
                for piece in want.chunks(MAX_CHUNK_PAYLOAD) {
                    writer
                        .write_payload(&mut client, piece)
                        .await
                        .expect("载荷应可写出");
                    request_chunks += 1;
                }
                assert_eq!(
                    request_chunks,
                    want.chunks(MAX_CHUNK_PAYLOAD).count(),
                    "{name}/{size} 请求分块数应自洽"
                );
                writer.write_finish(&mut client).await.expect("EOF 帧应可写出");

                let mut reader =
                    Reader::new(key.clone(), Direction::Response, Duration::from_secs(5))
                        .expect("可构造读端");
                let mut replay =
                    SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
                let request_salt = writer.salt().to_vec();
                let opened = reader
                    .open(&mut client, &mut replay, clock(), Some(&request_salt))
                    .await
                    .unwrap_or_else(|error| panic!("{name}/{size} 响应开场校验：{error:?}"));
                assert!(
                    matches!(&opened.association, Association::Response(salt) if salt == &request_salt),
                    "{name}/{size} 响应回指 salt 必须等于请求 salt"
                );
                let mut got = opened.payload.clone();
                let mut response_chunks = usize::from(!opened.payload.is_empty());
                while got.len() < want.len() {
                    match reader.read_payload(&mut client).await.expect("响应载荷可读") {
                        Some(chunk) => {
                            got.extend_from_slice(&chunk);
                            response_chunks += 1;
                        }
                        None => break,
                    }
                }
                assert_eq!(got, want, "{name}/{size} 回程载荷逐字节一致");
                println!(
                    "cell forward {name} {size}: first_packet={first_packet_len} \
                     request_chunks={request_chunks} response_chunks={response_chunks}"
                );
                timeout(WAIT, echo_task)
                    .await
                    .expect("echo 任务超时")
                    .expect("echo 任务失败");
            }
            drop(reference);
        }
    })
    .await
    .expect("正向矩阵总超时");
}

/// 方向二：Xray 客户端 SOCKS → Rust 服务端。三套件 × 三载荷，记录首包长与双向 chunk 数。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn matrix_reverse_xray_client_to_rust_server() {
    timeout(OVERALL, async {
        for (method, name) in matrix_methods() {
            let psk = vec![0x11; method.key_len()];
            let key = Key::new(method, &psk).expect("假 PSK 应可用");
            let echo = TcpListener::bind(BIND).await.expect("echo 应可监听");
            let echo_port = echo.local_addr().expect("echo 应有地址").port();
            let server = TcpListener::bind(BIND).await.expect("本端应可监听");
            let rust_port = server.local_addr().expect("本端应有地址").port();
            let specs = matrix_sizes();
            let echo_task = tokio::spawn(serve_echo(echo, specs.len()));
            let served_task = tokio::spawn(async move {
                let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
                let mut rows: Vec<Row> = Vec::new();
                for _ in 0..specs.len() {
                    let (stream, _peer) = timeout(OVERALL, server.accept())
                        .await
                        .expect("本端监听器接受超时")
                        .expect("本端监听器应可接受连接");
                    rows.push(serve_one_matrix(stream, key.clone(), &mut replay, true).await);
                }
                rows
            });
            let port = free_port();
            let reference = launch(xray_client_config(port, rust_port, name, &psk), port).await;
            let target = TargetAddr::V4(LOOPBACK, echo_port);
            for size in specs {
                let want = line(size);
                let mut stream = socks5_connect(port, &target).await;
                timeout(WAIT, stream.write_all(&want))
                    .await
                    .expect("SOCKS 写载荷超时")
                    .expect("SOCKS 写载荷失败");
                let mut reply = read_line(&mut stream, ECHO_LIMIT).await;
                while reply.len() < want.len() {
                    reply.extend_from_slice(&read_line(&mut stream, ECHO_LIMIT).await);
                }
                assert_eq!(reply, want, "{name}/{size} 端到端载荷不符");
                timeout(WAIT, stream.shutdown())
                    .await
                    .expect("SOCKS 关写半超时")
                    .expect("SOCKS 关写半失败");
                drop(stream);
            }
            let rows = served_task.await.expect("本端服务任务");
            assert_eq!(rows.len(), specs.len(), "本端应处理每条互通连接");
            for (index, row) in rows.iter().enumerate() {
                let want = line(specs[index]);
                assert_eq!(
                    row.request, want,
                    "{name}/{} 请求方向载荷不符",
                    specs[index]
                );
                assert_eq!(row.reply, want, "{name}/{} 响应方向载荷不符", specs[index]);
                assert!(
                    row.first_packet_len > method.key_len() + 27,
                    "{name}/{} 首包长过短：{}",
                    specs[index],
                    row.first_packet_len
                );
                println!(
                    "cell reverse {name} {}: first_packet={} request_chunks={} \
                     response_chunks={}",
                    specs[index], row.first_packet_len, row.request_chunks, row.response_chunks
                );
            }
            drop(reference);
            timeout(WAIT, echo_task)
                .await
                .expect("echo 服务任务超时")
                .expect("echo 服务任务失败");
        }
    })
    .await
    .expect("反向矩阵总超时");
}

/// 半关闭（客户端侧）：`shutdown(Write)` 之后仍按有限超时读到完整响应。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn half_close_rust_client_still_reads_response() {
    let method = Method::Aes256;
    let name = "2022-blake3-aes-256-gcm";
    timeout(WAIT, async {
        let psk = vec![0x33; method.key_len()];
        let key = Key::new(method, &psk).expect("假 PSK 应可用");
        let echo = TcpListener::bind(BIND).await.expect("echo 应可监听");
        let echo_port = echo.local_addr().expect("echo 应有地址").port();
        let echo_task = tokio::spawn(serve_echo(echo, 1));
        let port = free_port();
        let reference = launch(server_config(port, name, &psk), port).await;

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("连接 Xray");
        let target = TargetAddr::V4(LOOPBACK, echo_port);
        let want: &[u8] = b"half-close-ping\n";
        let mut writer = Writer::random(&key, Direction::Request).expect("可构造写端");
        let mut opening = Vec::new();
        writer
            .write_request_header(&mut opening, &target, want, now_secs(), 8)
            .await
            .expect("请求开场可写");
        client.write_all(&opening).await.expect("开场应可落盘");
        writer
            .write_finish(&mut client)
            .await
            .expect("EOF 帧应可写出");
        // 关键：先关写半，再读回程；读半必须仍然可用并读到完整响应。
        client.shutdown().await.expect("关写半失败");

        let mut reader = Reader::new(key.clone(), Direction::Response, Duration::from_secs(5))
            .expect("可构造读端");
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let request_salt = writer.salt().to_vec();
        let opened = reader
            .open(&mut client, &mut replay, clock(), Some(&request_salt))
            .await
            .expect("关写半后仍应能读响应开场");
        let mut got = opened.payload;
        while got.len() < want.len() {
            match reader
                .read_payload(&mut client)
                .await
                .expect("响应载荷可读")
            {
                Some(chunk) => got.extend_from_slice(&chunk),
                None => break,
            }
        }
        assert_eq!(got, want, "关写半后回程必须完整一致");
        timeout(WAIT, echo_task)
            .await
            .expect("echo 任务超时")
            .expect("echo 任务失败");
        drop(reference);
    })
    .await
    .expect("半关闭客户端读响应总超时");
}

/// 半关闭（服务端侧）：Rust 服务端写完整条响应后释放连接，Xray 客户端读端必须见 EOF。
#[tokio::test]
#[ignore = "需要显式提供固定版本 Xray"]
async fn half_close_rust_server_close_gives_client_eof() {
    let method = Method::Aes256;
    let name = "2022-blake3-aes-256-gcm";
    timeout(OVERALL, async {
        let psk = vec![0x44; method.key_len()];
        let key = Key::new(method, &psk).expect("假 PSK 应可用");
        let echo = TcpListener::bind(BIND).await.expect("echo 应可监听");
        let echo_port = echo.local_addr().expect("echo 应有地址").port();
        let echo_task = tokio::spawn(serve_echo(echo, 1));
        let server = TcpListener::bind(BIND).await.expect("本端应可监听");
        let rust_port = server.local_addr().expect("本端应有地址").port();
        let served_task = tokio::spawn(async move {
            let (stream, _peer) = timeout(OVERALL, server.accept())
                .await
                .expect("本端监听器接受超时")
                .expect("本端监听器应可接受连接");
            let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
            // wait_peer=false：写完响应即释放连接，不等待对端 EOF。
            serve_one_matrix(stream, key, &mut replay, false).await
        });
        let port = free_port();
        let reference = launch(xray_client_config(port, rust_port, name, &psk), port).await;
        let target = TargetAddr::V4(LOOPBACK, echo_port);
        let want: Vec<u8> = b"server-close-eof\n".to_vec();
        let mut stream = socks5_connect(port, &target).await;
        timeout(WAIT, stream.write_all(&want))
            .await
            .expect("SOCKS 写载荷超时")
            .expect("SOCKS 写载荷失败");
        let reply = read_line(&mut stream, ECHO_LIMIT).await;
        assert_eq!(reply, want, "响应载荷必须完整读回");
        // 客户端也半关闭写方向：让 Xray 上传方向收尾，服务端关闭才会完整传播为 EOF。
        timeout(WAIT, stream.shutdown())
            .await
            .expect("SOCKS 关写半超时")
            .expect("SOCKS 关写半失败");
        // 服务端已释放连接：读端必须在有限超时内拿到 EOF（0 字节），而非悬挂。
        let mut label = [0u8; 1];
        let n = timeout(WAIT, stream.read(&mut label))
            .await
            .expect("等待服务端关闭给出 EOF 超时")
            .expect("读 EOF 失败");
        assert_eq!(n, 0, "服务端关闭后客户端读端必须读到 EOF");
        let row = served_task.await.expect("本端服务任务");
        assert_eq!(row.request, want, "服务端记录的请求方向载荷不符");
        drop(stream);
        drop(reference);
        timeout(WAIT, echo_task)
            .await
            .expect("echo 服务任务超时")
            .expect("echo 服务任务失败");
    })
    .await
    .expect("服务端关闭给出 EOF 总超时");
}

/// 异常路径：错误 PSK、截断头、篡改 AEAD tag、同 salt 重放，四项判据各配有限超时。
/// 纯 Rust 原语即可判定，不依赖 Xray；判据按下文每个 `assert!(matches!(...))` 锁定。
#[tokio::test]
#[ignore = "随参考套件以 --ignored 一起运行"]
async fn receiver_rejects_abnormal_streams() {
    let method = Method::Aes256;
    let key_a = Key::new(method, &[0x11; 32]).expect("假密钥 A 可用");
    let key_b = Key::new(method, &[0x99; 32]).expect("假密钥 B 可用");
    let salt = vec![0x5A; method.key_len()];
    let target = TargetAddr::V4([127, 0, 0, 1], 9);
    let now = now_secs();

    // 1) 错误 PSK：同一 salt 下的请求开场，用另一个密钥的读端必须认证失败。
    {
        let wire = sealed_request(&key_a, &salt, &target, b"wrong-key", now).await;
        let (mut client, mut server) = loopback_pair().await;
        client.write_all(&wire).await.expect("应可写入");
        drop(client);
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut reader = Reader::new(key_b.clone(), Direction::Request, Duration::from_secs(2))
            .expect("可构造读端");
        let outcome = timeout(WAIT, reader.open(&mut server, &mut replay, clock(), None))
            .await
            .expect("错误 PSK 判定超时");
        let error = rejected_tcp(outcome, "错误 PSK 的密文");
        assert!(
            matches!(error, Error::Authentication),
            "错误 PSK 应报 Authentication，实际 {error:?}"
        );
    }

    // 2) 截断头：只写 salt 后关闭，读端在固定头处应报 Length，而非认证或悬挂。
    {
        let (mut client, mut server) = loopback_pair().await;
        client.write_all(&salt).await.expect("应可写入 salt");
        client.shutdown().await.expect("关写半失败");
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut reader = Reader::new(key_a.clone(), Direction::Request, Duration::from_secs(2))
            .expect("可构造读端");
        let outcome = timeout(WAIT, reader.open(&mut server, &mut replay, clock(), None))
            .await
            .expect("截断头判定超时");
        let error = rejected_tcp(outcome, "截断头");
        assert!(
            matches!(error, Error::Length),
            "截断头应报 Length，实际 {error:?}"
        );
    }

    // 3) 篡改固定头 AEAD tag：翻转固定头 auth tag 首字节，读端必须认证失败。
    {
        let mut wire = sealed_request(&key_a, &salt, &target, b"tampered", now).await;
        wire[salt.len() + 11] ^= 0x01;
        let (mut client, mut server) = loopback_pair().await;
        client.write_all(&wire).await.expect("应可写入");
        drop(client);
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let mut reader = Reader::new(key_a.clone(), Direction::Request, Duration::from_secs(2))
            .expect("可构造读端");
        let outcome = timeout(WAIT, reader.open(&mut server, &mut replay, clock(), None))
            .await
            .expect("篡改 tag 判定超时");
        let error = rejected_tcp(outcome, "篡改 AEAD tag 的密文");
        assert!(
            matches!(error, Error::Authentication),
            "篡改 AEAD tag 应报 Authentication，实际 {error:?}"
        );
    }

    // 4) 同 salt 重放：同一 salt 第二次合法开场必须被 SessionReplay 判为重放。
    {
        let mut replay = SessionReplay::new(Duration::from_secs(60)).expect("合法保留期");
        let first = sealed_request(&key_a, &salt, &target, b"first", now).await;
        let (mut client, mut server) = loopback_pair().await;
        client.write_all(&first).await.expect("首条应可写入");
        drop(client);
        let mut reader = Reader::new(key_a.clone(), Direction::Request, Duration::from_secs(2))
            .expect("可构造读端");
        let opened = timeout(WAIT, reader.open(&mut server, &mut replay, clock(), None))
            .await
            .expect("首条判定超时")
            .expect("首条合法开场应通过");
        assert_eq!(opened.payload, b"first", "首条开场载荷应可解出");

        let second = sealed_request(&key_a, &salt, &target, b"second", now).await;
        let (mut client, mut server) = loopback_pair().await;
        client.write_all(&second).await.expect("次条应可写入");
        drop(client);
        let mut reader = Reader::new(key_a.clone(), Direction::Request, Duration::from_secs(2))
            .expect("可构造读端");
        let outcome = timeout(WAIT, reader.open(&mut server, &mut replay, clock(), None))
            .await
            .expect("重放判定超时");
        let error = rejected_tcp(outcome, "同 salt 第二次开场");
        assert!(
            matches!(error, Error::Replay),
            "同 salt 重放应报 Replay，实际 {error:?}"
        );
    }
}
