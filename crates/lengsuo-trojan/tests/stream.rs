//! Trojan 异步请求头握手测试（UDP 帧见 `tests/stream_datagram.rs`）。
//!
//! 覆盖：逐字节到达且不吞应用载荷、错密码在读满哈希时早拒绝、格式错误立即返回、
//! 截断即 EOF 与静默对端超时、内存与真实 TCP 半关闭后的回包、零时长拒绝、
//! 单个截止时间覆盖整操作、错误不泄漏凭据。
//! 密码为测试专用假凭据；这些自建 roundtrip 只证明本实现内部一致，
//! 不宣称与 Xray 实跑互通。异步读写均由外层 timeout 或调用参数约束，
//! `read_to_end` 之前一定先关闭对端写端。

use std::time::Duration;

use lengsuo_trojan::codec::{self, Command, Request};
use lengsuo_trojan::stream::{receive_request, send_request, Error};
use lengsuo_trojan::Credential;
use lengsuo_trojan::TargetAddr;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// 测试假密码。
const PASSWORD: &str = "Trojan-Test-Passwd";
const OTHER_PASSWORD: &str = "other-test-passwd";

/// 正常操作等待；SILENT 用于确认静默对端确实超时。
const WAIT: Duration = Duration::from_secs(2);
const SILENT: Duration = Duration::from_millis(30);

fn credential() -> Credential {
    Credential::new(PASSWORD)
}

fn tcp_request() -> Request {
    Request {
        command: Command::Tcp,
        target: TargetAddr::V4([203, 0, 113, 7], 443),
    }
}

/// 头部 + 载荷的完整线上字节，便于固定偏移篡改。
fn encoded(request: &Request, password: &str) -> Vec<u8> {
    codec::encode(request, &Credential::new(password)).expect("可编码")
}

#[tokio::test]
async fn byte_at_a_time_request_keeps_application_payload() {
    timeout(WAIT, async {
        // 容量 1 强制逐字节交付，验证增量读取不吞后续载荷。
        let (mut client, mut server) = duplex(1);
        let header = encoded(&tcp_request(), PASSWORD);
        let writer = tokio::spawn(async move {
            for byte in header {
                client.write_all(&[byte]).await.expect("可写入");
            }
            client
                .write_all(b"GET /index HTTP/1.1")
                .await
                .expect("可写入");
        });

        let seen = receive_request(&mut server, &credential(), WAIT)
            .await
            .unwrap();
        assert_eq!(seen, tcp_request());
        let mut payload = [0u8; 19];
        server.read_exact(&mut payload).await.expect("可读载荷");
        assert_eq!(
            &payload, b"GET /index HTTP/1.1",
            "头部之后的字节必须原样留给应用"
        );
        writer.await.expect("写端任务");
    })
    .await
    .expect("逐字节握手超时");
}

#[tokio::test]
async fn wrong_password_rejected_before_rest_of_header_arrives() {
    timeout(WAIT, async {
        let (mut client, mut server) = duplex(128);
        // 只发送 56 字节哈希（错误密码），CRLF/命令/地址永不到达。
        let other = encoded(&tcp_request(), OTHER_PASSWORD);
        client.write_all(&other[..56]).await.expect("可写入");
        assert!(
            matches!(
                receive_request(&mut server, &credential(), WAIT).await,
                Err(Error::Codec(codec::Error::Authentication))
            ),
            "错误密码必须在哈希读满时立即拒绝，不等整头部"
        );
    })
    .await
    .expect("早拒绝超时");
}

#[tokio::test]
async fn header_format_errors_return_immediately() {
    timeout(WAIT, async {
        let base = encoded(&tcp_request(), PASSWORD);
        // 命令字节非法、CRLF 损坏与非法 ATYP 都在头部字节已可得时立刻失败，不续读；
        // 用 SILENT 证明失败不是等到超时才报出来的。
        for (index, byte, expect) in [
            (58usize, 0x02u8, "command"),
            (56usize, b'x', "crlf"),
            (59usize, 0x05u8, "address"),
        ] {
            let mut broken = base.clone();
            broken[index] = byte;
            let (mut client, mut server) = duplex(128);
            client.write_all(&broken).await.expect("可写入");
            let err = receive_request(&mut server, &credential(), SILENT)
                .await
                .expect_err("必须失败");
            match expect {
                "command" => assert!(
                    matches!(err, Error::Codec(codec::Error::InvalidCommand(0x02))),
                    "{err:?}"
                ),
                "crlf" => assert!(
                    matches!(err, Error::Codec(codec::Error::InvalidCrlf { offset: 56 })),
                    "{err:?}"
                ),
                _ => assert!(
                    matches!(err, Error::Codec(codec::Error::Address(_))),
                    "{err:?}"
                ),
            }
        }
    })
    .await
    .expect("格式错误超时");
}

#[tokio::test]
async fn truncated_header_reports_eof_and_silent_peer_times_out() {
    timeout(WAIT, async {
        let bytes = encoded(&tcp_request(), PASSWORD);
        // 每个截断点都关闭写端：读端只能得到 EOF（UnexpectedEof），不能误判成功。
        for end in [1usize, 56, 58, 59, 66, bytes.len() - 1] {
            let (mut client, mut server) = duplex(128);
            client.write_all(&bytes[..end]).await.expect("可写入");
            client.shutdown().await.expect("可关闭写端");
            assert!(
                matches!(
                    receive_request(&mut server, &credential(), WAIT).await,
                    Err(Error::Io(_))
                ),
                "截断点 {end}"
            );
        }
        // 静默对端（无任何字节、也不关闭）在截止时间后报超时。
        let (_client, mut server) = duplex(128);
        assert!(matches!(
            receive_request(&mut server, &credential(), SILENT).await,
            Err(Error::Timeout)
        ));
    })
    .await
    .expect("截断与静默超时");
}

#[tokio::test]
async fn zero_deadline_is_rejected_for_request_operations() {
    let (mut client, mut server) = duplex(128);
    let request = tcp_request();
    let mut cases = Vec::new();
    cases.push(send_request(&mut client, &request, &credential(), Duration::ZERO).await);
    cases.push(
        receive_request(&mut server, &credential(), Duration::ZERO)
            .await
            .map(|_| ()),
    );
    for err in cases {
        assert!(
            matches!(err, Err(Error::InvalidDeadline)),
            "零时长必须拒绝，得到 {err:?}"
        );
    }
}

#[tokio::test]
async fn one_deadline_covers_whole_fragmented_request() {
    timeout(WAIT, async {
        // 分片且中途停顿超过截止时间：整操作超时，不因后续字节到达而成功。
        let (mut slow, mut peer) = duplex(4096);
        let header = encoded(&tcp_request(), PASSWORD);
        slow.write_all(&header[..40]).await.expect("可写入首片");
        let tail = header[40..].to_vec();
        let laggard = tokio::spawn(async move {
            tokio::time::sleep(SILENT).await;
            slow.write_all(&tail).await.expect("可写入尾片");
        });
        assert!(matches!(
            receive_request(&mut peer, &credential(), Duration::from_millis(5)).await,
            Err(Error::Timeout)
        ));
        laggard.await.expect("延迟写端任务");

        // 续读片段最终能在足够长的截止时间内成功，证明超时来自截止时间本身。
        let (mut client, mut server) = duplex(1);
        let header = encoded(&tcp_request(), PASSWORD);
        let writer = tokio::spawn(async move {
            for byte in header {
                client.write_all(&[byte]).await.expect("可写入");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        assert_eq!(
            receive_request(&mut server, &credential(), WAIT)
                .await
                .unwrap(),
            tcp_request()
        );
        writer.await.expect("分片写端任务");
    })
    .await
    .expect("整体截止时间超时");
}

#[tokio::test]
async fn bidirectional_half_close_then_reply_in_memory() {
    timeout(WAIT, async {
        let (mut client, server) = duplex(4096);
        let worker = tokio::spawn(async move {
            let mut server = server;
            let seen = receive_request(&mut server, &credential(), WAIT)
                .await
                .unwrap();
            assert_eq!(seen, tcp_request());
            // 客户端先关写端，因此 read_to_end 有界。
            let mut request_body = Vec::new();
            server
                .read_to_end(&mut request_body)
                .await
                .expect("可读到 EOF");
            assert_eq!(request_body, b"hello");
            server.write_all(b"reply after EOF").await.expect("可回写");
            server.shutdown().await.expect("可关闭写端");
        });

        send_request(&mut client, &tcp_request(), &credential(), WAIT)
            .await
            .unwrap();
        client.write_all(b"hello").await.expect("可写入载荷");
        // 半关闭：只关写端，回包仍可读。
        client.shutdown().await.expect("可关闭写端");
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.expect("可读到 EOF");
        assert_eq!(reply, b"reply after EOF");
        worker.await.expect("服务端任务");
    })
    .await
    .expect("内存半关闭超时");
}

#[tokio::test]
async fn real_tcp_half_close_then_reply() {
    timeout(WAIT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("可监听");
        let addr = listener.local_addr().expect("可取地址");
        let server = tokio::spawn(async move {
            let (mut accepted, _peer) = listener.accept().await.expect("可接受");
            let seen = receive_request(&mut accepted, &credential(), WAIT)
                .await
                .unwrap();
            assert_eq!(seen, tcp_request());
            let mut body = Vec::new();
            accepted.read_to_end(&mut body).await.expect("可读到 EOF");
            assert_eq!(body, b"ping");
            accepted.write_all(b"pong").await.expect("可回写");
            accepted.shutdown().await.expect("可关闭");
        });

        let mut client = TcpStream::connect(addr).await.expect("可连接");
        send_request(&mut client, &tcp_request(), &credential(), WAIT)
            .await
            .unwrap();
        client.write_all(b"ping").await.expect("可写入载荷");
        // tokio 的 shutdown 对 TcpStream 只做写半关闭（SHUT_WR），读端仍可收回包。
        client.shutdown().await.expect("可半关闭写端");
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.expect("可读到 EOF");
        assert_eq!(reply, b"pong");
        server.await.expect("服务端任务");
    })
    .await
    .expect("真实 TCP 半关闭超时");
}

#[tokio::test]
async fn request_errors_never_leak_credentials() {
    timeout(WAIT, async {
        let failures = [
            {
                let (mut w, mut r) = duplex(128);
                w.write_all(&encoded(&tcp_request(), OTHER_PASSWORD))
                    .await
                    .expect("可写入");
                receive_request(&mut r, &credential(), WAIT)
                    .await
                    .map(|_| ())
            },
            {
                let (mut w, mut r) = duplex(128);
                let mut broken = encoded(&tcp_request(), PASSWORD);
                broken[56] = b'x';
                w.write_all(&broken).await.expect("可写入");
                receive_request(&mut r, &credential(), WAIT)
                    .await
                    .map(|_| ())
            },
            {
                let (_w, mut r) = duplex(128);
                receive_request(&mut r, &credential(), Duration::ZERO)
                    .await
                    .map(|_| ())
            },
        ];
        for err in failures {
            let err = err.expect_err("用例必须失败");
            let text = format!("{err}");
            let debug = format!("{err:?}");
            assert!(!text.contains(PASSWORD), "Display 泄漏密码：{text}");
            assert!(!debug.contains(PASSWORD), "Debug 泄漏密码：{debug}");
            // 哈希文本同样不得出现在错误里。
            let hash = credential().as_hex().to_owned();
            assert!(
                !text.contains(&hash) && !debug.contains(&hash),
                "错误泄漏哈希"
            );
        }
    })
    .await
    .expect("凭据不泄漏超时");
}
