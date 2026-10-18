//! 测试侧装配：TCP 监听 → tokio-rustls TlsAcceptor 握手 → session::serve。
//! 把握手结果与会话统计统一回报给测试断言，避免各用例重复 accept 循环。
use crate::report::{Failure, Report};
use crate::session;
use crate::tls;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// 单条入站连接的可观察结果。
#[derive(Debug)]
pub enum Observed {
    /// TLS 握手被拒（明文、错误 ClientHello 或版本不合法），未进入会话层。
    HandshakeRejected(String),
    /// TLS 握手成功后会话结束：统计与结束原因（`None` 表示干净结束）。
    SessionEnded(Report, Option<Failure>),
}

/// 接受循环：每连接独立任务；失败不回退明文。
pub async fn accept_loop(
    listener: TcpListener,
    acceptor: Arc<tokio_rustls::TlsAcceptor>,
    password: Vec<u8>,
    wait: Duration,
    sink: mpsc::UnboundedSender<Observed>,
) {
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            break;
        };
        let acceptor = Arc::clone(&acceptor);
        let password = password.clone();
        let sink = sink.clone();
        tokio::spawn(async move {
            let stream = match tls::handshake(&acceptor, socket, wait).await {
                Ok(stream) => stream,
                Err(err) => {
                    let reason = match err {
                        Failure::Handshake(text) => text,
                        other => format!("{other:?}"),
                    };
                    let _ = sink.send(Observed::HandshakeRejected(reason));
                    return;
                }
            };
            let (stats, outcome) = session::serve(stream, &password, wait).await;
            let _ = sink.send(Observed::SessionEnded(stats, outcome.err()));
        });
    }
}

/// 绑定回环端口并启动接受循环，返回端口与结果通道。
pub fn spawn_tls_server(
    password: &[u8],
    acceptor: tokio_rustls::TlsAcceptor,
    wait: Duration,
) -> (u16, mpsc::UnboundedReceiver<Observed>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定回环端口失败");
    listener.set_nonblocking(true).expect("设置非阻塞失败");
    let port = listener.local_addr().expect("读取端口").port();
    let listener = TcpListener::from_std(listener).expect("转换 tokio 监听失败");
    let (sink, source) = mpsc::unbounded_channel();
    tokio::spawn(accept_loop(
        listener,
        Arc::new(acceptor),
        password.to_vec(),
        wait,
        sink,
    ));
    (port, source)
}

/// 回环 echo 目标，返回其地址（连接后原样回写直到 EOF）。
pub async fn spawn_echo() -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let echo = TcpListener::bind("127.0.0.1:0").await.expect("echo 监听");
    let addr = echo.local_addr().expect("echo 地址");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            if socket.write_all(&buffer[..count]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}
