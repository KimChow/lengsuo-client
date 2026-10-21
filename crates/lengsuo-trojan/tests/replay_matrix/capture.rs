//! `tests/replay_matrix.rs` 的**头部捕获端**：被动观察参考客户端写出的字节。
//!
//! 存在意义：Trojan 头部在 TLS 之内（或明文之上），只有位于客户端与服务端之间的
//! 观察者能看清「参考客户端到底写了什么」。捕获端**不参与**任何认证或路由决策，
//! 它只按 Trojan 头部格式把那段字节记录下来。
//!
//! 头部长度按参考 `proxy/trojan/protocol.go` 的 `ConnReader.ParseHeader` 顺序推导：
//! 56 字节哈希 → 2 字节 CRLF → 1 字节命令 → SOCKS 地址（ATYP 决定长度）→ 2 字节 CRLF。

#![allow(dead_code)]

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::harness::WAIT;

/// 头部捕获服务端：**被动观察者**。
///
/// 它按 Trojan 头部格式解析自己收到的字节（56 字节哈希 + CRLF + 命令 + 地址 +
/// CRLF），把整段头部原样记录下来，然后**原样转发**给上游——它不参与任何
/// 认证或路由决策，只把参考客户端写出的字节暴露出来。
pub struct CaptureServer {
    pub port: u16,
    headers: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl CaptureServer {
    /// 绑定捕获端；`upstream` 是要转发到的上游端口。
    ///
    /// `forward_header` 决定**头部本身**是否转发给上游：
    /// - `true`：上游是 trojan 服务端，它要靠这段头部做认证与路由 ⇒ 整条流
    ///   （头部 + 载荷）原样转发；
    /// - `false`：上游是普通业务目标（回显后端）⇒ 只转发头部之后的载荷，
    ///   否则业务目标会把头部字节当成载荷回显。
    pub async fn spawn(upstream: u16, forward_header: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let headers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = headers.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let sink = sink.clone();
                tokio::spawn(async move {
                    let _ = capture_one(socket, upstream, forward_header, sink).await;
                });
            }
        });
        Self {
            port,
            headers,
            task,
        }
    }

    /// 迄今捕获到的头部（每个连接一段）。
    pub fn headers(&self) -> Vec<Vec<u8>> {
        self.headers.lock().unwrap().clone()
    }

    /// 停掉捕获端。
    pub async fn stop(self) {
        self.task.abort();
        let _ = tokio::time::timeout(WAIT, self.task).await;
    }
}

/// 捕获一条连接：读出整段 trojan 头部并记录，然后按 `forward_header` 决定
/// 头部是否也转发给上游。
///
/// 捕获端只是**被动观察者**：它不修改任何字节，只决定头部要不要跟着走。
async fn capture_one(
    mut socket: TcpStream,
    upstream: u16,
    forward_header: bool,
    sink: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
) -> std::io::Result<()> {
    let header = match read_trojan_header(&mut socket).await {
        Ok(header) => header,
        Err(_) => return Err(std::io::Error::other("头部读取失败")),
    };
    sink.lock().unwrap().push(header.clone());
    let mut target =
        TcpStream::connect(std::net::SocketAddr::from(([127, 0, 0, 1], upstream))).await?;
    if forward_header {
        // 上游是 trojan 服务端：头部必须原样转发（它要靠这段头部认证与路由）。
        tokio::time::timeout(WAIT, target.write_all(&header))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "头部转发超时"))?
            .map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, error.to_string())
            })?;
    }
    // 双向各拷一份，EOF 只关对端写侧（半关闭），两侧都结束才返回——回程不会
    // 被提前切断。
    let (mut client_read, mut client_write) = socket.split();
    let (mut target_read, mut target_write) = target.split();
    let (up, down) = tokio::join!(
        copy_bounded(&mut client_read, &mut target_write),
        copy_bounded(&mut target_read, &mut client_write)
    );
    up?;
    down?;
    Ok(())
}

/// 按 Trojan 头部格式读出**整段**头部（只读头部本身，不多读）。
///
/// 长度推导与参考 `protocol.go` 的 `ConnReader.ParseHeader` 同序：
/// 56 字节哈希 → 2 字节 CRLF → 1 字节命令 → SOCKS 地址（ATYP 决定长度）→ 2 字节 CRLF。
async fn read_trojan_header(socket: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(68);
    // 56 字节哈希 + 2 字节 CRLF + 1 字节命令 + 1 字节 ATYP。
    read_exact_into(socket, &mut buf, 60).await?;
    // ATYP 之后还需要的字节数：地址本体 + 端口 + 尾 CRLF。
    let remaining = match buf[59] {
        0x01 => 4 + 2 + 2,
        0x04 => 16 + 2 + 2,
        0x03 => {
            // 域名多一个长度字节：先读它，再算域名本体长度。
            read_exact_into(socket, &mut buf, 61).await?;
            usize::from(buf[60]) + 2 + 2
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("未知 ATYP：{other:#04x}"),
            ))
        }
    };
    let total = 60 + remaining;
    read_exact_into(socket, &mut buf, total).await?;
    buf.truncate(total);
    Ok(buf)
}

/// 读到 `buf.len() == want` 为止（不超出）。
async fn read_exact_into(
    socket: &mut TcpStream,
    buf: &mut Vec<u8>,
    want: usize,
) -> std::io::Result<()> {
    while buf.len() < want {
        let mut chunk = [0u8; 256];
        let want_now = want - buf.len();
        let take = want_now.min(chunk.len());
        let read = tokio::time::timeout(WAIT, socket.read(&mut chunk[..take]))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "头部读取超时"))?
            .map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, error.to_string())
            })?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "头部未读完",
            ));
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    Ok(())
}

/// 有界双向拷贝：单次读/写都有截止时间。
async fn copy_bounded<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let read = tokio::time::timeout(WAIT, reader.read(&mut buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "拷贝读超时"))?
            .map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, error.to_string())
            })?;
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        tokio::time::timeout(WAIT, writer.write_all(&buf[..read]))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "拷贝写超时"))?
            .map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, error.to_string())
            })?;
    }
}
