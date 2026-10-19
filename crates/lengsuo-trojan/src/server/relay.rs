//! CONNECT 出站建立与双向中继（半关闭正确传递），对齐 `proxy/trojan/server.go`
//! 的 `handleConnection`。
//!
//! 参考把一段连接拆成 `requestDone`（客户端 → 目标）与 `responseDone`（目标 →
//! 客户端）两条并发拷贝：任一侧读到 EOF 就 `Close` 对端写侧（half-close），另一侧
//! 仍继续到自己的 EOF；任一侧出错则 `Interrupt` 双向并结束。这里用两个 pinned
//! future + `tokio::select!` 表达同一结构，不重排、不合并：
//!
//! - 每条拷贝的单个读/写操作都包在一个空闲截止时间内（参考的
//!   `CancelAfterInactivity` 计时器在每次活动后重置；逐操作超时的效果等价——
//!   任何一段静默超过 `connection_idle` 即断连，偏差见 `docs/trojan-status.md`）。
//! - 读满缓冲后写回，缓冲不跨界帧语义（trojan TCP 流本身无帧边界）。
//! - 一侧干净 EOF：half-close 对端写侧，继续等另一侧，直到它也 EOF / 空闲截止。
//! - 一侧出错：立刻取消另一侧（drop 即取消），对齐参考 `Interrupt` 双向。

use std::future::Future;
use std::time::Duration;

use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::server::Error;

/// 内部中继缓冲：只影响读盘粒度，不改变线上字节。
const COPY_BUF: usize = 32 * 1024;

/// 解析目标并建立出站 TCP 连接（单个截止时间；域名走 tokio DNS）。
///
/// 参考的 `dispatcher.Dispatch` 在 routing/dispatcher 层完成，trojan 代码只拿到
/// 建好的连接；本运行时没有 dispatcher 层，这里就是出站建立点。参考在
/// dispatcher 内部做退避重试，本实现为单次拨号（偏差记录在
/// `docs/trojan-status.md` 偏离清单）。
pub async fn connect_target(target: &TargetAddr, deadline: Duration) -> Result<TcpStream, Error> {
    if deadline.is_zero() {
        return Err(Error::InvalidDeadline);
    }
    let dial = async {
        match target {
            TargetAddr::V4(ip, port) => {
                TcpStream::connect(std::net::SocketAddr::from((*ip, *port))).await
            }
            TargetAddr::V6(ip, port) => {
                TcpStream::connect(std::net::SocketAddr::from((*ip, *port))).await
            }
            TargetAddr::Domain(host, port) => TcpStream::connect((host.as_str(), *port)).await,
        }
    };
    timeout(deadline, dial)
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(Error::Dial)
}

/// 客户端读写两半与出站读写两半之间的双向中继，`idle` 为单段静默上限。
pub async fn relay<Cr, Cw, Ur, Uw>(
    client_reader: Cr,
    client_writer: Cw,
    upstream_reader: Ur,
    upstream_writer: Uw,
    idle: Duration,
) -> Result<(), Error>
where
    Cr: AsyncRead + Unpin,
    Cw: AsyncWrite + Unpin,
    Ur: AsyncRead + Unpin,
    Uw: AsyncWrite + Unpin,
{
    if idle.is_zero() {
        return Err(Error::InvalidDeadline);
    }
    let mut up = Box::pin(copy_until_eof(client_reader, upstream_writer, idle));
    let mut down = Box::pin(copy_until_eof(upstream_reader, client_writer, idle));

    tokio::select! {
        first = &mut up => settle(&mut down, first).await,
        first = &mut down => settle(&mut up, first).await,
    }
}

/// 一侧已完成：干净 EOF 才继续等另一侧，出错立即取消另一侧。
async fn settle<F>(remaining: &mut F, first: Result<u64, Error>) -> Result<(), Error>
where
    F: Future<Output = Result<u64, Error>> + Unpin,
{
    match first {
        Ok(_bytes) => remaining.await.map(|_| ()),
        Err(err) => Err(err),
    }
}

/// 单方向拷贝：读到 EOF 就对写侧 `shutdown`（half-close），错误上抛。
async fn copy_until_eof<R, W>(mut reader: R, mut writer: W, idle: Duration) -> Result<u64, Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; COPY_BUF];
    let mut total = 0u64;
    loop {
        let read = timeout(idle, reader.read(&mut buf))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Relay)?;
        if read == 0 {
            timeout(idle, writer.shutdown())
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(Error::Relay)?;
            return Ok(total);
        }
        timeout(idle, writer.write_all(&buf[..read]))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Relay)?;
        total += read as u64;
    }
}
