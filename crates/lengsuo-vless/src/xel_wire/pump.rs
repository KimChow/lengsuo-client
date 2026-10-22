//! 记录层与管道之间的搬运任务（读方向 / 写方向）。
//!
//! 从 [`super`] 拆出以保持单文件 ≤400 行（软约束）。

use std::{io, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

use super::config::{Error, MAX_PLAINTEXT_PER_RECORD};
use super::endpoint::{XelReceiver, XelSender};

/// 单次底层 I/O 的截止时间（所有网络操作必须有界）。
pub(super) const IO_DEADLINE: Duration = Duration::from_secs(10);

/// 读任务：传输 → 管道。按记录解封，把明文写进管道。
pub(super) async fn pump_reads<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    receiver: &mut XelReceiver,
    mut transport: R,
    mut sink: W,
) -> Result<(), Error> {
    let mut buffer = vec![0u8; MAX_PLAINTEXT_PER_RECORD];
    loop {
        let read = timeout(IO_DEADLINE, transport.read(&mut buffer))
            .await
            .map_err(|_| Error::Timeout)??;
        if read == 0 {
            // 对端关闭写半：残字节即截断（fail-closed），随后关闭应用侧写端。
            receiver.finish()?;
            let _ = sink.shutdown().await;
            return Ok(());
        }
        let plaintext = receiver.open(&buffer[..read])?;
        if !plaintext.is_empty() {
            timeout(IO_DEADLINE, sink.write_all(&plaintext))
                .await
                .map_err(|_| Error::Timeout)??;
        }
    }
}

/// 写任务：管道 → 传输。把应用字节封成记录写出。
pub(super) async fn pump_writes<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    sender: &mut XelSender,
    mut source: R,
    mut transport: W,
) -> Result<(), Error> {
    let mut buffer = vec![0u8; MAX_PLAINTEXT_PER_RECORD];
    loop {
        let read = timeout(IO_DEADLINE, source.read(&mut buffer))
            .await
            .map_err(|_| Error::Timeout)??;
        if read == 0 {
            transport.shutdown().await?;
            return Ok(());
        }
        let wire = sender.seal(&buffer[..read])?;
        timeout(IO_DEADLINE, transport.write_all(&wire))
            .await
            .map_err(|_| Error::Timeout)??;
    }
}

/// `JoinHandle` 的两层结果拍平（`JoinError` → `io::Error`）。
pub(super) fn flatten(
    outcome: Result<Result<(), Error>, tokio::task::JoinError>,
) -> Result<(), Error> {
    match outcome {
        Ok(inner) => inner,
        Err(join) => Err(Error::Io(io::Error::other(join.to_string()))),
    }
}

/// 复制一份错误（`io::Error` 不实现 `Clone`，按 kind 重建，不回显原始字节）。
///
/// 复制只保留错误**种类**与静态文案：I/O 错误用 `other` 重建（不带原始
/// 路径/内容），记录层错误本身是可 `Copy` 的。
pub(super) fn clone_error(error: &Error) -> Error {
    match error {
        Error::Record(inner) => Error::Record(*inner),
        Error::Io(_) => Error::Io(io::Error::other("XEL: I/O 失败")),
        Error::Timeout => Error::Timeout,
    }
}
