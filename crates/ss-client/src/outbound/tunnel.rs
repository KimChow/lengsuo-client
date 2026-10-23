//! 已建连的出口隧道：`TcpReader` / `TcpWriter` 的双向字节流适配。
//!
//! 收方向：首次认证 chunk 作为 `first_response` 暴露，同时按顺序先交给
//! `AsyncRead`；之后逐个 chunk 交付，绝不把未认证字节交给上层。
//!
//! 发方向：`AsyncWrite::poll_write` 把调用方的字节拷进一次 `TcpWriter::send`
//! （每次 write 一个 chunk 序列，salt 只在首次上线）。因为 `send` / `shutdown`
//! 是 async 且借用 writer，这里把 writer **移动**进 `Box::pin` 的 future，
//! pending 期间字段为 `None`，完成后归还——避免自引用。
//!
//! 故意不实现 `Debug`：内部持有 `TcpReader` / `TcpWriter`（主密钥）。

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use lengsuo_shadowsocks::{TcpError, TcpReader, TcpWriter};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

type Writer = TcpWriter<OwnedWriteHalf>;
type Reader = TcpReader<OwnedReadHalf>;

/// `send` 与 `shutdown` 的 future 输出相同：把 writer 归还并带上结果。
type WriteFut = Pin<Box<dyn Future<Output = (Writer, Result<(), TcpError>)>>>;
type ReadFut = Pin<Box<dyn Future<Output = (Reader, Result<Option<Vec<u8>>, TcpError>)>>>;

pub struct Tunnel {
    reader: Option<Reader>,
    writer: Option<Writer>,
    /// 回程首个已认证 chunk（服务端数据，不是握手标记）。
    first_response: Vec<u8>,
    /// 尚未交付给 `AsyncRead` 的明文字节（初始为 `first_response` 的副本）。
    read_buf: Vec<u8>,
    read_pos: usize,
    eof: bool,
    read_fut: Option<ReadFut>,
    /// `(future, 本次写入字节数, 是否 shutdown)`。
    write_fut: Option<(WriteFut, usize, bool)>,
}

impl Tunnel {
    pub(crate) fn new(reader: Reader, writer: Writer, first_response: Vec<u8>) -> Self {
        Self {
            reader: Some(reader),
            writer: Some(writer),
            read_buf: first_response.clone(),
            first_response,
            read_pos: 0,
            eof: false,
            read_fut: None,
            write_fut: None,
        }
    }

    /// 回程方向解出的首个已认证 chunk 明文。
    #[must_use]
    pub fn first_response(&self) -> &[u8] {
        &self.first_response
    }
}

/// 底层协议错误 → `io::Error`。`Io` 原样透传，其余保留 Display 文本。
fn to_io(err: TcpError) -> io::Error {
    match err {
        TcpError::Io(io) => io,
        other => io::Error::other(other.to_string()),
    }
}

impl AsyncRead for Tunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 先交付已缓冲的明文字节（首个回程 chunk 或上一次多读的余量）。
            if this.read_pos < this.read_buf.len() {
                let n = buf.remaining().min(this.read_buf.len() - this.read_pos);
                buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
                this.read_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                // 0 字节即 EOF。
                return Poll::Ready(Ok(()));
            }
            if this.read_fut.is_none() {
                let Some(reader) = this.reader.take() else {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                };
                this.read_fut = Some(Box::pin(async move {
                    let mut reader = reader;
                    let res = reader.recv().await;
                    (reader, res)
                }));
            }
            let poll_res = {
                let fut = this.read_fut.as_mut().expect("just created");
                fut.as_mut().poll(cx)
            };
            match poll_res {
                Poll::Pending => return Poll::Pending,
                Poll::Ready((reader, res)) => {
                    this.read_fut = None;
                    this.reader = Some(reader);
                    match res {
                        Ok(Some(chunk)) => {
                            this.read_buf = chunk;
                            this.read_pos = 0;
                        }
                        Ok(None) => {
                            this.eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        Err(err) => {
                            this.eof = true;
                            return Poll::Ready(Err(to_io(err)));
                        }
                    }
                }
            }
        }
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some((mut fut, len, is_shutdown)) = this.write_fut.take() {
            match fut.as_mut().poll(cx) {
                Poll::Pending => {
                    this.write_fut = Some((fut, len, is_shutdown));
                    return Poll::Pending;
                }
                Poll::Ready((writer, res)) => {
                    this.writer = Some(writer);
                    if is_shutdown {
                        return Poll::Ready(Err(closed()));
                    }
                    return Poll::Ready(res.map(|()| len).map_err(to_io));
                }
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(writer) = this.writer.take() else {
            return Poll::Ready(Err(closed()));
        };
        let data = buf.to_vec();
        let len = data.len();
        let mut fut: WriteFut = Box::pin(async move {
            let mut writer = writer;
            let res = writer.send(&data).await;
            (writer, res)
        });
        match fut.as_mut().poll(cx) {
            Poll::Pending => {
                this.write_fut = Some((fut, len, false));
                Poll::Pending
            }
            Poll::Ready((writer, res)) => {
                this.writer = Some(writer);
                Poll::Ready(res.map(|()| len).map_err(to_io))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // `TcpWriter::send` 在返回前已 flush；若有 pending 的写入，先让它完成。
        if let Some((mut fut, len, is_shutdown)) = this.write_fut.take() {
            match fut.as_mut().poll(cx) {
                Poll::Pending => {
                    this.write_fut = Some((fut, len, is_shutdown));
                    return Poll::Pending;
                }
                Poll::Ready((writer, res)) => {
                    this.writer = Some(writer);
                    if let Err(err) = res {
                        return Poll::Ready(Err(to_io(err)));
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some((mut fut, len, is_shutdown)) = this.write_fut.take() {
                match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        this.write_fut = Some((fut, len, is_shutdown));
                        return Poll::Pending;
                    }
                    Poll::Ready((writer, res)) => {
                        this.writer = Some(writer);
                        if let Err(err) = res {
                            return Poll::Ready(Err(to_io(err)));
                        }
                        if is_shutdown {
                            return Poll::Ready(Ok(()));
                        }
                        // 刚完成一次普通写入，继续发起 shutdown。
                    }
                }
            }
            let Some(writer) = this.writer.take() else {
                // 已 shutdown（或 writer 已被半关闭）。
                return Poll::Ready(Ok(()));
            };
            let fut: WriteFut = Box::pin(async move {
                let mut writer = writer;
                let res = writer.shutdown().await;
                (writer, res)
            });
            this.write_fut = Some((fut, 0, true));
        }
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "tunnel writer is closed")
}
