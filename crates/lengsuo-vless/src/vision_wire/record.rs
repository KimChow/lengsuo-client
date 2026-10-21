//! VLESS Vision **记录层**（AEAD）流包装器：把承载流变成「AEAD 记录加密后」的
//! 字节流。
//!
//! 对应参考 `proxy/vless/encryption/common.go` 的 `CommonConn.Write` /
//! `CommonConn.Read`。加密与分帧**全部**由既有 [`crate::vision::record`] 完成，
//! 本文件不含第二套 AEAD 逻辑。
//!
//! 参考基线：Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::vision::record::{RecordReader, RecordWriter};

use super::{RecordConfig, VisionWireError, WireOutbox, READ_CHUNK};

/// VLESS Vision 记录层（AEAD）流。
///
/// - 写：明文 → [`RecordWriter::seal`]（参考 `CommonConn.Write`：按 8192 分块、
///   5 字节头作 AAD）→ 承载流。
/// - 读：承载流 → [`RecordReader::push`] + [`RecordReader::next_plaintext`]
///   （参考 `CommonConn.Read`：重组整条记录后解封）→ 明文。
///
/// 认证失败 / 头非法 / 截断 ⇒ 立即返回错误（既有 [`crate::vision::record`] 的
/// fail-closed 语义），不回退明文。
pub struct RecordStream<S> {
    inner: S,
    writer: RecordWriter,
    reader: RecordReader,
    outbox: WireOutbox,
    plaintext: Vec<u8>,
    /// 承载流是否已 EOF。
    eof: bool,
}

impl<S> fmt::Debug for RecordStream<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordStream")
            .field("inner", &"<stream>")
            .field("plaintext_len", &self.plaintext.len())
            .field("eof", &self.eof)
            .finish()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> RecordStream<S> {
    /// 建立记录层流。上下文或密钥材料为空 ⇒ **fail-closed**，构造失败。
    pub fn new(inner: S, config: &RecordConfig) -> Result<Self, VisionWireError> {
        if config.ctx.is_empty() {
            return Err(VisionWireError::InvalidConfig("记录层派生上下文不能为空"));
        }
        if config.key.is_empty() {
            return Err(VisionWireError::InvalidConfig("记录层密钥材料不能为空"));
        }
        Ok(Self {
            inner,
            writer: RecordWriter::new(&config.ctx, &config.key, config.cipher),
            reader: RecordReader::new(&config.ctx, &config.key, config.cipher),
            outbox: WireOutbox::new(),
            plaintext: Vec::new(),
            eof: false,
        })
    }

    /// 取回承载流。
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RecordStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        loop {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if !me.plaintext.is_empty() {
                let take = me.plaintext.len().min(buf.remaining());
                buf.put_slice(&me.plaintext[..take]);
                me.plaintext.drain(..take);
                return Poll::Ready(Ok(()));
            }
            if me.eof {
                return Poll::Ready(Ok(()));
            }
            let mut chunk = [0u8; READ_CHUNK];
            let mut inner_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut me.inner).poll_read(cx, &mut inner_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let filled = inner_buf.filled();
                    if filled.is_empty() {
                        me.eof = true;
                        // 流结束检查：残字节即截断 ⇒ fail-closed。
                        if let Err(error) = me.reader.finish() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                format!("vision 记录层收尾失败：{error}"),
                            )));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    if let Err(error) = me.reader.push(filled) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("vision 记录层失败：{error}"),
                        )));
                    }
                    loop {
                        match me.reader.next_plaintext() {
                            Ok(Some(plain)) => me.plaintext.extend_from_slice(&plain),
                            Ok(None) => break,
                            Err(error) => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("vision 记录层失败：{error}"),
                                )))
                            }
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RecordStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !me.outbox.is_idle() {
            // 上一轮还没写完（上一轮 `poll_write` 返回过 `Pending`）：tokio 契约要求
            // 调用方会用**同一个** buffer 回来，因此本轮不编码新数据，只把上一轮
            // 的剩余线上字节写完。
            return match me.outbox.poll_drain(&mut me.inner, cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => Poll::Ready(Ok(me.outbox.report())),
            };
        }
        // 既有记录层原语：参考 `CommonConn.Write`。
        let record = me.writer.seal(buf).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("vision 记录层失败：{error}"),
            )
        })?;
        me.outbox.begin(Some(buf.len()));
        me.outbox.push_raw(&record);
        match me.outbox.poll_drain(&mut me.inner, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(me.outbox.report())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        if !me.outbox.is_idle() {
            match me.outbox.poll_drain(&mut me.inner, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                // 上一轮 `poll_write` 若返回过 `Pending`，调用方还会带着同一个
                // buffer 回来要字节数 ⇒ 这里**不**清 `reported`。
                Poll::Ready(Ok(())) => {}
            }
        }
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        match me.outbox.poll_drain(&mut me.inner, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_shutdown(cx),
        }
    }
}
