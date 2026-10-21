//! WebSocket 帧层（RFC 6455）：`Frames<S>` 状态机与读写方向语义。
//!
//! 从 `ws/mod.rs` 拆出以满足单文件行数上限（软 400 / 硬 700）。
//! 方向由构造时的 `client` 决定；详见 `ws` 模块文档。
//!
//! 结构：本文件只保留对外的 `Frames<S>` 类型与它的 `AsyncRead`/`AsyncWrite`
//! 实现；**读侧**状态机（帧头 → 扩展长度 → 掩码键 → 载荷）在 `read.rs`，
//! **写侧**状态机（帧构造与分步写出）在 `write.rs`。两侧共享同一 `Frame`
//! 语义与 RFC 6455 常量（常量仍定义在 `ws` 模块内，不重复导出）。
//! `Connection`/`ServerConnection` 两个包装已拆到 `ws/mod.rs`。

mod read;
mod write;

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{OP_BINARY, OP_CLOSE};
use read::{poll_read_state, Frame, ReadState};
use write::{advance_write, encode_frame, WriteState};

/// WebSocket 帧层核心：一个把字节流包成 RFC 6455 帧的双向适配器。
///
/// 方向由 `masked` 决定：客户端**发出掩码帧、收到不掩码帧**；服务端**收到掩码
/// 帧、发出不掩码帧**。读侧的掩码键剥离与写侧的掩码施加都按该标志执行，
/// 与参考 `connection`（客户端）和 gorilla `Upgrader`（服务端）一致。
pub struct Frames<S> {
    inner: S,
    /// 本端是否为“客户端方向”（发掩码 / 收不掩码）。
    client: bool,
    /// 当前帧剩余未读载荷。
    frame: Vec<u8>,
    frame_pos: usize,
    /// 分片拼接缓冲（continuation 帧）。
    fragments: Vec<u8>,
    /// 已收到 `Close`：读侧到此为止（EOF），不再读底层。
    closed: bool,
    read_state: ReadState,
    write_state: WriteState,
}

impl<S> Frames<S> {
    pub(crate) fn new(inner: S, client: bool) -> Self {
        Self {
            inner,
            client,
            frame: Vec::new(),
            frame_pos: 0,
            fragments: Vec::new(),
            closed: false,
            read_state: ReadState::Header {
                got: [0u8; 2],
                filled: 0,
            },
            write_state: WriteState::Idle,
        }
    }

    /// 对端是否应当掩码：客户端读服务端（不掩码）；服务端读客户端（掩码）。
    fn expect_masked(&self) -> bool {
        !self.client
    }

    /// 本端写出的帧是否掩码：客户端掩码，服务端不掩码。
    fn write_masked(&self) -> bool {
        self.client
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Frames<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 1) 优先交付当前帧剩余载荷。
            if this.frame_pos < this.frame.len() {
                let take = (this.frame.len() - this.frame_pos).min(buf.remaining());
                buf.put_slice(&this.frame[this.frame_pos..this.frame_pos + take]);
                this.frame_pos += take;
                return Poll::Ready(Ok(()));
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            // 2) 推进读状态机。
            let expect_masked = this.expect_masked();
            match poll_read_state(&mut this.inner, &mut this.read_state, expect_masked, cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(frame) => match frame {
                    Frame::Data { fin, payload } => {
                        this.fragments.extend_from_slice(&payload);
                        if fin {
                            this.frame = std::mem::take(&mut this.fragments);
                            this.frame_pos = 0;
                        } // 未 fin：继续读下一分片（循环回状态机）。
                    }
                    Frame::Close => {
                        this.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    // Ping/Pong 不携带应用数据：忽略（参考默认读循环亦不把它们
                    // 交给上层）。服务端不会主动 Ping（heartbeat 默认关闭）。
                    Frame::Ping | Frame::Pong => {}
                },
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Frames<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if !matches!(this.write_state, WriteState::Idle) {
            match advance_write(&mut this.inner, &mut this.write_state, cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(user) => return Poll::Ready(Ok(user)),
            }
        }
        let masked = this.write_masked();
        this.write_state = encode_frame(OP_BINARY, data, masked);
        match advance_write(&mut this.inner, &mut this.write_state, cx)? {
            Poll::Pending => Poll::Pending,
            Poll::Ready(user) => Poll::Ready(Ok(user)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !matches!(this.write_state, WriteState::Idle) {
            match advance_write(&mut this.inner, &mut this.write_state, cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(_) => {}
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // 参考 `connection.Close`：先发 Close 帧，再关底层写侧。
        let this = self.get_mut();
        if !matches!(this.write_state, WriteState::Idle) {
            match advance_write(&mut this.inner, &mut this.write_state, cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(_) => {}
            }
        }
        let masked = this.write_masked();
        this.write_state = encode_frame(OP_CLOSE, &[], masked);
        match advance_write(&mut this.inner, &mut this.write_state, cx)? {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(_) => {}
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
