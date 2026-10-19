//! 会话读写句柄：读与写各有一把异步互斥量，供帧循环与各回程任务共用。
//!
//! 参考实现里读循环（`recvLoop`）与写（`connLock` 保护的 `conn.Write`）是分开的两条
//! 路径，读写互不阻塞。本实现保持同样语义：**读锁只在一次 `read` 期间持有，写锁只在
//! 一次写出期间持有**。两者必须是独立的锁——若共用一个锁，帧循环阻塞在
//! “读下一帧”时会永远占住锁，回程任务就再也写不出 PUSH（自死锁）。
//!
//! 写出失败一律向上传播，由调用方关闭会话（fail-closed）。
use super::writer::FrameWriter;
use crate::frame::{Command, Frame};
use crate::padding::PaddingScheme;
use crate::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

/// 可克隆的会话句柄。克隆之间共享同一对读写锁、同一份 padding 计数。
#[derive(Clone)]
pub struct Sink {
    reader: Arc<Mutex<Box<dyn ErasedRead>>>,
    writer: Arc<Mutex<WriterState>>,
    wait: Duration,
}

/// 写侧状态：`FrameWriter` 与当前方案（方案变更时两者一起更新）。
struct WriterState {
    writer: Box<dyn ErasedWrite>,
    padding: PaddingScheme,
}

/// 只保留「按帧读取」这一能力。
trait ErasedRead: Send {
    fn read<'a>(&'a mut self, limit: u16, wait: Duration) -> Boxed<'a, Frame>;
}

/// 只保留写出能力。
trait ErasedWrite: Send {
    fn control_data<'a>(
        &'a mut self,
        command: Command,
        stream_id: u32,
        data: &'a [u8],
    ) -> Boxed<'a, ()>;
    fn data<'a>(&'a mut self, stream_id: u32, data: &'a [u8]) -> Boxed<'a, usize>;
    fn set_padding(&mut self, scheme: PaddingScheme);
}

type Boxed<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, Error>> + Send + 'a>>;

impl<R: AsyncRead + Unpin + Send> ErasedRead for R {
    fn read<'a>(&'a mut self, limit: u16, wait: Duration) -> Boxed<'a, Frame> {
        Box::pin(Frame::read(self, limit, wait))
    }
}

impl<W: AsyncWrite + Unpin + Send> ErasedWrite for FrameWriter<W> {
    fn control_data<'a>(
        &'a mut self,
        command: Command,
        stream_id: u32,
        data: &'a [u8],
    ) -> Boxed<'a, ()> {
        Box::pin(FrameWriter::control_data(self, command, stream_id, data))
    }
    fn data<'a>(&'a mut self, stream_id: u32, data: &'a [u8]) -> Boxed<'a, usize> {
        Box::pin(FrameWriter::data(self, stream_id, data))
    }
    fn set_padding(&mut self, scheme: PaddingScheme) {
        FrameWriter::set_padding(self, scheme)
    }
}

impl Sink {
    /// 由读半与写半构造；读锁与写锁相互独立（见模块文档）。
    pub fn new<R, W>(reader: R, writer: W, padding: PaddingScheme, wait: Duration) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            reader: Arc::new(Mutex::new(Box::new(reader))),
            writer: Arc::new(Mutex::new(WriterState {
                writer: Box::new(FrameWriter::new(writer, padding.clone())),
                padding,
            })),
            wait,
        }
    }

    /// 读一帧；仅在本调用期间持有读锁。
    pub async fn read(&self, limit: u16) -> Result<Frame, Error> {
        let mut guard = self.reader.lock().await;
        guard.read(limit, self.wait).await
    }

    /// 当前 padding 方案。
    pub async fn padding(&self) -> PaddingScheme {
        self.writer.lock().await.padding.clone()
    }

    pub async fn set_padding(&self, scheme: PaddingScheme) {
        let mut guard = self.writer.lock().await;
        guard.padding = scheme.clone();
        guard.writer.set_padding(scheme);
    }

    /// 空载荷控制帧。
    pub async fn control(&self, command: Command, stream_id: u32) -> Result<(), Error> {
        self.control_data(command, stream_id, &[]).await
    }

    /// 带载荷控制帧（padding 写出策略在 `FrameWriter::conn_write`）。
    pub async fn control_data(
        &self,
        command: Command,
        stream_id: u32,
        data: &[u8],
    ) -> Result<(), Error> {
        let mut guard = self.writer.lock().await;
        guard.writer.control_data(command, stream_id, data).await
    }

    /// 数据帧；返回交付给目标的载荷字节数（参考语义）。
    pub async fn data(&self, stream_id: u32, data: &[u8]) -> Result<usize, Error> {
        let mut guard = self.writer.lock().await;
        guard.writer.data(stream_id, data).await
    }
}
