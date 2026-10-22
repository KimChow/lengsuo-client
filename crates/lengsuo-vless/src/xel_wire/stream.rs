//! 把「已建立的字节流」包装成「xel 加密/分帧后的字节流」（`AsyncRead`/`AsyncWrite`）。
//!
//! 从 [`super`] 拆出以保持单文件 ≤400 行（软约束）。

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use tokio::{
    io::{duplex, split, AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    task::{spawn, JoinHandle},
    time::timeout,
};

use super::config::{Error, XelWireConfig, MAX_PLAINTEXT_PER_RECORD};
use super::pump::{clone_error, flatten, pump_reads, pump_writes, IO_DEADLINE};

/// 管道容量（一条记录的最大明文量的量级）。
const PIPE: usize = MAX_PLAINTEXT_PER_RECORD + 256;

/// XEL 记录层出站原语：把「已建立的字节流」包装成「xel 加密/分帧后的字节流」。
///
/// 结构照搬 [`crate::reality_link::RealityStream`] 的既有做法：记录层两个方向各
/// 起一个后台任务，在「底层传输」与「内存管道（`tokio::io::duplex`）」之间搬运
/// 记录；调用方拿到的是管道的应用侧，因此 `AsyncRead`/`AsyncWrite` 就是普通
/// 字节流，可直接交给 [`crate::stream::send_request`] 等主链路函数。
pub struct XelStream {
    /// 应用侧（管道本端）：VLESS 头与载荷都从这里读写。
    app: DuplexStream,
    /// 读方向失败槽：读任务失败时把错误放进来，应用侧读到 EOF 前先取它
    /// （管道本身只能表达 EOF，不能表达失败原因）。用 `Arc` 是因为
    /// `io::Error` 不实现 `Clone`。
    read_error: Arc<Mutex<Option<Arc<Error>>>>,
    /// 写方向失败槽：写任务失败时把错误放进来，应用侧写入前先取它。
    write_error: Arc<Mutex<Option<Arc<Error>>>>,
    /// 读任务：传输 → 管道。
    reader_task: Option<JoinHandle<Result<(), Error>>>,
    /// 写任务：管道 → 传输。
    writer_task: Option<JoinHandle<Result<(), Error>>>,
    /// 写任务的结果（`shutdown()` 先等过写任务时存在这里，`close()` 取用）。
    writer_result: Option<Result<(), Error>>,
}

impl XelStream {
    /// 用已建立的传输（通常是已握好 TLS 的字节流）构造 XEL 记录层字节流。
    pub fn new<T>(transport: T, config: XelWireConfig) -> Result<Self, Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, mut receiver) = config.split()?;
        let (read_half, write_half) = split(transport);
        let (app, inner) = duplex(PIPE);
        let (inner_read, inner_write) = split(inner);
        let read_error = Arc::new(Mutex::new(None));
        let sink_error = Arc::clone(&read_error);
        let reader_task = spawn(async move {
            // 失败槽必须在**管道写端关闭之前**填好：否则应用侧可能先看到
            // 一个「干净的 EOF」而误以为流是正常结束的（fail-closed 被绕过）。
            // 因此写端由本闭包持有，`pump_reads` 只借用它。
            let mut sink = inner_write;
            let outcome = pump_reads(&mut receiver, read_half, &mut sink).await;
            if let Err(error) = &outcome {
                // 失败原因只放进槽里（不写进管道字节流），应用侧读到时取出。
                if let Ok(mut slot) = sink_error.lock() {
                    *slot = Some(Arc::new(clone_error(error)));
                }
            }
            // 无论成功还是失败都关闭管道写半：`tokio::io::split` 出来的半边
            // drop **不会**关闭管道（底层 `Arc` 还活着），不显式 shutdown 的话
            // 应用侧会永远等在一个「不会到来的 EOF」上。
            let _ = sink.shutdown().await;
            outcome
        });
        let write_error = Arc::new(Mutex::new(None));
        let sink_error = Arc::clone(&write_error);
        let writer_task = spawn(async move {
            let mut source = inner_read;
            let outcome = pump_writes(&mut sender, &mut source, write_half).await;
            if let Err(error) = &outcome {
                // 写方向失败同样要让应用侧看见（否则应用侧会写进一个没人读的
                // 管道，直到管道满才挂死）。
                if let Ok(mut slot) = sink_error.lock() {
                    *slot = Some(Arc::new(clone_error(error)));
                }
            }
            outcome
        });
        Ok(Self {
            app,
            read_error,
            write_error,
            reader_task: Some(reader_task),
            writer_task: Some(writer_task),
            writer_result: None,
        })
    }

    /// 关闭写方向（应用侧 → 传输的写任务随之结束），返回前等写任务收尾。
    ///
    /// 写任务的失败**不在这里**报错（写方向的失败通常在读取方向失败之后才被
    /// 观察到），由 [`XelStream::close`] 统一报。
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.app.shutdown().await?;
        self.join_writer().await;
        Ok(())
    }

    /// 等写任务收尾并把结果存进 `writer_result`（只等一次，避免重复 poll）。
    async fn join_writer(&mut self) {
        if let Some(task) = self.writer_task.take() {
            self.writer_result = Some(flatten(task.await));
        }
    }

    /// 收尾：关闭写方向并等两个后台任务结束。
    ///
    /// 读取方向在传输 EOF 时做截断检查（残字节 ⇒ 失败），任何一方向失败都原样
    /// 返回（fail-closed 的可见出口）；读任务在截止时间内未结束则中止它。
    pub async fn close(mut self) -> Result<(), Error> {
        let _ = self.app.shutdown().await;
        self.join_writer().await;
        let writer = self.writer_result.take();
        let mut reader_task = self.reader_task.take();
        let reader = match reader_task.as_mut() {
            Some(task) => match timeout(IO_DEADLINE, &mut *task).await {
                Ok(joined) => flatten(joined),
                Err(_) => {
                    task.abort();
                    Err(Error::Timeout)
                }
            },
            None => Ok(()),
        };
        // 先报读取方向（对端数据的真实性校验在这里），再报写入方向。
        reader?;
        writer.unwrap_or(Ok(()))?;
        Ok(())
    }
}

impl std::fmt::Debug for XelStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XelStream").finish_non_exhaustive()
    }
}

impl Drop for XelStream {
    fn drop(&mut self) {
        if let Some(task) = self.reader_task.take() {
            task.abort();
        }
        if let Some(task) = self.writer_task.take() {
            task.abort();
        }
    }
}

impl AsyncRead for XelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 先把管道里**已认证的明文**交给应用侧（记录层失败可能发生在同一批
        // 字节的后半段；前半段的明文是有效的，不该被丢弃）。
        // 三态：None = 管道读侧仍 pending（等更多数据）；
        // Some(Ok(())) = 本轮读到数据；错误直接向上抛（不吞）。
        let before = buf.filled().len();
        let read: Option<io::Result<()>> = match Pin::new(&mut self.app).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => Some(Ok(())),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => None,
        };
        // 本轮**没有交付任何字节**（管道 EOF 或 pending）且读方向已失败 ⇒ 报出
        // 失败原因。
        //
        // 这一步是 fail-closed 的关键：管道本身只能表达 EOF，读任务失败时会把
        // 失败原因放进 `read_error` 槽并关闭管道写端。若这里不把失败报出来，
        // 应用侧读到的是**干净的 EOF**——「错钥/篡改/截断的流」会被误读成
        // 「对端正常结束」（静默降级）。只有 [`XelStream::close`] 会报出该失败，
        // 而只读不收尾的调用方根本不会发现。
        //
        // 交付了字节的那一轮**不**报：那些明文已经过认证，仍然有效；失败会在
        // 下一轮（管道 EOF 时）报出。
        if buf.filled().len() == before {
            let failure = match self.read_error.lock() {
                Ok(slot) => slot.as_ref().cloned(),
                Err(_) => None,
            };
            if let Some(error) = failure {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                )));
            }
        }
        match read {
            Some(result) => Poll::Ready(result),
            // 管道侧 pending：本层没有更多数据可给，但**读方向可能已有失败**
            // （上面已检查并返回）。这里返回 Pending 让调用方等管道唤醒。
            None => Poll::Pending,
        }
    }
}

impl AsyncWrite for XelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 写方向失败必须让应用侧看见（否则应用侧会一直写进一个没人读的管道）。
        if let Ok(slot) = self.write_error.lock() {
            if let Some(error) = slot.as_ref() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                )));
            }
        }
        Pin::new(&mut self.app).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.app).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.app).poll_shutdown(cx)
    }
}
