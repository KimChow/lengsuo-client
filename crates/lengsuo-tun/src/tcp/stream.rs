//! `AsyncRead + AsyncWrite` 流抽象：把用户态 TCP 栈的单条连接暴露成 tokio 流。
//!
//! 分工（对应参考实现 `app/dispatcher/default.go` 里 Dispatch 返回的 inbound/outbound
//! 两个 Link）：
//! - **读端**：[`TcpStream`] 从 [`StreamSink`] 投递的 `Deliver` 载荷里读，字节序即状态机
//!   交付顺序（状态机已做按序重排，本层不重复排序）。
//! - **写端**：[`TcpStream`] 写入的字节经 `mpsc` 交给 [`StreamSink`]，由驱动方取走并通过
//!   `TcpListener::send` 编成段发出——本层不构造 IP/TCP 头部。
//!
//! 载荷经 `mpsc` 通道传递，用 `Vec<u8>` + 读游标累积半包，避免每读一次都重新分配。
//! 一切等待都不在本层做超时：超时由调用方（驱动循环 / 用例）用
//! `tokio::time::timeout` 包裹，符合本卡「所有异步等待带超时」的要求。
//!
//! 明确不做：不做拥塞控制、不做分段（`send` 一段到底，分段由上层按 MTU 决定）、
//! 不做重传、不持有定时器。逐条差异见文件末尾「偏离清单」。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// 单条流的内部通道容量（消息条数）：读端待交付消息与写端待发送消息各一个队列。
const CHANNEL_CAPACITY: usize = 16;

/// 读端单次交付字节数的上限：超过则拆成多条消息，避免单条消息过大。
const DELIVER_CHUNK: usize = 64 * 1024;

/// 驱动方持有的流句柄：投递读侧载荷、观察写侧请求、感知半关闭。
///
/// 与 [`TcpStream`] 成对存在，由 [`StreamPair::new`] 一起创建。
pub struct StreamSink {
    /// 读侧投递端；`finish_read` 时取走并 drop，读端据此得到 EOF。
    deliver: Option<mpsc::Sender<Vec<u8>>>,
    egress: mpsc::Receiver<Vec<u8>>,
    /// 上层是否已关闭写端（`shutdown(Write)` 或 drop）。
    write_closed: bool,
}

/// [`TcpStream`] 与驱动侧 [`StreamSink`] 的成对句柄。
pub struct StreamPair {
    stream: TcpStream,
    sink: StreamSink,
}

/// 上层可读可写的单条连接流。
pub struct TcpStream {
    deliver: mpsc::Receiver<Vec<u8>>,
    /// 写出口发送端；`shutdown` 时取走并 drop，驱动侧据此感知写端结束。
    egress: Option<mpsc::Sender<Vec<u8>>>,
    /// 已从队列取出但未读完的剩余字节（读游标即队首，读完立即 drain）。
    pending: Vec<u8>,
    /// 读侧是否已收到 EOF（对端 FIN 或驱动方收尾）。
    read_eof: bool,
    /// 写侧是否已调用过 `shutdown`。
    write_shutdown: bool,
}

impl StreamPair {
    /// 建立一对流句柄。二者共享两个 `mpsc` 通道：读端交付、写端出口。
    pub fn new() -> Self {
        let (deliver_tx, deliver_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (egress_tx, egress_rx) = mpsc::channel(CHANNEL_CAPACITY);
        Self {
            stream: TcpStream {
                deliver: deliver_rx,
                egress: Some(egress_tx),
                pending: Vec::new(),
                read_eof: false,
                write_shutdown: false,
            },
            sink: StreamSink {
                deliver: Some(deliver_tx),
                egress: egress_rx,
                write_closed: false,
            },
        }
    }

    /// 拆成（上层流，驱动侧句柄）。上层持有流读写；驱动方持有句柄收发。
    pub fn split(self) -> (TcpStream, StreamSink) {
        (self.stream, self.sink)
    }
}

impl Default for StreamPair {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamSink {
    /// 投递一段已按序交付的应用载荷。读端按投递顺序读出。
    ///
    /// 队列满时返回 `false`，调用方应稍后重投（本层不阻塞、不丢弃已交付字节——
    /// 状态机已把这段载荷移出接收窗口，丢弃即数据丢失）。
    pub fn deliver(&mut self, payload: &[u8]) -> bool {
        if payload.is_empty() {
            return true;
        }
        let Some(deliver) = self.deliver.as_ref() else {
            return false;
        };
        let mut rest = payload;
        while !rest.is_empty() {
            let take = rest.len().min(DELIVER_CHUNK);
            if deliver.try_send(rest[..take].to_vec()).is_err() {
                return false;
            }
            rest = &rest[take..];
        }
        true
    }

    /// 通知读端 EOF（对端 FIN 或连接终结）：取走并 drop 投递端，读端得到 0 字节。
    pub fn finish_read(&mut self) {
        self.deliver = None;
    }

    /// 取走上层已写入、等待编成段发送的载荷；无待发数据时返回 `None`。
    pub fn take_egress(&mut self) -> Option<Vec<u8>> {
        match self.egress.try_recv() {
            Ok(bytes) => Some(bytes),
            Err(mpsc::error::TryRecvError::Empty) => None,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                // 流已被 drop：视为写端关闭。
                self.write_closed = true;
                None
            }
        }
    }

    /// 上层是否已关闭写端（`shutdown(Write)` 或 drop 流）。
    pub fn write_closed(&self) -> bool {
        self.write_closed || self.egress.is_closed()
    }

    /// 读侧是否已收尾（`finish_read` 已调用）。
    pub fn read_closed(&self) -> bool {
        self.deliver.is_none()
    }
}

impl TcpStream {
    /// 对端是否已关闭写端（`read` 会在排空后返回 0）。
    pub fn peer_closed(&self) -> bool {
        self.read_eof
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 先排空已累积的字节。
        if !self.pending.is_empty() {
            let take = self.pending.len().min(buf.remaining());
            buf.put_slice(&self.pending[..take]);
            self.pending.drain(..take);
            return Poll::Ready(Ok(()));
        }
        if self.read_eof {
            // 读侧结束：交出 0 字节表示 EOF。
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.deliver).poll_recv(cx) {
            Poll::Ready(Some(bytes)) => {
                let take = bytes.len().min(buf.remaining());
                buf.put_slice(&bytes[..take]);
                if take < bytes.len() {
                    self.pending.extend_from_slice(&bytes[take..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.read_eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_shutdown {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "写端已关闭")));
        }
        let Some(egress) = self.egress.as_ref() else {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "写端已关闭")));
        };
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match egress.try_send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            // 通道满 / 驱动侧已断开：注册唤醒后返回 Pending，由驱动方取走数据后再写。
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "驱动侧已断开",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 载荷经通道异步发出，本层没有额外缓冲需要刷。
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write_shutdown = true;
        // 取走并 drop 发送端：驱动侧的 `take_egress`/`write_closed` 据此感知写端结束。
        self.egress = None;
        Poll::Ready(Ok(()))
    }
}

// ---- 与参考实现 / RFC 9293 的有意差异 ----
//
// 1. 本层不做分段：一次 `write` 交出一条消息，由驱动方决定是否按 MTU 切段后调用
//    `TcpListener::send`（`send` 本身也不分段）。
// 2. 本层不持有定时器、不做重传与超时：一切等待由调用方的 `tokio::time::timeout` 兜底。
// 3. 不做发送缓冲与流量控制：写端只按 `mpsc` 容量做背压，读端交付失败（队列满）由
//    驱动方重投；本层不丢弃已交付字节。
// 4. `poll_flush` 立即返回：载荷已交给通道，本层没有可刷的本地缓冲。
