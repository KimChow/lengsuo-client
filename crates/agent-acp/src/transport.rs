//! P2 传输抽象：帧汇（写侧）/ 帧源（读侧）与拆除钩子。
//!
//! 设计结论：保持**同步线程模型**（std::thread + std::sync::mpsc），不引入异步
//! 运行时——P1 是零 IO 纯类型层，ACP 单连接请求-响应模式没有高并发 IO 需求，
//! thread-per-connection 与现状一致、可离线测试、零新依赖。
//!
//! 传输层只搬运帧字节并完成顶层归类（[`TopLevel`]，P1 纯函数），不承载业务
//! 语义；业务路由在 [`crate::client`]。两种实现：
//! - [`crate::stdio`]：真实子进程 stdio（spawn + reader 线程 + [`crate::LineDecoder`]）；
//! - [`mock_transport`]：内存通道注入，测试不 spawn 进程。

use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use crate::codec::decode_frame;
use crate::control::TopLevel;
use crate::error::Error;

/// 帧源吐出的一次事件。
#[derive(Debug)]
pub enum SourceEvent {
    /// 一条成功归类的帧。
    Frame(TopLevel),
    /// 帧体畸形但字节流仍对齐（如 JSON 非法）：忽略并计数，连接可继续。
    BadFrame {
        /// 失败原因（仅供观测）。
        reason: String,
    },
    /// 连接终止。`reason` 为 `None` 表示干净收尾；`Some` 表示 fail-closed
    /// 下毒（解码器超长、流截断、读 IO 错误），调用方必须丢弃这条连接。
    Closed {
        /// 终止原因。
        reason: Option<String>,
    },
}

/// [`FrameSource::next_event`] 的结果。
#[derive(Debug)]
pub enum SourcePull {
    /// 超时内没有事件。
    Timeout,
    /// 取到一个事件。
    Event(SourceEvent),
}

/// 写侧：把已编码的一帧（含行尾 `\n`）推给对端。
pub trait FrameSink: Send {
    /// 写入一帧并 flush。失败即传输错误（写侧通常已不可恢复）。
    ///
    /// # Errors
    /// [`Error::Transport`]：对端管道断开或写入失败。
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), Error>;

    /// 尽力关闭写侧（如释放子进程 stdin，让对端读到 EOF）。幂等。
    fn close(&mut self) {}
}

/// 读侧：阻塞取下一个帧事件，带超时（便于调用方轮询停止标志）。
pub trait FrameSource: Send {
    /// 在 `timeout` 内取下一个事件；取不到返回 [`SourcePull::Timeout`]。
    fn next_event(&mut self, timeout: Duration) -> SourcePull;
}

/// 一次性拆除钩子：[`Teardown::run`] 或 Drop 时执行一次（stdio 形态里
/// 负责关 stdin、回收 reader/writer 线程、kill+reap 子进程）。
///
/// 未交给 [`crate::client::Client`] 就丢弃的 [`Transport`]，其内嵌 Teardown
/// 在 drop 时自动执行——**任何路径都不留孤儿进程**。
pub struct Teardown {
    hook: Option<Box<dyn FnOnce() + Send>>,
}

impl std::fmt::Debug for Teardown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Teardown")
            .field("armed", &self.hook.is_some())
            .finish()
    }
}

impl Teardown {
    /// 空钩子（mock 传输用）。
    #[must_use]
    pub fn none() -> Self {
        Self { hook: None }
    }

    /// 包装一个一次性动作。
    pub fn new(f: impl FnOnce() + Send + 'static) -> Self {
        Self {
            hook: Some(Box::new(f)),
        }
    }

    /// 立即执行（已执行则空操作）。幂等。
    pub fn run(&mut self) {
        if let Some(hook) = self.hook.take() {
            hook();
        }
    }
}

impl Drop for Teardown {
    fn drop(&mut self) {
        self.run();
    }
}

/// 一条已建立的 ACP 连接：帧汇 + 帧源 + 拆除钩子。
pub struct Transport {
    /// 写侧。
    pub sink: Box<dyn FrameSink>,
    /// 读侧。
    pub source: Box<dyn FrameSource>,
    /// 拆除钩子。
    pub teardown: Teardown,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport")
            .field("sink", &"<dyn FrameSink>")
            .field("source", &"<dyn FrameSource>")
            .field("teardown", &self.teardown)
            .finish()
    }
}

impl Transport {
    /// 用自定义汇/源组装传输（无拆除钩子）。
    #[must_use]
    pub fn new(sink: Box<dyn FrameSink>, source: Box<dyn FrameSource>) -> Self {
        Self {
            sink,
            source,
            teardown: Teardown::none(),
        }
    }

    /// 附带拆除钩子的组装。
    #[must_use]
    pub fn with_teardown(
        sink: Box<dyn FrameSink>,
        source: Box<dyn FrameSource>,
        teardown: Teardown,
    ) -> Self {
        Self {
            sink,
            source,
            teardown,
        }
    }
}

/// 通道帧汇：把帧字节转投 [`MockPeer`] 的出口接收端。
struct ChannelSink {
    tx: Option<Sender<Vec<u8>>>,
}

impl FrameSink for ChannelSink {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), Error> {
        let Some(tx) = &self.tx else {
            return Err(Error::Transport {
                reason: "mock 帧汇已关闭".into(),
            });
        };
        tx.send(frame.to_vec()).map_err(|_| Error::Transport {
            reason: "mock 出口接收端已释放".into(),
        })
    }

    fn close(&mut self) {
        self.tx = None;
    }
}

/// 通道帧源：直接接收 [`SourceEvent`]（由 [`MockPeer`] 或 reader 线程注入）。
struct ChannelSource {
    rx: Receiver<SourceEvent>,
}

impl FrameSource for ChannelSource {
    fn next_event(&mut self, timeout: Duration) -> SourcePull {
        match self.rx.recv_timeout(timeout) {
            Ok(ev) => SourcePull::Event(ev),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => SourcePull::Timeout,
            // 注入端释放：视为干净收尾（测试显式下毒走 feed_event(Closed)）。
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                SourcePull::Event(SourceEvent::Closed { reason: None })
            }
        }
    }
}

/// 帧事件通道：`(帧源, 注入端)`。stdio reader 线程与 mock 注入共用此汇合点。
#[must_use]
pub fn event_channel() -> (Box<dyn FrameSource>, Sender<SourceEvent>) {
    let (tx, rx) = std::sync::mpsc::channel::<SourceEvent>();
    (Box::new(ChannelSource { rx }), tx)
}

/// 内存 mock 对端：注入入站帧、收集出站帧。
#[derive(Debug)]
pub struct MockPeer {
    incoming: Sender<SourceEvent>,
    /// 出站帧字节接收端（Client 写出的每一帧都会出现在这里）。
    pub outgoing: Receiver<Vec<u8>>,
}

impl MockPeer {
    /// 注入一条完整帧体（行内容）：走 P1 [`crate::codec::decode_frame`] 真实
    /// 归类，畸形 JSON 自动转为 [`SourceEvent::BadFrame`]。
    pub fn feed_line(&self, body: &[u8]) {
        let ev = match decode_frame(body) {
            Ok(top) => SourceEvent::Frame(top),
            Err(e) => SourceEvent::BadFrame {
                reason: e.to_string(),
            },
        };
        let _ = self.incoming.send(ev);
    }

    /// 注入一条 JSON 值（自动序列化为一帧）。
    ///
    /// # Panics
    /// 传入值无法序列化时 panic（仅测试装配用）。
    pub fn feed_json(&self, value: &serde_json::Value) {
        let body = serde_json::to_vec(value).expect("mock 帧序列化");
        self.feed_line(&body);
    }

    /// 直接注入任意源事件（如下毒收尾 [`SourceEvent::Closed`]）。
    pub fn feed_event(&self, ev: SourceEvent) {
        let _ = self.incoming.send(ev);
    }

    /// 收取一帧出站字节（超时即 None）。
    #[must_use]
    pub fn recv_outgoing(&self, timeout: Duration) -> Option<Vec<u8>> {
        self.outgoing.recv_timeout(timeout).ok()
    }
}

/// 新建内存 mock 传输：`(Transport, MockPeer)`，不 spawn 任何进程。
#[must_use]
pub fn mock_transport() -> (Transport, MockPeer) {
    let (frame_tx, frame_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let (source, incoming) = event_channel();
    let transport = Transport::new(Box::new(ChannelSink { tx: Some(frame_tx) }), source);
    let peer = MockPeer {
        incoming,
        outgoing: frame_rx,
    };
    (transport, peer)
}
