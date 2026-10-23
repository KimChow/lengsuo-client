//! VLESS **Mux 承载**接线：把库级 `lengsuo_vless::mux_wire` 原语接成 node 的
//! 产品级承载（`VlessStream::Mux`）。参考基线：Xray `d2758a023cd7…`。
//!
//! - 承载请求头：`proxy/vless/outbound/outbound.go:218-232`（目标 `v1.mux.cool`
//!   ⇒ `command = RequestCommandMux`）+ `proxy/vless/encoding/encoding.go:50-54`
//!   （`Mux` **不写地址段**）⇒ 线上 `00 | UUID | 00 | 03`。
//! - 会话与下行派发：`common/mux/client.go:290-310,369-400`（`sm.Allocate`、
//!   `fetchOutput` 的四个 `handleStatus*`）、`common/mux/writer.go`（帧）；
//!   策略 `app/proxyman/outbound/handler.go:138-139`。
//!
//! 帧生成、会话 ID 分配与会话生命周期**全部**由库级 `MuxWire` / `MuxSession`
//! 承担；下行派发由库级 `mux::worker::MuxClient` 承担；node 侧只做「字节流拆分
//! + 按会话派发」的编排。
//!
//! # 为什么读侧在 node 侧驱动（偏离 / 跨 crate 项）
//!
//! `MuxWire::next_inbound` 与 `MuxWire::open` **都**要 `&mut MuxWire`（参考的
//! `Dispatch` 与 `fetchOutput` 是两个 goroutine），而本仓的转发任务必须 `Send`
//! ⇒ `MuxWire` 独占读写两半边（`mux_wire/carrier.rs:56-72`）、外部拿不到读
//! 半边，`open` 与 `next_inbound` 无法并发；且它的内部超时
//! （`mux_wire/carrier.rs:138`）会在帧中途取消读 ⇒ 字节丢失、承载错位。
//!
//! ⇒ node 侧自己拆承载连接（`tokio::io::split`）：**写侧**交给库级 `MuxWire`
//! （`open` 分配 ID + 写 `New`；`MuxSession::write` 写 `Keep`；`close` 写 `End`），
//! **读侧**用同一批库原语（`mux::frame` 解帧 + `MuxClient` 派发）驱动。
//!
//! # 握手顺序（**不能**先等响应头）
//!
//! 参考把响应头滞留到首个 mux 帧才 flush（`common/buf/writer.go:165`）⇒
//! **先发帧，再在读循环里消费响应头**。完整偏离清单见本卡报告。

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use lengsuo_vless::header::{Command as VlessCommand, Request};
use lengsuo_vless::mux::frame::{decode_from_async, read_data_async, TargetNetwork};
use lengsuo_vless::mux::worker::{write_closing_end, Action, MuxClient, SessionState, Strategy};
use lengsuo_vless::mux::{MUX_COOL_ADDRESS, MUX_COOL_PORT};
use lengsuo_vless::mux_wire::{Error as MuxError, MuxSession, MuxWire};
use lengsuo_vless::stream::{receive_response_header, send_request};
use ss_core::target::TargetAddr;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex};

use crate::config::{NodeConfig, NodeMuxSettings};
use crate::outbound::DialError;

/// 承载连接上会话 I/O 的截止时间（参考的承载 I/O 无截止时间）。
pub const MUX_IO_DEADLINE: Duration = Duration::from_secs(30);

/// 帧字节队列（写侧唯一出口 ⇒ 帧不交错）。
type FrameQueue = mpsc::UnboundedSender<Vec<u8>>;

/// 下行派发状态：库级 `MuxClient`（会话表 + 参考的四个 `handleStatus*` 分支）
/// 与 node 的路由表（会话 ID → 收件箱）；读循环与开会话共用一把锁。
struct Dispatch {
    client: MuxClient,
    routes: HashMap<u16, mpsc::UnboundedSender<Delivery>>,
}

type Shared = Arc<Mutex<Dispatch>>;

enum Delivery {
    Data(Vec<u8>),
    Closed,
}

/// 写命令：业务数据（写 `Keep` 帧）/ 收尾（写 `End` 帧，参考 `Writer.Close`）。
enum WriteCmd {
    Data(Vec<u8>),
    Close,
}

/// Mux 是否启用（配置里有 `mux` 段即启用）。
#[must_use]
pub fn mux_enabled(config: &NodeConfig) -> bool {
    config.mux.is_some()
}

/// node 配置 → 参考 `ClientStrategy`（`app/proxyman/outbound/handler.go:138-139`）。
#[must_use]
pub fn strategy(mux: &NodeMuxSettings) -> Strategy {
    Strategy {
        max_concurrency: mux.concurrency,
        max_connection: mux.max_connections,
    }
}

/// 承载请求头：目标写 `v1.mux.cool`（参考 `common/mux/client.go:186-187`）；
/// `Mux` 命令**不写地址段**（`encoding.go:50-54`）⇒ 线上只有 `00 | UUID | 00 |
/// 03`；这里的 `target` 只是占位。
#[must_use]
pub fn carrier_request() -> Request {
    Request {
        command: VlessCommand::Mux,
        target: TargetAddr::Domain(MUX_COOL_ADDRESS.to_owned(), MUX_COOL_PORT),
    }
}

struct QueueWriter {
    tx: FrameQueue,
}

impl AsyncRead for QueueWriter {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for QueueWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.tx.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(broken_pipe("mux 帧队列已关闭"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// 承载连接：一条 mux 承载（可开多条逻辑会话）。
pub struct MuxCarrier {
    /// 库级承载：会话 ID 分配 + `New`/`Keep`/`End` 帧生成。
    wire: Arc<Mutex<MuxWire>>,
    dispatch: Shared,
}

/// 建立承载连接：写 VLESS `command=Mux` 请求头 → 拆读写两半 → 起读循环与刷写任务。
pub async fn open_carrier<S>(
    mut stream: S,
    config: &NodeConfig,
    credential: [u8; 16],
    wait: Duration,
) -> Result<Arc<MuxCarrier>, DialError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    // 参考 `outbound.go:218-232` + `encoding.go:50-54`：承载请求头没有地址段。
    send_request(&mut stream, &carrier_request(), &credential, wait).await?;
    let mux = config
        .mux
        .as_ref()
        .ok_or_else(|| DialError::Rejected("未配置 mux 段".to_owned()))?;
    let (mut source, sink) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    // 刷写任务：帧字节 → 承载连接（写侧唯一的出口 ⇒ 保序）。
    tokio::spawn(async move {
        let mut sink = sink;
        while let Some(bytes) = rx.recv().await {
            if sink.write_all(&bytes).await.is_err() {
                break;
            }
            let _ = sink.flush().await;
        }
    });
    // 库级承载：`MuxWire` 的写半边是帧队列，读半边永远 EOF（node 自己读帧）。
    let wire = MuxWire::new(QueueWriter { tx: tx.clone() }, strategy(mux));
    let dispatch: Shared = Arc::new(Mutex::new(Dispatch {
        client: MuxClient::new(),
        routes: HashMap::new(),
    }));
    // 读循环：先消费 VLESS 响应头（参考把它滞留到首个 mux 帧才 flush），
    // 再解帧并按会话派发。
    let reader = Arc::clone(&dispatch);
    tokio::spawn(async move {
        read_loop(&mut source, reader, tx).await;
    });
    Ok(Arc::new(MuxCarrier {
        wire: Arc::new(Mutex::new(wire)),
        dispatch,
    }))
}

/// 承载读循环（参考 `ClientWorker.fetchOutput`）。帧读**不设超时**：中途取消会
/// 丢字节、让承载错位（参考的读也是无限阻塞的）。
async fn read_loop(source: &mut (impl AsyncRead + Unpin), dispatch: Shared, tx: FrameQueue) {
    // 响应头：参考把它滞留到首个 mux 帧才 flush ⇒ 这里在读循环里消费。
    let header = receive_response_header(source, MUX_IO_DEADLINE).await;
    if header.is_err() {
        close_all(&dispatch).await;
        return;
    }
    loop {
        let meta = match decode_from_async(source, false).await {
            Ok(meta) => meta,
            Err(_) => break,
        };
        // 参考的四个分支在带 OptionData 时都会消费数据段 ⇒ 必须先读再派发。
        // node 只开 TCP 会话 ⇒ 数据段按流式上限读（参考 `NewStreamReader`）。
        let data = if meta.has_data() {
            match read_data_async(source, true).await {
                Ok(data) => Some(data),
                Err(_) => break,
            }
        } else {
            None
        };
        let mut dispatch = dispatch.lock().await;
        let action = match dispatch.client.handle(&meta, data) {
            Ok(action) => action,
            Err(_) => break,
        };
        match action {
            Action::None => {}
            Action::Deliver { id, payload, .. } => {
                if let Some(tx) = dispatch.routes.get(&id) {
                    let _ = tx.send(Delivery::Data(payload));
                }
            }
            Action::CloseSession { id } => {
                dispatch.client.manager.remove(id);
                if let Some(tx) = dispatch.routes.remove(&id) {
                    let _ = tx.send(Delivery::Closed);
                }
            }
            // 参考 `handleStatusKeep` 未命中会话 ⇒ 回一个 `End` 帧通知对端关闭。
            Action::SendEnd { id } => {
                let mut wire = Vec::new();
                if write_closing_end(&mut wire, id, TargetNetwork::Tcp).is_ok() {
                    let _ = tx.send(wire);
                }
            }
        }
    }
    close_all(&dispatch).await;
}

async fn close_all(dispatch: &Shared) {
    let mut dispatch = dispatch.lock().await;
    for (_, tx) in dispatch.routes.drain() {
        let _ = tx.send(Delivery::Closed);
    }
}

fn broken_pipe(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, message.to_owned())
}

/// 一条逻辑会话的字节流（`AsyncRead` + `AsyncWrite`）。
pub struct MuxSessionIo {
    id: u16,
    carrier: Arc<MuxCarrier>,
    inbox: mpsc::UnboundedReceiver<Delivery>,
    pending: Vec<u8>,
    commands: mpsc::UnboundedSender<WriteCmd>,
    acks: mpsc::UnboundedReceiver<()>,
    pending_acks: usize,
}

impl MuxSessionIo {
    #[must_use]
    pub fn id(&self) -> u16 {
        self.id
    }

    /// 在同一条承载上再开一条逻辑会话。
    pub async fn open_session(&self, target: TargetAddr) -> Result<MuxSessionIo, MuxError> {
        self.carrier.open_session(target).await
    }
}

impl AsyncRead for MuxSessionIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.pending.is_empty() {
                match self.inbox.poll_recv(cx) {
                    Poll::Ready(Some(Delivery::Data(data))) => self.pending = data,
                    Poll::Ready(Some(Delivery::Closed)) | Poll::Ready(None) => {
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => return Poll::Pending,
                }
                continue; // 零长数据帧不是 EOF（参考空写 = no-op）：继续等下一帧。
            }
            let take = self.pending.len().min(buf.remaining());
            let chunk: Vec<u8> = self.pending.drain(..take).collect();
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for MuxSessionIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.commands.send(WriteCmd::Data(buf.to_vec())) {
            Ok(()) => {
                self.pending_acks += 1;
                Poll::Ready(Ok(buf.len()))
            }
            Err(_) => Poll::Ready(Err(broken_pipe("mux 会话写任务已退出"))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_acks > 0 {
            match self.acks.poll_recv(cx) {
                Poll::Ready(Some(())) => self.pending_acks -= 1,
                // 写任务退出（写失败或已关闭）⇒ 帧没有落地 ⇒ fail-closed。
                Poll::Ready(None) => {
                    self.pending_acks = 0;
                    return Poll::Ready(Err(broken_pipe("mux 会话写任务已退出")));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.commands.send(WriteCmd::Close);
        Poll::Ready(Ok(()))
    }
}

/// 会话写任务：数据 → `Keep` 帧（参考 `Writer.WriteMultiBuffer`），收尾 → `End`。
async fn spawn_writer(
    mut session: MuxSession,
    mut commands: mpsc::UnboundedReceiver<WriteCmd>,
    acks: mpsc::UnboundedSender<()>,
) {
    while let Some(command) = commands.recv().await {
        match command {
            WriteCmd::Data(payload) => {
                if session.write(&payload, MUX_IO_DEADLINE).await.is_err() {
                    return;
                }
                let _ = acks.send(());
            }
            WriteCmd::Close => {
                let _ = session.close(MUX_IO_DEADLINE).await;
                let _ = acks.send(());
                return;
            }
        }
    }
}

impl MuxCarrier {
    /// 打开一条逻辑会话（参考 `ClientWorker.Dispatch` → `sm.Allocate`）：会话 ID 与
    /// `New` 帧由库级 `MuxWire` 负责；本方法只登记路由并起写任务。
    pub async fn open_session(
        self: &Arc<Self>,
        target: TargetAddr,
    ) -> Result<MuxSessionIo, MuxError> {
        let (inbox_tx, inbox) = mpsc::unbounded_channel();
        // 登记与开帧放在同一把锁里：读循环的派发也拿这把锁 ⇒ 对端不可能在
        // 「会话已开、路由未登记」的窗口里回数据。
        let mut dispatch = self.dispatch.lock().await;
        let session = {
            let mut wire = self.wire.lock().await;
            wire.open((target.clone(), TargetNetwork::Tcp), None, MUX_IO_DEADLINE)
                .await?
        };
        let id = session.id();
        let state = SessionState {
            target: (target, TargetNetwork::Tcp),
        };
        dispatch.client.manager.add(id, state);
        dispatch.routes.insert(id, inbox_tx);
        drop(dispatch);
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (acks, ack_rx) = mpsc::unbounded_channel();
        tokio::spawn(spawn_writer(session, command_rx, acks));
        Ok(MuxSessionIo {
            id,
            carrier: Arc::clone(self),
            inbox,
            pending: Vec::new(),
            commands,
            acks: ack_rx,
            pending_acks: 0,
        })
    }
}
