//! VLESS Mux 出站原语（客户端侧）：把「已建立的字节流」接成一条 mux 承载连接。
//!
//! ## 定位
//!
//! [`crate::mux`] 已经把参考的帧编解码（`common/mux/frame.go`）与会话状态机
//! （`common/mux/{session,client,writer}.go`）转写完成，但那两层是**纯逻辑**的：
//! 输入输出由调用方注入，会话的数据面（`buf.Copy`）也由调用方驱动
//! （见 `mux/worker.rs` 模块头）。生产侧缺的是「把一条已建立的字节流接成一条
//! mux 承载连接」的那层接线，本模块就是这层。
//!
//! ```text
//! 已建立的字节流（TCP / REALITY / 任意 AsyncRead+AsyncWrite）
//!      │  tokio::io::split
//!      ├── 写半边 ──▶ MuxWire::open / MuxSession::write / MuxSession::close
//!      └── 读半边 ──▶ MuxWire::next_inbound
//! ```
//!
//! ## 复用的既有原语（**本模块不含第二份帧逻辑**）
//!
//! | 本模块的出口 | 复用的既有原语 | 位置 |
//! |---|---|---|
//! | 会话 ID 分配、活跃/累计会话数 | `worker::SessionManager::allocate` | `src/mux/worker.rs:100` |
//! | 会话登记 / 移除 | `worker::SessionManager::add` / `remove` | `src/mux/worker.rs:118` / `:127` |
//! | 请求侧帧生成（`New`/`Keep`/`End`） | `worker::SessionWriter::{write_meta_only,write_multi,close}` | `src/mux/worker.rs:244` / `:263` / `:278` |
//! | 「通知对端关闭」帧 | `worker::write_closing_end` | `src/mux/worker.rs:298` |
//! | 下行帧派发 | `worker::MuxClient::handle` | `src/mux/worker.rs:353` |
//! | 帧头解码 | `mux::frame::decode_from_async` | `src/mux/frame.rs:422` |
//! | 数据段解码 | `mux::frame::read_data_async` | `src/mux/frame.rs:437` |
//!
//! 本模块只做三件事：把字节流劈成读写两半、把 `worker` 的同步原语接到异步写
//! 半边上、把 `worker` 的状态机接成异步读半边上的一个循环。**加密/分帧/会话
//! 状态机一律不在本文件里重写。**
//!
//! ## 与参考的对应（Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）
//!
//! - [`MuxWire::open`] ≡ 参考 `ClientWorker.Dispatch` ＋ `fetchInput` 的首帧：
//!   `New` 帧携带目标地址，可选携带首包（参考 `writeFirstPayload`）。
//! - [`MuxSession::write`] ≡ 参考 `Writer.WriteMultiBuffer`：空载荷只发元数据帧，
//!   流式会话按 8 KiB 分片，分组（UDP）会话一帧一包。
//! - [`MuxSession::close`] ≡ 参考 `Writer.Close` ＋ `Session.Close`：`End` 帧，
//!   出错时带 `OptionError`；关闭后把会话从会话表摘除。
//! - [`MuxWire::next_inbound`] ≡ 参考 `ClientWorker.fetchOutput` 的读循环：
//!   `KeepAlive`/`New` 丢数据、`Keep` 未命中会话回 `End`、`End` 关闭会话、
//!   帧头不合法即终止整条承载连接。
//!
//! ## 偏离参考之处（详见 `docs/vless-mux-wire.md` 的「偏离清单」）
//!
//! 1. **每次 I/O 都要调用方给截止时间**（参考的承载连接读是无限阻塞的）。
//!    本仓对网络 I/O 一律要求有界，调用方可用 [`DEFAULT_DEADLINE`]。
//! 2. **不承载 GlobalID / XUDP 跨连接恢复**（参考 `FrameMetadata.WriteTo` 的
//!    `b.UDP != nil` 分支会写 8 字节 GlobalID）。`mux/frame.rs` 模块头已记该差异，
//!    本模块沿用。
//! 3. **不写 `source`/`local` 地址**（参考只在 `Inbound != nil`，即反向 mux 时写）。
//!    本模块是出站原语，不承载反向 mux 上下文。
//! 4. **数据段长度超过 `u16::MAX` 直接报错**（参考 `serial.WriteUint16` 会静默截断）。

use std::{sync::Arc, time::Duration};

use ss_core::target::TargetAddr;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
    time::timeout,
};

use crate::mux::frame::{
    decode_from_async, read_data_async, FrameError, FrameMetadata, TargetNetwork,
};
use crate::mux::worker::{
    write_closing_end, Action, AllocateError, MuxClient, SessionState, SessionWriter, Strategy,
};

/// 默认 I/O 截止时间。
///
/// 参考的承载连接读是无限阻塞的（`ClientWorker.fetchOutput` 直接 `Unmarshal`），
/// 本仓要求所有网络 I/O 有界，故由调用方逐次给出截止时间；此常量是建议值。
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);

/// mux 出站原语的错误。全部 fail-closed：出错即返回，不产出任何替代数据。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 帧编解码失败（协议层不合法）。
    #[error("mux: 帧编解码失败：{0}")]
    Frame(#[from] FrameError),
    /// 会话分配失败（并发/累计上限，或会话表已关闭）。
    #[error("mux: 会话分配失败：{0}")]
    Allocate(#[from] AllocateError),
    /// 会话表已关闭，无法登记新会话。
    #[error("mux: 会话表已关闭")]
    SessionTableClosed,
    /// 截止时间必须大于零。
    #[error("mux: 截止时间必须大于零")]
    InvalidDeadline,
    /// I/O 超时。
    #[error("mux: I/O 超时")]
    Timeout,
    /// 底层 I/O 失败。
    #[error("mux: 底层 I/O 失败：{0}")]
    Io(#[from] std::io::Error),
}

/// 承载连接上收到的一帧及其派发结果。
#[derive(Debug)]
pub struct MuxFrame {
    /// 帧元数据（参考 `FrameMetadata`）。
    pub meta: FrameMetadata,
    /// 客户端状态机对该帧的派发结果（参考 `ClientWorker.fetchOutput` 的
    /// `handleStatueKeepAlive`/`handleStatusNew`/`handleStatusKeep`/`handleStatusEnd`）。
    pub action: Action,
}

/// 会话表与策略（`MuxClient` 持有 `SessionManager`；策略来自 `ClientStrategy`）。
struct ClientState {
    client: MuxClient,
    strategy: Strategy,
}

/// 逻辑会话的写侧句柄。
///
/// 一个句柄对应承载连接上的一条 mux 会话（参考 `Session`）。多个句柄可并发写
/// 同一条承载连接：写半边由 `Arc<Mutex<..>>` 串行化，与参考里
/// `ClientWorker.link.Writer`（`pipe.Writer`，自带锁）语义一致。
pub struct MuxSession {
    id: u16,
    writer: SessionWriter,
    sink: Arc<Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,
    state: Arc<Mutex<ClientState>>,
}

impl std::fmt::Debug for MuxSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxSession")
            .field("id", &self.id)
            .field("has_error", &self.writer.has_error)
            .finish_non_exhaustive()
    }
}

impl MuxSession {
    /// 会话 ID（参考 `Session.ID`）。
    #[must_use]
    pub fn id(&self) -> u16 {
        self.id
    }

    /// 标记本次会话以错误收尾：随后的 `End` 帧带 `OptionError`。
    ///
    /// 参考 `fetchInput` 在拷贝失败时置 `writer.hasError = true`。
    pub fn mark_error(&mut self) {
        self.writer.has_error = true;
    }

    /// 写数据（参考 `Writer.WriteMultiBuffer`）。
    ///
    /// - 空载荷 ⇒ 只发一个元数据帧（参考 `writeMetaOnly`）；
    /// - TCP 会话 ⇒ 按 8 KiB 分片，每片一帧（参考 `buf.SplitSize(mb, 8*1024)`）；
    /// - UDP 会话 ⇒ 一帧一包（参考 `buf.SplitFirst`）。
    ///
    /// 整段载荷先编码进内存再落盘（复用 `worker::SessionWriter::write_multi` 这一
    /// 既有原语），故调用方宜按 ≤ 8 KiB 分片调用。
    pub async fn write(&mut self, payload: &[u8], deadline: Duration) -> Result<(), Error> {
        let mut wire = Vec::new();
        self.writer.write_multi(&mut wire, payload)?;
        write_to(self.sink.as_ref(), &wire, deadline).await
    }

    /// 结束会话：写 `End` 帧并把会话从会话表摘除。
    ///
    /// 参考 `Writer.Close`（写 `End` 帧；`has_error` 时带 `OptionError`）
    /// ＋ `Session.Close` 末尾的 `s.parent.Remove`。
    pub async fn close(mut self, deadline: Duration) -> Result<(), Error> {
        let mut wire = Vec::new();
        self.writer.close(&mut wire)?;
        write_to(self.sink.as_ref(), &wire, deadline).await?;
        self.state.lock().await.client.manager.remove(self.id);
        Ok(())
    }
}

/// mux 承载连接（客户端侧出站原语）。
///
/// 持有承载连接的一读一写两半边，以及参考 `ClientWorker` 的会话表与下行派发
/// 状态机（[`MuxClient`]）。生产侧（出站代理）典型用法：
///
/// ```no_run
/// # use ss_core::target::TargetAddr;
/// # use lengsuo_vless::mux::frame::TargetNetwork;
/// # use lengsuo_vless::mux::worker::Strategy;
/// # use lengsuo_vless::mux_wire::{MuxWire, DEFAULT_DEADLINE};
/// # async fn demo(stream: tokio::net::TcpStream) -> Result<(), Box<dyn std::error::Error>> {
/// // 1) 把「已建立的字节流」交给 mux 承载连接。
/// let mut wire = MuxWire::new(stream, Strategy::default());
/// // 2) 打开一条逻辑会话：首帧 `New` 携带目标地址。
/// let target = (TargetAddr::Domain("example.invalid".to_string(), 443), TargetNetwork::Tcp);
/// let mut session = wire.open(target, None, DEFAULT_DEADLINE).await?;
/// // 3) 写应用数据（`Keep` 帧 + 数据段）。
/// session.write(b"ping", DEFAULT_DEADLINE).await?;
/// // 4) 读承载连接上的下行帧，按 `frame.action` 派发。
/// let frame = wire.next_inbound(DEFAULT_DEADLINE).await?;
/// let _ = frame.action;
/// // 5) 收尾：`End` 帧 + 从会话表摘除（`close` 两者都做）。
/// session.close(DEFAULT_DEADLINE).await?;
/// # Ok(()) }
/// ```
pub struct MuxWire {
    sink: Arc<Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,
    source: Box<dyn AsyncRead + Send + Unpin>,
    state: Arc<Mutex<ClientState>>,
}

impl std::fmt::Debug for MuxWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxWire").finish_non_exhaustive()
    }
}

impl MuxWire {
    /// 把「已建立的字节流」包装成一条 mux 承载连接。
    ///
    /// `strategy` 对应参考 `ClientStrategy`（`MaxConcurrency` / `MaxConnection`）。
    pub fn new<S>(stream: S, strategy: Strategy) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (read, write) = tokio::io::split(stream);
        Self {
            sink: Arc::new(Mutex::new(Box::new(write))),
            source: Box::new(read),
            state: Arc::new(Mutex::new(ClientState {
                client: MuxClient::new(),
                strategy,
            })),
        }
    }

    /// 打开一条逻辑会话：分配会话 ID、登记会话、写出首帧 `New`。
    ///
    /// `first` 是可选首包（参考 `writeFirstPayload`）；`None` 时只发一个不带
    /// 数据段的 `New` 帧（参考「首包超时 ⇒ `WriteMultiBuffer(空)`」）。
    pub async fn open(
        &mut self,
        target: (TargetAddr, TargetNetwork),
        first: Option<&[u8]>,
        deadline: Duration,
    ) -> Result<MuxSession, Error> {
        check_deadline(deadline)?;
        // 帧生成与会话登记在状态锁内完成，落到承载连接上的写发生在锁外。
        let (id, writer, wire) = {
            let mut state = self.state.lock().await;
            // 参考 `ClientWorker.Dispatch`：`sm.Allocate` 后登记会话。
            let strategy = state.strategy;
            let id = state.client.manager.allocate(&strategy)?;
            if !state.client.manager.add(
                id,
                SessionState {
                    target: target.clone(),
                },
            ) {
                return Err(Error::SessionTableClosed);
            }
            let mut writer = SessionWriter::request(id, target.clone(), target.1);
            let mut wire = Vec::new();
            match first {
                // 参考 `writeFirstPayload` 拿到首包 ⇒ 首帧带数据。
                Some(payload) => writer.write_multi(&mut wire, payload)?,
                // 参考 `writeFirstPayload` 超时 ⇒ 空 multi-buffer ⇒ 只发元数据。
                None => writer.write_meta_only(&mut wire)?,
            }
            (id, writer, wire)
        };
        write_to(self.sink.as_ref(), &wire, deadline).await?;
        Ok(MuxSession {
            id,
            writer,
            sink: Arc::clone(&self.sink),
            state: Arc::clone(&self.state),
        })
    }

    /// 读承载连接上的下一帧，并按参考 `ClientWorker.fetchOutput` 派发。
    ///
    /// 帧头不合法（未知 status/network、`metaLen > 512`、截断）时**直接返回
    /// 错误**：参考在该处 `return`，即终止整条承载连接。调用方必须把错误当作
    /// 「承载连接已终止」处理。
    ///
    /// 派发 `Action::SendEnd`（下行 `Keep` 帧未命中会话）时本方法**自动**写出
    /// 那帧 `End` 通知（参考 `handleStatusKeep` 里的 `closingWriter.Close()`）。
    pub async fn next_inbound(&mut self, deadline: Duration) -> Result<MuxFrame, Error> {
        check_deadline(deadline)?;
        let meta = timeout(deadline, decode_from_async(&mut self.source, false))
            .await
            .map_err(|_| Error::Timeout)??;
        // 参考的四个 handle* 分支在有 OptionData 时都会消费数据段
        // （`buf.Copy(NewStreamReader(reader), buf.Discard)` 或读给会话），
        // 因此**必须**先消费数据段再派发，否则承载连接会错位。
        let stream = self.session_is_stream(meta.session_id).await;
        let data = if meta.has_data() {
            Some(
                timeout(deadline, read_data_async(&mut self.source, stream))
                    .await
                    .map_err(|_| Error::Timeout)??,
            )
        } else {
            None
        };
        let (action, closing) = {
            let mut state = self.state.lock().await;
            let action = state.client.handle(&meta, data)?;
            // 参考 `handleStatusEnd` → `s.Close(false)`：会话从会话表摘除。
            if let Action::CloseSession { id } = action {
                state.client.manager.remove(id);
            }
            let closing = matches!(action, Action::SendEnd { .. });
            (action, closing)
        };
        if closing {
            // 参考 `handleStatusKeep` 未命中会话 ⇒ 回一个 `End` 帧通知对端关闭。
            let mut wire = Vec::new();
            write_closing_end(&mut wire, meta.session_id, TargetNetwork::Tcp)?;
            write_to(self.sink.as_ref(), &wire, deadline).await?;
        }
        Ok(MuxFrame { meta, action })
    }

    /// 通知对端关闭某条会话（参考 `handleStatusKeep` 未命中会话时回的 `End` 帧）。
    ///
    /// [`MuxWire::next_inbound`] 已在派发 `Action::SendEnd` 时自动做过一次；
    /// 本方法供上层需要主动收尾时使用。
    pub async fn send_end(&self, id: u16, deadline: Duration) -> Result<(), Error> {
        check_deadline(deadline)?;
        let mut wire = Vec::new();
        write_closing_end(&mut wire, id, TargetNetwork::Tcp)?;
        write_to(self.sink.as_ref(), &wire, deadline).await
    }

    /// 关闭承载连接的写方向（参考 `ClientWorker.Close` →
    /// `common.Interrupt(m.link.Writer)`）。
    ///
    /// 关闭后对端读到 EOF；本仓的读半边仍可继续读，直到对端也关闭。
    pub async fn shutdown(&self, deadline: Duration) -> Result<(), Error> {
        check_deadline(deadline)?;
        let mut sink = self.sink.lock().await;
        timeout(deadline, sink.shutdown())
            .await
            .map_err(|_| Error::Timeout)??;
        Ok(())
    }

    /// 会话结束后从会话表摘除（参考 `Session.Close` 末尾的 `s.parent.Remove`）。
    pub async fn forget(&self, id: u16) {
        self.state.lock().await.client.manager.remove(id);
    }

    /// 某条会话的目标地址（上层据此把下行数据路由回对应的上游连接）。
    pub async fn session_target(&self, id: u16) -> Option<(TargetAddr, TargetNetwork)> {
        self.state
            .lock()
            .await
            .client
            .manager
            .get(id)
            .map(|session| session.target.clone())
    }

    /// 当前活跃会话数（参考 `SessionManager.Size`）。
    pub async fn active_sessions(&self) -> usize {
        self.state.lock().await.client.manager.size()
    }

    /// 累计分配过的会话数（参考 `SessionManager.Count`）。
    pub async fn total_sessions(&self) -> u16 {
        self.state.lock().await.client.manager.count()
    }

    /// 会话的数据方向是否按流式读（参考 `Session.NewReader`：
    /// `transferType == Stream` ⇒ `NewStreamReader`，否则 `NewPacketReader`）。
    /// 未知会话按流式处理，与参考丢弃路径（`NewStreamReader`）一致。
    async fn session_is_stream(&self, id: u16) -> bool {
        let state = self.state.lock().await;
        state
            .client
            .manager
            .get(id)
            .is_none_or(|session| session.target.1 == TargetNetwork::Tcp)
    }
}

/// 把一整段字节写入承载连接写半边（带截止时间）。
async fn write_to(
    sink: &Mutex<Box<dyn AsyncWrite + Send + Unpin>>,
    bytes: &[u8],
    deadline: Duration,
) -> Result<(), Error> {
    check_deadline(deadline)?;
    let mut sink = sink.lock().await;
    timeout(deadline, async {
        sink.write_all(bytes).await?;
        sink.flush().await
    })
    .await
    .map_err(|_| Error::Timeout)??;
    Ok(())
}

/// 截止时间必须大于零（对齐 `crate::stream::deadline` 的判据）。
fn check_deadline(deadline: Duration) -> Result<(), Error> {
    if deadline.is_zero() {
        return Err(Error::InvalidDeadline);
    }
    Ok(())
}
