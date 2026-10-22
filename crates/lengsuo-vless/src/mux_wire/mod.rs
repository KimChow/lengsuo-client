//! VLESS Mux 出站原语（客户端侧）：把「已建立的字节流」接成一条 mux 承载连接。
//!
//! ## 定位
//!
//! [`crate::mux`] 已经把参考的帧编解码（`common/mux/frame.go`）与会话状态机
//! （`common/mux/{session,client,writer}.go`）转写完成，但那两层是**纯逻辑**的：
//! 输入输出由调用方注入，会话的数据面（`buf.Copy`）也由调用方驱动
//! （见 `mux/worker/mod.rs` 模块头）。生产侧缺的是「把一条已建立的字节流接成一条
//! mux 承载连接」的那层接线 —— 本模块就是这层。
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
//! | 会话 ID 分配、活跃/累计会话数 | `worker::SessionManager::allocate` | `mux/worker/session.rs:80` |
//! | 会话登记 / 移除 | `worker::SessionManager::add` / `remove` | `mux/worker/session.rs:98` / `:107` |
//! | 请求侧帧生成（`New`/`Keep`/`End`） | `worker::SessionWriter::{write_meta_only,write_multi,close}` | `mux/worker/writer.rs:97` / `:116` / `:131` |
//! | 「通知对端关闭」帧 | `worker::write_closing_end` | `mux/worker/writer.rs:151` |
//! | 下行帧派发 | `worker::MuxClient::handle` | `mux/worker/state.rs:29` |
//! | 帧头 / 数据段解码 | `mux::frame::{decode_from_async,read_data_async}` | `mux/frame/payload.rs:48` / `:63` |
//!
//! 本模块只做三件事：把字节流劈成读写两半、把 `worker` 的同步原语接到异步写
//! 半边上、把 `worker` 的状态机接成异步读半边上的一个循环。**加密/分帧/会话状态机
//! 一律不在本文件里重写**（详见 [`crate::mux`] 模块头）。
//!
//! ## 与参考的对应（Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）
//!
//! - [`MuxWire::open`] ≡ 参考 `ClientWorker.Dispatch` ＋ `fetchInput` 的首帧：
//!   `New` 帧携带目标地址，可选携带首包（参考 `writeFirstPayload`）。
//! - [`MuxSession::write`] ≡ 参考 `Writer.WriteMultiBuffer`：空载荷只发元数据帧，
//!   流式会话按 8 KiB 分片，分组（UDP）会话一帧一包。
//! - [`MuxSession::close`] ≡ 参考 `Writer.Close` ＋ `Session.Close`：`End` 帧，出错时
//!   带 `OptionError`；关闭后把会话从会话表摘除。
//! - [`MuxWire::next_inbound`] ≡ 参考 `ClientWorker.fetchOutput` 的读循环：
//!   `KeepAlive`/`New` 丢数据、`Keep` 未命中会话回 `End`、`End` 关闭会话、
//!   帧头不合法即终止整条承载连接。
//!
//! ## 承载连接上的 VLESS 响应头（**握手顺序**）
//!
//! 在 mux 承载连接上，**VLESS 响应头与 mux 帧流是同一条字节流**；响应头只在
//! **读侧**消费一次，写侧从不等它。
//!
//! ⚠️ **不能先阻塞等响应头再发帧**：参考 VLESS 入站把响应头写进
//! `buf.BufferedWriter` **之后**才 `SetFlushNext()` ⇒ 响应头滞留缓冲区，要等
//! **第一个 mux 下行帧**才 flush ⇒ 「我方等响应头」与「对端等第一个帧」互锁成
//! 死锁。参考自己的客户端不死锁，是因为它的 `postRequest` 在**另一个 goroutine**
//! 里持续转发 mux 帧流；本仓是**单线程**读侧，没有那个并发结构。
//! ⇒ 正确顺序：**先发 mux 帧**，再在读帧循环里消费开头那段响应头（完整依据见
//! `handshake` 模块头）。
//!
//! - 承载在 VLESS 连接上 ⇒ 用 [`MuxWire::new_over_vless`]（登记待消费的响应头）。
//! - 承载连接上**没有** VLESS 响应头前缀 ⇒ 用 [`MuxWire::new`]。
//!
//! ## 偏离参考之处（详见 `docs/vless-mux-wire.md` 的「偏离清单」）
//!
//! 1. **每次 I/O 都要调用方给截止时间**（参考的承载连接读是无限阻塞的）。
//!    本仓对网络 I/O 一律要求有界，调用方可用 [`DEFAULT_DEADLINE`]。
//! 2. **不承载 GlobalID / XUDP 跨连接恢复**（参考 `FrameMetadata.WriteTo` 的
//!    `b.UDP != nil` 分支会写 8 字节 GlobalID）。`mux/frame/mod.rs` 模块头已记该差异。
//! 3. **不写 `source`/`local` 地址**（参考只在 `Inbound != nil`，即反向 mux 时写）。
//!    本模块是出站原语，不承载反向 mux 上下文。
//! 4. **数据段长度超过 `u16::MAX` 直接报错**（参考 `serial.WriteUint16` 会静默截断）。
//! 5. **承载连接的写方向关闭用 `shutdown()`**（参考 `ClientWorker.Close` 用
//!    `common.Interrupt` 打断整条管道）；本仓只关写半边，不终止整条连接。
//! 6. **`End` 帧的 `OptionError` 由调用方显式置位**（参考在 `fetchInput` 失败时
//!    自动置 `writer.hasError`；本仓数据面由调用方驱动，故调 `mark_error()`）。

use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
    time::timeout,
};

use crate::mux::frame::FrameMetadata;
use crate::mux::worker::{Action, MuxClient, Strategy};

use handshake::PendingResponseHeader;

mod carrier;
mod error;
mod handshake;
mod session;

pub use error::Error;
pub use session::MuxSession;

/// 默认 I/O 截止时间。
///
/// 参考的承载连接读是无限阻塞的（`ClientWorker.fetchOutput` 直接 `Unmarshal`），
/// 本仓要求所有网络 I/O 有界，故由调用方逐次给出截止时间；此常量是建议值。
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);

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
pub(super) struct ClientState {
    client: MuxClient,
    strategy: Strategy,
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
    /// 承载连接开头还挂着一段待消费的 VLESS 响应头。
    ///
    /// 见模块头「承载连接上的 VLESS 响应头」：响应头**只在读侧**消费一次，
    /// 写侧从不等它 ⇒ 不会与参考「首个 mux 帧才 flush 响应头」的顺序互锁。
    pending_response_header: PendingResponseHeader,
}

impl std::fmt::Debug for MuxWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxWire")
            .field(
                "has_pending_response_header",
                &self.pending_response_header.is_pending(),
            )
            .finish_non_exhaustive()
    }
}

/// 把一整段字节写入承载连接写半边（带截止时间）。
pub(super) async fn write_to(
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
