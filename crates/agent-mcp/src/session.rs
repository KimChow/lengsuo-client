//! 会话复用层：单条 transport 上的请求—响应 id 关联、通知分发、
//! 服务端请求处置与 poisoned 语义。
//!
//! 一条连接上并发多个请求是允许且常见的（本 crate 的并发请求复用同一
//! [`Session`]），因此响应顺序可以与请求顺序不同，匹配只依据 `id`。
//!
//! poisoned 语义（v0 取舍，同步记录到 result.md）：
//! - **帧级损坏**（非法 UTF-8、非法头、超长帧、EOF 截断帧）：字节流无法重新
//!   对齐，连接标记 poisoned，所有在途请求以同一错误失败，必须重建客户端。
//! - **单请求超时**：本地无法知道服务端是否仍在处理该 id，迟到响应可能被
//!   误认成别的需求，因此同样标记 poisoned（fail-closed），v0 不尝试取消。
//! - **可判定的畸形消息**（JSON 合法但不符合 JSON-RPC 2.0 形状）：只计数并
//!   忽略，不 poison —— 分帧仍然对齐，流没有损坏。
//! - **对端 EOF / 主动关闭**：标记 closed，在途请求失败，不再接受新请求，
//!   但原因文本记录为生命周期结束，与“损坏”区分。
//!
//! 子模块划分（本文件保留共享状态 [`Inner`] 与会话句柄 [`Session`] 的定义）：
//! - [`config`]：会话参数；
//! - [`core`]：构造、传输安装与只读访问；
//! - [`request`]：请求/通知/服务端回复路径；
//! - [`lifecycle`]：关闭、中止与 `Drop`；
//! - [`reader`]：stdout 读循环。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::{broadcast, oneshot, Mutex as AsyncMutex};
use tokio::time::Instant;

use crate::codec::{FrameDecoder, Framing};
use crate::error::Error;
use crate::protocol::{
    parse_wire_message, JsonRpcErrorObject, JsonRpcNotification, NotificationEnvelope,
    RequestEnvelope, RequestId, Response, ResponsePayload, ServerRequest, WireMessage,
    METHOD_NOT_FOUND,
};

mod config;
mod core;
mod lifecycle;
mod reader;
mod request;

pub(crate) use config::SessionConfig;

use reader::reader_loop;

/// 单次从 stdout 读取的块大小。
const READ_CHUNK_BYTES: usize = 16 * 1024;

/// 服务端请求记录上限（v0 不处理这些请求，只留证据并自动拒绝）。
const SERVER_REQUEST_LOG: usize = 64;

/// 通知广播通道的最小容量（配置为 0 时按 1 处理）。
const MIN_NOTIFY_CAPACITY: usize = 1;

/// 响应投递通道。投递 `Ok(负载)`，连接级失败投递 `Err(错误)`，这样超时
/// 引发的连带失败（poisoned）能原样传给等待方，不会伪装成一条响应。
type Reply = oneshot::Sender<Result<ResponsePayload, Error>>;

/// 会话共享状态（reader 任务与各请求方共用）。
struct Inner {
    framing: Framing,
    max_frame_bytes: usize,
    default_timeout: Duration,
    /// 写侧。锁保证一帧的 `write_all + flush` 不被别的请求交叉拆开。
    /// 会话构造与传输安装分两步，未安装前为 `None`。
    writer: AsyncMutex<Option<ChildStdin>>,
    /// 是否已安装传输（stdio 子进程管道）。
    transport: AtomicBool,
    /// 在途请求表。std Mutex：全程不跨 await 持有。
    pending: Mutex<BTreeMap<RequestId, Reply>>,
    /// 致命损坏原因；非 `None` 时连接必须丢弃。
    poison: Mutex<Option<String>>,
    closed: AtomicBool,
    notify_tx: broadcast::Sender<JsonRpcNotification>,
    /// 会话创建时预留的订阅端：保留给「一次性取走交付通道」的语义（v0 上层走
    /// [`Session::subscribe_notifications`]，本端只保证首帧不丢在广播通道里）。
    #[allow(dead_code)] // v0 出口：将来通知交付任务接管时启用
    notify_seed: Mutex<Option<broadcast::Receiver<JsonRpcNotification>>>,
    /// 慢订阅者滞后次数（诊断用；策略是丢弃最旧而不是阻塞读循环）。
    notify_dropped: AtomicU64,
    server_requests: Mutex<Vec<ServerRequest>>,
    unmatched_responses: AtomicU64,
    ignored_messages: AtomicU64,
}

/// 一条已建立 stdio 连接的 MCP 会话（低层，供 [`crate::client`] 使用）。
///
/// 会话构造与传输安装分两步（[`Session::with_config`] →
/// [`Session::attach_stdio`]）：前者只建状态，后者接管 stdio 管道并启动 reader。
/// stdio 之外的传输（将来 HTTP/SSE）可以自己预装传输后跳过 spawn。
pub(crate) struct Session {
    inner: Arc<Inner>,
    child: AsyncMutex<Option<Child>>,
    next_id: AtomicI64,
    reader_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Inner {
    #[must_use]
    fn poison_reason(&self) -> Option<String> {
        self.poison.lock().expect("poison 锁不中毒").clone()
    }

    fn ensure_usable(&self) -> Result<(), Error> {
        if let Some(reason) = self.poison_reason() {
            return Err(Error::Poisoned { reason });
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Transport {
                reason: "会话已关闭".to_string(),
            });
        }
        Ok(())
    }

    fn failure_reason(&self) -> Error {
        if let Some(reason) = self.poison_reason() {
            return Error::Poisoned { reason };
        }
        Error::Transport {
            reason: "连接结束，响应未送达".to_string(),
        }
    }

    /// 标记 poisoned（致命帧损坏或超时）。首次原因胜出，便于定位根因。
    fn poison(&self, reason: String) {
        let mut guard = self.poison.lock().expect("poison 锁不中毒");
        if guard.is_none() {
            *guard = Some(reason);
        }
    }

    fn close_writer(&self) {
        if let Ok(mut guard) = self.writer.try_lock() {
            let _ = guard.take();
        }
    }

    fn register(&self, id: RequestId, tx: Reply) {
        self.pending
            .lock()
            .expect("pending 锁不中毒")
            .insert(id, tx);
    }

    fn deregister(&self, id: &RequestId) {
        self.pending.lock().expect("pending 锁不中毒").remove(id);
    }

    /// 向所有在途请求投递错误（只撤下 sender，不改变 closed/poison 标记）。
    fn fail_all(&self, err: &Error) {
        let entries: Vec<Reply> = {
            let mut guard = self.pending.lock().expect("pending 锁不中毒");
            std::mem::take(&mut *guard).into_values().collect()
        };
        for tx in entries {
            let _ = tx.send(Err(err.clone()));
        }
    }

    /// 投递一条响应；未匹配到在途请求则计数（迟到响应或陌生 id）。
    fn deliver(&self, resp: Response) {
        let tx = self
            .pending
            .lock()
            .expect("pending 锁不中毒")
            .remove(&resp.id);
        match tx {
            Some(tx) => {
                let _ = tx.send(Ok(resp.payload()));
            }
            None => {
                self.unmatched_responses.fetch_add(1, Ordering::AcqRel);
            }
        }
    }

    /// 编码并写入一帧。`write_all + flush` 在同一把锁内完成，保证帧不被拆开交叉。
    async fn send_frame<T: serde::Serialize>(&self, body: &T) -> Result<(), Error> {
        self.ensure_usable()?;
        let frame = self.framing.encode(body)?;
        let mut guard = self.writer.lock().await;
        let Some(stdin) = guard.as_mut() else {
            return Err(Error::Transport {
                reason: "子进程 stdin 已关闭，会话不可复用".to_string(),
            });
        };
        let result = async {
            stdin.write_all(&frame).await.map_err(|e| e.to_string())?;
            stdin.flush().await.map_err(|e| e.to_string())
        }
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(reason) => {
                // 写失败意味着对端已不在读：丢弃写侧，不再复用。
                let _ = guard.take();
                self.poison(format!("写入子进程 stdin 失败：{reason}"));
                Err(Error::Transport {
                    reason: format!("写入子进程 stdin 失败：{reason}"),
                })
            }
        }
    }

    /// 广播一条通知。无订阅者属正常（`send` 返回 `Err` 只代表所有订阅端都已
    /// 释放）；订阅者滞后由 `Receiver::recv` 侧丢最旧，本端只计数不阻塞读循环。
    fn broadcast_notification(&self, note: JsonRpcNotification) {
        // 会话尚未建立订阅端（握手阶段）与订阅端已释放都属正常路径：通知不是
        // 协议状态权威来源，不能因为没人收就判定连接损坏。
        let _ = self.notify_tx.send(note);
    }

    fn record_server_request(&self, req: ServerRequest) {
        let mut guard = self
            .server_requests
            .lock()
            .expect("server request 锁不中毒");
        if guard.len() >= SERVER_REQUEST_LOG {
            guard.remove(0);
        }
        guard.push(req);
    }
}
