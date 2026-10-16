//! 会话共享状态：写侧、在途请求表、poisoned 标记、通知分发与统计计数。
//!
//! 这些状态被 reader 任务与所有请求方共用，因此全部放在 [`Arc<Inner>`] 里；
//! 只使用 `std::sync::Mutex`（临界区内不 await）与原子计数，避免跨 await
//! 持锁导致自等待。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::ChildStdin;
use tokio::sync::{broadcast, oneshot, Mutex as AsyncMutex};

use crate::codec::Framing;
use crate::error::Error;
use crate::protocol::{
    JsonRpcNotification, NotificationEnvelope, RequestId, Response, ResponsePayload, ServerRequest,
};

/// 单次从 stdout 读取的块大小。
pub(super) const READ_CHUNK_BYTES: usize = 16 * 1024;

/// 服务端请求记录上限（v0 不处理这些请求，只留证据并自动拒绝）。
const SERVER_REQUEST_LOG: usize = 64;

/// 通知广播通道的最小容量（配置为 0 时按 1 处理）。
pub(super) const MIN_NOTIFY_CAPACITY: usize = 1;

/// 响应投递通道。投递 `Ok(负载)`，连接级失败投递 `Err(原因)`，这样超时引发的
/// 连带失败（poisoned）能原样传给等待方，不会被伪装成一条正常响应。
pub(super) type Reply = oneshot::Sender<Result<ResponsePayload, Error>>;

/// 会话共享状态。
pub(super) struct Inner {
    pub(super) framing: Framing,
    pub(super) max_frame_bytes: usize,
    pub(super) default_timeout: Duration,
    /// 写侧。锁保证一帧的 `write_all + flush` 不被别的请求交叉拆开。
    /// 会话构造与传输安装分两步，未安装前为 `None`。
    pub(super) writer: AsyncMutex<Option<ChildStdin>>,
    /// 是否已安装传输（stdio 子进程管道）。
    pub(super) transport: AtomicBool,
    /// 在途请求表。std Mutex：全程不跨 await 持有。
    pub(super) pending: Mutex<BTreeMap<RequestId, Reply>>,
    /// 致命损坏原因；非 `None` 时连接必须丢弃。
    pub(super) poison: Mutex<Option<String>>,
    pub(super) closed: AtomicBool,
    pub(super) notify_tx: broadcast::Sender<JsonRpcNotification>,
    /// 会话创建时预留的唯一订阅端，由上层取走（[`super::Session::take_notifications`]）。
    pub(super) notify_seed: Mutex<Option<broadcast::Receiver<JsonRpcNotification>>>,
    /// 慢订阅者滞后次数（诊断用；策略是丢弃最旧而不是阻塞读循环）。
    /// 用 `Arc` 是因为取走的订阅端也要往同一计数上累加。
    pub(super) notify_dropped: Arc<AtomicU64>,
    pub(super) server_requests: Mutex<Vec<ServerRequest>>,
    pub(super) unmatched_responses: AtomicU64,
    pub(super) ignored_messages: AtomicU64,
}

impl Inner {
    #[must_use]
    pub(super) fn poison_reason(&self) -> Option<String> {
        self.poison.lock().expect("poison 锁不中毒").clone()
    }

    /// 连接是否仍可用：未 poisoned、未 closed、已安装传输。
    pub(super) fn ensure_usable(&self) -> Result<(), Error> {
        if let Some(reason) = self.poison_reason() {
            return Err(Error::Poisoned { reason });
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Transport {
                reason: "会话已关闭".to_string(),
            });
        }
        if !self.transport.load(Ordering::Acquire) {
            return Err(Error::Transport {
                reason: "会话尚未安装传输".to_string(),
            });
        }
        Ok(())
    }

    /// 等待方拿不到响应时的原因：优先 poisoned，其次按连接结束处理。
    pub(super) fn failure_reason(&self) -> Error {
        if let Some(reason) = self.poison_reason() {
            return Error::Poisoned { reason };
        }
        Error::Transport {
            reason: "连接结束，响应未送达".to_string(),
        }
    }

    /// 标记 poisoned（致命帧损坏或超时）。首次原因胜出，便于定位根因。
    pub(super) fn poison(&self, reason: String) {
        let mut guard = self.poison.lock().expect("poison 锁不中毒");
        if guard.is_none() {
            *guard = Some(reason);
        }
    }

    /// 丢弃写侧句柄。用 `try_lock`：这是清理路径，不能因为锁被请求方持有
    /// 而等待（等待就会在 Drop/abort 上阻塞）。取不到锁时由持有方在写失败
    /// 后自行丢弃，语义不变。
    pub(super) fn close_writer(&self) {
        if let Ok(mut guard) = self.writer.try_lock() {
            let _ = guard.take();
        }
    }

    pub(super) fn register(&self, id: RequestId, tx: Reply) {
        self.pending
            .lock()
            .expect("pending 锁不中毒")
            .insert(id, tx);
    }

    pub(super) fn deregister(&self, id: &RequestId) {
        self.pending.lock().expect("pending 锁不中毒").remove(id);
    }

    /// 向所有在途请求投递错误（只撤下 sender，不改变 closed/poison 标记）。
    pub(super) fn fail_all(&self, err: &Error) {
        let entries: Vec<Reply> = {
            let mut guard = self.pending.lock().expect("pending 锁不中毒");
            std::mem::take(&mut *guard).into_values().collect()
        };
        for tx in entries {
            let _ = tx.send(Err(err.clone()));
        }
    }

    /// 投递一条响应；未匹配到在途请求则计数（迟到响应或陌生 id）。
    pub(super) fn deliver(&self, resp: Response) {
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
    pub(super) async fn send_frame<T: serde::Serialize>(&self, body: &T) -> Result<(), Error> {
        self.ensure_usable()?;
        let frame = self.framing.encode(body)?;
        self.send_raw_frame(&frame).await
    }

    /// 写入已编码的帧。服务端请求拒绝路径需要先在 reader 内编码，以便尽早
    /// 发现内部状态损坏；请求路径则由 [`Self::send_frame`] 编码后转入这里。
    pub(super) async fn send_raw_frame(&self, frame: &[u8]) -> Result<(), Error> {
        self.ensure_usable()?;
        let mut guard = self.writer.lock().await;
        let Some(stdin) = guard.as_mut() else {
            return Err(Error::Transport {
                reason: "子进程 stdin 已关闭，会话不可复用".to_string(),
            });
        };
        let result = async {
            stdin.write_all(frame).await.map_err(|e| e.to_string())?;
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

    /// 广播一条通知。无订阅者属正常（`send` 的 `Err` 只代表所有订阅端都已
    /// 释放）；订阅者滞后由 `Receiver::recv` 一侧丢最旧并计数，读循环不阻塞。
    /// 通知不是协议状态的权威来源，因此没人收也不判定连接损坏。
    pub(super) fn broadcast_notification(&self, note: JsonRpcNotification) {
        let _ = self.notify_tx.send(note);
    }

    /// 记录服务端发起的请求，环形保留最近 [`SERVER_REQUEST_LOG`] 条。
    pub(super) fn record_server_request(&self, req: ServerRequest) {
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
