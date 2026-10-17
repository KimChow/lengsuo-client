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

/// 单次从 stdout 读取的块大小。
const READ_CHUNK_BYTES: usize = 16 * 1024;

/// 服务端请求记录上限（v0 不处理这些请求，只留证据并自动拒绝）。
const SERVER_REQUEST_LOG: usize = 64;

/// 通知广播通道的最小容量（配置为 0 时按 1 处理）。
const MIN_NOTIFY_CAPACITY: usize = 1;

/// 响应投递通道。投递 `Ok(负载)`，连接级失败投递 `Err(错误)`，这样超时
/// 引发的连带失败（poisoned）能原样传给等待方，不会伪装成一条响应。
type Reply = oneshot::Sender<Result<ResponsePayload, Error>>;

/// 会话参数。
#[derive(Debug, Clone)]
pub(crate) struct SessionConfig {
    pub(crate) framing: Framing,
    pub(crate) max_frame_bytes: usize,
    pub(crate) notify_capacity: usize,
    pub(crate) default_timeout: Duration,
}

impl SessionConfig {
    /// 每请求默认超时（30s）。
    pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    pub(crate) fn new(
        framing: Framing,
        max_frame_bytes: usize,
        notify_capacity: usize,
        default_timeout: Duration,
    ) -> Self {
        Self {
            framing,
            max_frame_bytes,
            notify_capacity: notify_capacity.max(MIN_NOTIFY_CAPACITY),
            default_timeout,
        }
    }
}

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

impl Session {
    /// 建立会话状态但不安装传输：`has_transport()` 为 `false`，任何请求都会
    /// 以 [`Error::Transport`] fail-closed 拒绝，直到 [`Self::attach_stdio`]。
    #[must_use]
    pub(crate) fn with_config(config: SessionConfig) -> Arc<Self> {
        let (notify_tx, rx) = broadcast::channel(config.notify_capacity.max(MIN_NOTIFY_CAPACITY));
        let inner = Arc::new(Inner {
            framing: config.framing,
            max_frame_bytes: config.max_frame_bytes,
            default_timeout: config.default_timeout,
            writer: AsyncMutex::new(None),
            transport: AtomicBool::new(false),
            pending: Mutex::new(BTreeMap::new()),
            poison: Mutex::new(None),
            closed: AtomicBool::new(false),
            notify_tx,
            notify_seed: Mutex::new(Some(rx)),
            notify_dropped: AtomicU64::new(0),
            server_requests: Mutex::new(Vec::new()),
            unmatched_responses: AtomicU64::new(0),
            ignored_messages: AtomicU64::new(0),
        });
        Arc::new(Self {
            inner,
            child: AsyncMutex::new(None),
            next_id: AtomicI64::new(1),
            reader_task: Mutex::new(None),
        })
    }

    /// 安装 stdio 传输：接管子进程管道并启动 reader 任务。只能成功一次。
    ///
    /// # Errors
    /// [`Error::Transport`]：该会话已安装过传输（不覆盖，避免旧管道泄漏）。
    pub(crate) async fn attach_stdio(
        &self,
        stdin: ChildStdin,
        stdout: ChildStdout,
        child: Child,
    ) -> Result<(), Error> {
        {
            let mut writer = self.inner.writer.lock().await;
            if writer.is_some() || self.inner.transport.load(Ordering::Acquire) {
                return Err(Error::Transport {
                    reason: "会话已安装传输，不能重复安装".to_string(),
                });
            }
            *writer = Some(stdin);
            *self.child.lock().await = Some(child);
            self.inner.transport.store(true, Ordering::Release);
        }
        let task = tokio::spawn(reader_loop(
            BufReader::with_capacity(READ_CHUNK_BYTES, stdout),
            Arc::clone(&self.inner),
        ));
        *self.reader_task.lock().expect("reader 锁不中毒") = Some(task);
        Ok(())
    }

    /// 是否已安装传输。
    #[must_use]
    pub(crate) fn has_transport(&self) -> bool {
        self.inner.transport.load(Ordering::Acquire)
    }

    /// 以显式标记 poisoned：上层在握手失败等路径上留下原因文本。
    pub(crate) fn fail(&self, reason: &str) {
        self.inner.poison(reason.to_string());
    }

    #[must_use]
    pub(crate) fn framing(&self) -> Framing {
        self.inner.framing
    }

    #[must_use]
    pub(crate) fn default_timeout(&self) -> Duration {
        self.inner.default_timeout
    }

    /// 连接是否被标记 poisoned。
    #[must_use]
    pub(crate) fn is_poisoned(&self) -> bool {
        self.inner.poison_reason().is_some()
    }

    /// poisoned 原因（若有）。
    #[must_use]
    pub(crate) fn poison_reason(&self) -> Option<String> {
        self.inner.poison_reason()
    }

    /// 会话是否已结束（EOF 或主动关闭）。
    #[must_use]
    pub(crate) fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    /// 无法匹配到在途请求的响应数量（迟到响应或陌生 id）。
    #[must_use]
    pub(crate) fn unmatched_responses(&self) -> u64 {
        self.inner.unmatched_responses.load(Ordering::Acquire)
    }

    /// 被忽略的畸形消息数量（不损坏流，仅计数）。
    #[must_use]
    pub(crate) fn ignored_messages(&self) -> u64 {
        self.inner.ignored_messages.load(Ordering::Acquire)
    }

    /// 因订阅者滞后而被丢弃的通知数量。
    #[must_use]
    pub(crate) fn notify_dropped(&self) -> u64 {
        self.inner.notify_dropped.load(Ordering::Acquire)
    }

    /// 订阅服务端主动通知。每个订阅端独立；滞后时该端丢最旧（读循环不阻塞）。
    pub(crate) fn subscribe_notifications(&self) -> broadcast::Receiver<JsonRpcNotification> {
        self.inner.notify_tx.subscribe()
    }

    /// 取出并清空已记录的服务端请求（v0 只记录并自动拒绝，不处理）。
    pub(crate) fn drain_server_requests(&self) -> Vec<ServerRequest> {
        std::mem::take(
            &mut *self
                .inner
                .server_requests
                .lock()
                .expect("server request 锁不中毒"),
        )
    }

    fn alloc_id(&self) -> Result<RequestId, Error> {
        match self.next_id.fetch_add(1, Ordering::Relaxed) {
            // 取尽：回退并永久钉在 MAX，后续调用持续 fail-closed
            // （与 ss-core nonce 取尽同一语义：不可逆，不静默复用）。
            i64::MAX => {
                self.next_id.store(i64::MAX, Ordering::Relaxed);
                Err(Error::InvalidConfig {
                    reason: "请求 id 已取尽，必须重建会话".to_string(),
                })
            }
            n => Ok(RequestId::Number(n)),
        }
    }

    /// 发送请求并等待响应，返回 `result` 值；对端 `error` 分支映射为
    /// [`Error::JsonRpc`]。`timeout` 为 `None` 时使用会话默认值。
    ///
    /// # Errors
    /// 见 [`Error`]：超时（并 poison 连接）、传输中断、帧损坏、对端 JSON-RPC 错误。
    pub(crate) async fn request(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Option<Duration>,
    ) -> Result<Value, Error> {
        let payload = self.request_payload(method, params, timeout).await?;
        match payload {
            ResponsePayload::Result(v) => Ok(v),
            ResponsePayload::Error(e) => Err(e.to_error()),
        }
    }

    /// 发送请求并等待响应负载（保留 `error` 分支原样，供需要细粒度处理的调用方）。
    #[allow(dead_code)] // v0 出口：将来 sampling/进度等需要区分 result/error 形状时使用
    pub(crate) async fn request_payload(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Option<Duration>,
    ) -> Result<ResponsePayload, Error> {
        let timeout = timeout.unwrap_or(self.inner.default_timeout);
        let start = Instant::now();
        let deadline = start + timeout;
        self.inner.ensure_usable()?;
        let id = self.alloc_id()?;
        let (tx, rx) = oneshot::channel();
        self.inner.register(id.clone(), tx);

        let envelope = RequestEnvelope {
            jsonrpc: "2.0",
            id: id.clone(),
            method: method.to_string(),
            params,
        };
        if let Err(e) = self.inner.send_frame(&envelope).await {
            self.inner.deregister(&id);
            return Err(e);
        }

        match tokio::time::timeout_at(deadline, rx).await {
            // rx 的 item 已是 `Result<ResponsePayload, Error>`：读侧投递的
            // 连接级失败（poisoned）原样返回，不伪装成一条响应。
            Ok(Ok(payload)) => payload,
            Ok(Err(_canceled)) => {
                // reader 收尾时撤下 sender：连接已结束。
                self.inner.deregister(&id);
                Err(self.inner.failure_reason())
            }
            Err(_elapsed) => {
                self.inner.deregister(&id);
                let elapsed_ms = (Instant::now() - start).as_millis() as u64;
                self.inner
                    .poison(format!("method={method} 等待响应超过 {timeout:?}"));
                // fail-closed：同会话其余在途请求一并失败，不复用半可信连接。
                self.inner.fail_all(&Error::Poisoned {
                    reason: format!("同会话内 method={method} 超时"),
                });
                Err(Error::Timeout { elapsed_ms })
            }
        }
    }

    /// 发送通知（无 id、无响应）。
    ///
    /// # Errors
    /// 写侧失败或连接不可用。
    pub(crate) async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), Error> {
        self.inner.ensure_usable()?;
        let envelope = NotificationEnvelope {
            jsonrpc: "2.0",
            method: method.to_string(),
            params,
        };
        self.inner.send_frame(&envelope).await
    }

    /// 回复服务端发起的请求（v0 提供出口，便于将来实现 sampling）。
    ///
    /// # Errors
    /// 写侧失败或连接不可用。
    #[allow(dead_code)] // 同上：v0 reader 自动拒绝，此出口留给后续实现
    pub(crate) async fn respond_to_server(
        &self,
        id: RequestId,
        payload: ResponsePayload,
    ) -> Result<(), Error> {
        let body = match payload {
            ResponsePayload::Result(v) => serde_json::json!({
                "jsonrpc": "2.0", "id": id, "result": v
            }),
            ResponsePayload::Error(e) => serde_json::json!({
                "jsonrpc": "2.0", "id": id, "error": e
            }),
        };
        self.inner.send_frame(&body).await
    }

    /// 正常关闭：关闭写侧（让服务端得到 stdin EOF），等待子进程退出；
    /// `kill_after` 到点仍未退出则强杀后再等一次。
    ///
    /// # Errors
    /// 等待子进程失败或强杀后仍不退出时返回 [`Error::Transport`]。
    pub(crate) async fn close(&self, kill_after: Duration) -> Result<i32, Error> {
        self.inner.close_writer();
        let mut guard = self.child.lock().await;
        let code = match guard.as_mut() {
            // 未安装传输（或子进程已回收）：没有进程可等，视为已退出。
            None => Ok(0),
            Some(child) => match tokio::time::timeout(kill_after, child.wait()).await {
                Ok(status) => status.map_err(|e| Error::Transport {
                    reason: format!("等待子进程退出失败：{e}"),
                }),
                Err(_) => {
                    let _ = child.start_kill();
                    tokio::time::timeout(kill_after, child.wait())
                        .await
                        .map_err(|_| Error::Transport {
                            reason: "子进程在强杀后仍未退出".to_string(),
                        })?
                        .map_err(|e| Error::Transport {
                            reason: format!("等待子进程退出失败：{e}"),
                        })
                }
            }
            .map(|status| status.code().unwrap_or(-1)),
        };
        let _ = guard.take();
        drop(guard);
        self.finish_shutdown();
        code
    }

    /// 立即强杀子进程并回收（异常清理路径，例如握手失败），停 reader。
    pub(crate) async fn abort(&self) {
        self.inner.close_writer();
        {
            let mut guard = self.child.lock().await;
            if let Some(child) = guard.as_mut() {
                let _ = child.start_kill();
                let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
            }
            let _ = guard.take();
        }
        self.finish_shutdown();
    }

    /// 标记 poisoned 并清理连接（超时后重建前调用）。
    #[allow(dead_code)] // 保留给上层显式丢弃语义；当前由 request 超时内部完成
    pub(crate) async fn hard_kill(&self, reason: String) {
        self.inner.poison(reason);
        self.abort().await;
    }

    /// 连接生命周期收尾：标记 closed、撤下在途请求、停 reader 任务。
    fn finish_shutdown(&self) {
        self.inner.closed.store(true, Ordering::Release);
        if let Some(task) = self.reader_task.lock().expect("reader 锁不中毒").take() {
            task.abort();
        }
    }

    /// `Drop` 前半程：停 reader、关写侧（不阻塞当前线程）。子进程由
    /// `kill_on_drop` 回收。
    pub(crate) fn finalize_drop(&self) -> Result<(), Error> {
        self.inner.close_writer();
        if let Ok(mut guard) = self.reader_task.try_lock() {
            if let Some(task) = guard.take() {
                task.abort();
            }
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // 先停 reader，再关闭写侧；不阻塞当前线程。子进程由 transport 的
        // `kill_on_drop` 负责，测试通过显式 shutdown/abort 验证无残留。
        let _ = self.finalize_drop();
    }
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

mod reader;
use reader::reader_loop;
