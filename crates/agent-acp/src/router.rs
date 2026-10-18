//! 路由核心（P2）：帧事件 → pending 完成 / 本地 handler 应答 / 有界事件队列。
//!
//! 分派语义表（顶层判别复用 P1 [`crate::control::TopLevel`]，RPC 与 control 面分流）：
//!
//! | 入站帧 | 归属 | 处理 |
//! |---|---|---|
//! | Rpc::Response | 我发出的请求 | 按 id 完成 pending；未知 id → 计数，不 panic |
//! | Rpc::Request | agent→客户端 | handler 表命中 → 同步执行并回响应；未命中 → 自动回 `-32601`（不静默，防对端悬挂）|
//! | Rpc::Notification | 单向事件 | 入有界事件队列（满丢最旧并计数，fail-closed 防内存） |
//! | ControlRequest | V.* 回调 | subtype handler 命中 → 回 `control_response`；未命中 → 入队为可观测事件，由上层延后 [`crate::client::Client::respond_control`] |
//! | ControlResponse | 我发出的 control 请求 | 按 request_id 完成 pending_control；未知 id → 计数 |
//! | ControlNotification | 完成回传/单向事件 | 入事件队列 |
//! | BadFrame | — | 计数（字节流仍对齐，连接可用） |
//! | Closed | — | 终止：撤下全部 pending、置 closed、唤醒 `next_event` |
//!
//! 对端把 control 应答以 `control_notification` 形态送来时（互通二态），本端
//! 不做隐式匹配——通知一律入队，由上层按 request_id 关联，避免猜错信封语义。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};

use crate::codec::encode_frame;
use crate::control::{
    ControlNotification, ControlRequest, ControlResponse, ControlResponseTag, TopLevel,
};
use crate::error::Error;
use crate::message::{
    JsonRpcErrorObject, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, Message, RequestId,
    JSONRPC_ERROR_METHOD_NOT_FOUND,
};
use crate::transport::{FrameSink, FrameSource, SourceEvent, SourcePull};

/// 连接终止时撤下 pending 所用的私有错误码（非标准族，-3260x 之外的自定义区）。
pub const ACP_ERROR_CONNECTION_CLOSED: i64 = -32000;
/// 内部协议违例（如对端响应既无 result 也无 error）的私有错误码。
pub const ACP_ERROR_INTERNAL: i64 = -32001;

/// RPC / control 应答的统一结局：成功值或 JSON-RPC 错误对象。
pub type RpcOutcome = std::result::Result<Value, JsonRpcErrorObject>;

/// JSON-RPC 入站请求 handler（同步执行；阻塞会挂住路由线程，慎用）。
pub type RpcHandler = dyn Fn(&JsonRpcRequest) -> RpcOutcome + Send + Sync;

/// control 入站请求 handler（按 subtype 键控）。
pub type ControlHandler = dyn Fn(&ControlRequest) -> RpcOutcome + Send + Sync;

/// 事件队列条目：单向通知与未认领的 control 请求。
#[derive(Debug, Clone, PartialEq)]
pub enum ClientEvent {
    /// JSON-RPC 通知（如 `session/update`）。
    Notification(JsonRpcNotification),
    /// control 通知信封（含完成回传）。
    ControlNotification(ControlNotification),
    /// 未注册 handler 的 control 请求：交上层观测并延后应答。
    ControlRequest(ControlRequest),
}

/// 路由线程共享状态：sink、pending 表、事件队列、handler 表与计数器。
pub(crate) struct RouteState {
    pub sink: Mutex<Box<dyn FrameSink>>,
    pub pending: Mutex<HashMap<RequestId, Sender<RpcOutcome>>>,
    pub pending_control: Mutex<HashMap<RequestId, Sender<RpcOutcome>>>,
    pub events: Mutex<VecDeque<ClientEvent>>,
    pub event_cv: Condvar,
    pub max_events: usize,
    pub handlers: Mutex<HashMap<String, Arc<RpcHandler>>>,
    pub control_handlers: Mutex<HashMap<&'static str, Arc<ControlHandler>>>,
    pub stop: AtomicBool,
    pub closed: AtomicBool,
    pub closed_reason: Mutex<Option<String>>,
    pub dropped_events: AtomicU64,
    pub bad_frames: AtomicU64,
    pub unknown_ids: AtomicU64,
    pub poll_interval: Duration,
}

impl std::fmt::Debug for RouteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteState")
            .field("closed", &self.closed.load(Ordering::Acquire))
            .field("max_events", &self.max_events)
            .field(
                "dropped_events",
                &self.dropped_events.load(Ordering::Acquire),
            )
            .field("bad_frames", &self.bad_frames.load(Ordering::Acquire))
            .field("unknown_ids", &self.unknown_ids.load(Ordering::Acquire))
            .finish()
    }
}

impl RouteState {
    pub fn new(sink: Box<dyn FrameSink>, max_events: usize, poll_interval: Duration) -> Self {
        Self {
            sink: Mutex::new(sink),
            pending: Mutex::new(HashMap::new()),
            pending_control: Mutex::new(HashMap::new()),
            events: Mutex::new(VecDeque::new()),
            event_cv: Condvar::new(),
            max_events: max_events.max(1),
            handlers: Mutex::new(HashMap::new()),
            control_handlers: Mutex::new(HashMap::new()),
            stop: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            closed_reason: Mutex::new(None),
            dropped_events: AtomicU64::new(0),
            bad_frames: AtomicU64::new(0),
            unknown_ids: AtomicU64::new(0),
            poll_interval,
        }
    }

    /// 连接可用（未终止）才可写。
    pub fn usable(&self) -> Result<(), Error> {
        if self.closed.load(Ordering::Acquire) {
            let reason = self
                .closed_reason
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .unwrap_or_else(|| "连接已终止".into());
            return Err(Error::Transport { reason });
        }
        Ok(())
    }

    /// 编码一帧并写入 sink（写锁覆盖编码+写，保证帧字节序与注册序一致）。
    pub fn write_frame<T: Serialize>(&self, value: &T) -> Result<(), Error> {
        self.usable()?;
        let frame = encode_frame(value)?;
        self.sink
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send_frame(&frame)
    }

    /// 取 pending 表（RPC / control 共用请求 id 空间但分表存放）。
    fn pending_map(
        &self,
        control: bool,
    ) -> std::sync::MutexGuard<'_, HashMap<RequestId, Sender<RpcOutcome>>> {
        let guard = if control {
            self.pending_control.lock()
        } else {
            self.pending.lock()
        };
        guard.unwrap_or_else(|e| e.into_inner())
    }

    /// 注册等待回执的通道。
    pub fn register(&self, control: bool, id: RequestId) -> Receiver<RpcOutcome> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.pending_map(control).insert(id, tx);
        rx
    }

    /// 撤销一个 pending（发送超时后的清理；返回是否确实存在）。
    pub fn cancel_pending(&self, control: bool, id: &RequestId) -> bool {
        self.pending_map(control).remove(id).is_some()
    }

    /// 完成一个 pending；未知 id 计数并丢弃（不 panic）。
    fn deliver(&self, control: bool, id: RequestId, outcome: RpcOutcome) {
        match self.pending_map(control).remove(&id) {
            Some(tx) => {
                let _ = tx.send(outcome);
            }
            None => {
                self.unknown_ids.fetch_add(1, Ordering::AcqRel);
            }
        }
    }

    /// 入队事件：满时丢最旧并计数（fail-closed：保护内存，不静默吞计数）。
    pub fn push_event(&self, ev: ClientEvent) {
        let mut q = self.events.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() >= self.max_events {
            let _ = q.pop_front();
            self.dropped_events.fetch_add(1, Ordering::AcqRel);
        }
        q.push_back(ev);
        drop(q);
        self.event_cv.notify_all();
    }

    /// 连接终止：撤下全部 pending，置 closed 与原因，唤醒等待者。幂等。
    pub fn terminate(&self, reason: Option<String>) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        *self.closed_reason.lock().unwrap_or_else(|e| e.into_inner()) = reason.clone();
        let err = RpcOutcome::Err(JsonRpcErrorObject {
            code: ACP_ERROR_CONNECTION_CLOSED,
            message: format!(
                "连接已终止：{}",
                reason.unwrap_or_else(|| "对端干净退出".into())
            ),
            data: None,
        });
        for map in [&self.pending, &self.pending_control] {
            let drained: Vec<_> = {
                let g = map.lock();
                let mut g = g.unwrap_or_else(|e| e.into_inner());
                g.drain().collect()
            };
            for (_id, tx) in drained {
                let _ = tx.send(err.clone());
            }
        }
        self.event_cv.notify_all();
    }

    /// 归类处理一帧（分派语义表见模块头）。
    pub fn handle_top(self: &Arc<Self>, top: TopLevel) {
        match top {
            TopLevel::Rpc(Message::Response(resp)) => {
                let outcome = match (&resp.error, &resp.result) {
                    (Some(e), _) => RpcOutcome::Err(e.clone()),
                    (None, Some(r)) => RpcOutcome::Ok(r.clone()),
                    (None, None) => RpcOutcome::Err(JsonRpcErrorObject {
                        code: ACP_ERROR_INTERNAL,
                        message: "响应既无 result 也无 error".into(),
                        data: None,
                    }),
                };
                self.deliver(false, resp.id.clone(), outcome);
            }
            TopLevel::Rpc(Message::Request(req)) => self.handle_inbound_request(req),
            TopLevel::Rpc(Message::Notification(n)) => {
                self.push_event(ClientEvent::Notification(n));
            }
            TopLevel::ControlRequest(req) => {
                let handler = self
                    .control_handlers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(req.request.subtype.as_str())
                    .cloned();
                match handler {
                    Some(h) => {
                        let outcome = h(&req);
                        let _ = self.respond_control(&req.request_id, outcome);
                    }
                    None => self.push_event(ClientEvent::ControlRequest(req)),
                }
            }
            TopLevel::ControlResponse(resp) => {
                self.deliver(true, resp.request_id.clone(), RpcOutcome::Ok(resp.response));
            }
            TopLevel::ControlNotification(n) => {
                self.push_event(ClientEvent::ControlNotification(n));
            }
        }
    }

    /// 入站 JSON-RPC 请求：命中 handler 则同步执行回响应；未命中自动回
    /// `-32601`，绝不应答失败后悬挂（也不静默丢弃）。
    fn handle_inbound_request(self: &Arc<Self>, req: JsonRpcRequest) {
        let handler = self
            .handlers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&req.method)
            .cloned();
        let outcome = match handler {
            Some(h) => h(&req),
            None => RpcOutcome::Err(JsonRpcErrorObject {
                code: JSONRPC_ERROR_METHOD_NOT_FOUND,
                message: "client does not handle this method".into(),
                data: Some(Value::String(req.method.clone())),
            }),
        };
        let resp = match outcome {
            Ok(v) => Message::Response(JsonRpcResponse::ok(req.id.clone(), v)),
            Err(e) => Message::Response(JsonRpcResponse::err(req.id.clone(), e)),
        };
        let _ = self.write_frame(&resp);
    }

    /// 回一条 control 应答信封：Ok → 载荷本体；Err → `{error:{…}}` 载荷。
    pub fn respond_control(
        &self,
        request_id: &RequestId,
        outcome: RpcOutcome,
    ) -> Result<(), Error> {
        let response = match outcome {
            Ok(v) => v,
            Err(e) => json!({ "error": e }),
        };
        let env = ControlResponse {
            kind: ControlResponseTag::ControlResponse,
            request_id: request_id.clone(),
            response,
        };
        self.write_frame(&env)
    }
}

/// 路由线程主循环：拉帧事件直到 Closed 或 stop 标志。
pub(crate) fn router_loop(mut source: Box<dyn FrameSource>, state: Arc<RouteState>) {
    while !state.stop.load(Ordering::Acquire) {
        match source.next_event(state.poll_interval) {
            SourcePull::Timeout => continue,
            SourcePull::Event(SourceEvent::Frame(top)) => state.handle_top(top),
            SourcePull::Event(SourceEvent::BadFrame { .. }) => {
                state.bad_frames.fetch_add(1, Ordering::AcqRel);
            }
            SourcePull::Event(SourceEvent::Closed { reason }) => {
                state.terminate(reason);
                return;
            }
        }
    }
    // stop 主动拆除：也算终止，撤 pending 唤醒调用方。
    state.terminate(None);
}
