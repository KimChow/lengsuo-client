//! 请求-响应路由客户端（P2）：组装 [`crate::transport`] 与 [`crate::router`]，
//! 提供同步 API（不引异步运行时）。
//!
//! 结构：`Client` 持有共享路由状态（写侧 sink + pending 表 + 事件队列），
//! 一条路由线程从帧源拉事件并分派（语义表见 [`crate::router`] 模块头）。
//! - 出站请求：`send_request` 先注册 pending 再写帧（消除响应先到的竞态）；
//!   写失败即撤销注册并报错。
//! - 回执：`RequestHandle::wait_timeout` 有界等待，超时撤销 pending。
//! - 事件：`next_event`（Condvar 阻塞 + 超时）/ `poll_event`（非阻塞）。
//! - 拆除：`stop → sink.close → 路由线程退出 → 一次性执行 Transport 的
//!   拆除钩子（stdio 形态里 kill+reap）`。Drop 自动执行，幂等。

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::control::{ControlRequest, ControlRequestBody, ControlRequestTag, ControlSubtype};
use crate::error::Error;
use crate::message::{JsonRpcRequest, RequestId};
use crate::router::{router_loop, ClientEvent, ControlHandler, RouteState, RpcHandler, RpcOutcome};
use crate::transport::{Teardown, Transport};

/// 默认事件队列上限。
pub const DEFAULT_MAX_EVENTS: usize = 1024;
/// 路由线程拉帧轮询间隔（同时决定 close 的响应延迟上界）。
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// `Client::next_event` 的结果。
#[derive(Debug, Clone, PartialEq)]
pub enum NextEvent {
    /// 取到一个事件。
    Event(ClientEvent),
    /// 超时内无事件（连接仍可用）。
    Idle,
    /// 连接已终止（事件队列已排空后才报此态；终止前入队的事件仍可先取出）。
    Closed,
}

/// 已发出请求的回执句柄：id + 完成通道。
#[derive(Debug)]
pub struct RequestHandle {
    /// 请求关联 id。
    pub id: RequestId,
    rx: Receiver<RpcOutcome>,
    control: bool,
    state: Arc<RouteState>,
}

impl RequestHandle {
    /// 有界等待响应。
    ///
    /// # Errors
    /// [`Error::Transport`]：超时（并撤销 pending，后续迟到的响应按未知 id 计数）。
    pub fn wait_timeout(self, timeout: Duration) -> crate::Result<RpcOutcome> {
        match self.rx.recv_timeout(timeout) {
            Ok(outcome) => Ok(outcome),
            Err(_) => {
                self.state.cancel_pending(self.control, &self.id);
                Err(Error::Transport {
                    reason: format!(
                        "请求 {} 等待响应超时（{}ms）",
                        self.id.display(),
                        timeout.as_millis()
                    ),
                })
            }
        }
    }

    /// 阻塞等待响应（无超时；仅确信对端必答时使用，倾向 [`Self::wait_timeout`]）。
    pub fn wait(self) -> RpcOutcome {
        self.rx.recv().unwrap_or_else(|_| {
            RpcOutcome::Err(crate::message::JsonRpcErrorObject {
                code: crate::router::ACP_ERROR_CONNECTION_CLOSED,
                message: "回执通道被释放".into(),
                data: None,
            })
        })
    }
}

/// 路由客户端配置。
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// 事件队列上限（满丢最旧并计数）。
    pub max_events: usize,
    /// 路由线程轮询间隔。
    pub poll_interval: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            max_events: DEFAULT_MAX_EVENTS,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }
}

/// 建在传输之上的 ACP 客户端（同步线程模型）。
#[derive(Debug)]
pub struct Client {
    state: Arc<RouteState>,
    next_number: AtomicI64,
    router: Mutex<Option<std::thread::JoinHandle<()>>>,
    teardown: Mutex<Option<Teardown>>,
}

impl Client {
    /// 接管一条传输：启动路由线程，返回客户端。
    #[must_use]
    pub fn new(transport: Transport) -> Self {
        Self::with_config(transport, ClientConfig::default())
    }

    /// 带配置接管传输。
    pub fn with_config(transport: Transport, config: ClientConfig) -> Self {
        let Transport {
            sink,
            source,
            teardown,
        } = transport;
        let state = Arc::new(RouteState::new(
            sink,
            config.max_events,
            config.poll_interval,
        ));
        let router = std::thread::Builder::new()
            .name("acp-router".into())
            .spawn({
                let state = Arc::clone(&state);
                move || router_loop(source, state)
            })
            .expect("路由线程总能启动");
        Self {
            state,
            next_number: AtomicI64::new(1),
            router: Mutex::new(Some(router)),
            teardown: Mutex::new(Some(teardown)),
        }
    }

    /// 下一个数字请求 id（字符串 id 由调用方自取，见 [`Self::send_request_id`]）。
    #[must_use]
    pub fn next_id(&self) -> RequestId {
        RequestId::Number(self.next_number.fetch_add(1, Ordering::AcqRel))
    }

    /// 发送 JSON-RPC 请求（指定 id）；params 为 Null 时省略。
    ///
    /// # Errors
    /// [`Error`]：序列化/写入失败或连接已终止。失败时不残留 pending。
    pub fn send_request_id(
        &self,
        id: RequestId,
        method: impl Into<String>,
        params: Value,
    ) -> crate::Result<RequestHandle> {
        let method = method.into();
        let req = JsonRpcRequest::new(id.clone(), method, params);
        // 先注册再写帧：响应可能在写回的同刻到达，注册后置会丢回执。
        let rx = self.state.register(false, id.clone());
        if let Err(e) = self.state.write_frame(&crate::Message::Request(req)) {
            self.state.cancel_pending(false, &id);
            return Err(e);
        }
        Ok(RequestHandle {
            id,
            rx,
            control: false,
            state: Arc::clone(&self.state),
        })
    }

    /// 发送 JSON-RPC 请求（自增数字 id）。
    pub fn send_request(
        &self,
        method: impl Into<String>,
        params: Value,
    ) -> crate::Result<RequestHandle> {
        let id = self.next_id();
        self.send_request_id(id, method, params)
    }

    /// 发送 JSON-RPC 通知（单向，无回执）。
    ///
    /// # Errors
    /// 同 [`Self::send_request`] 的写侧失败。
    pub fn send_notification(&self, method: impl Into<String>, params: Value) -> crate::Result<()> {
        self.state.write_frame(&crate::Message::Notification(
            crate::JsonRpcNotification::new(method, params),
        ))
    }

    /// 发送 control 请求信封（客户端→agent 的 B.* 私有面；subtype 已知形态）。
    ///
    /// # Errors
    /// [`Error`]：载荷无法摊平为对象、序列化/写入失败或连接已终止。
    pub fn send_control_request(
        &self,
        id: RequestId,
        subtype: ControlSubtype,
        payload: Value,
    ) -> crate::Result<RequestHandle> {
        let mut obj = match payload {
            Value::Object(map) => map,
            Value::Null => serde_json::Map::new(),
            other => {
                return Err(Error::MalformedMessage {
                    reason: format!("control 载荷必须是 JSON 对象，收到 {other}"),
                })
            }
        };
        // subtype 字段与 flatten 的 payload 分列：载荷内不得再带 subtype 键，
        // 否则 flatten 序列化会产生重复键（已知形态取 subtype 字段）。
        obj.remove("subtype");
        let req = ControlRequest {
            kind: ControlRequestTag::ControlRequest,
            request_id: id.clone(),
            request: ControlRequestBody {
                subtype,
                payload: Value::Object(obj),
            },
        };
        let rx = self.state.register(true, id.clone());
        if let Err(e) = self.state.write_frame(&req) {
            self.state.cancel_pending(true, &id);
            return Err(e);
        }
        Ok(RequestHandle {
            id,
            rx,
            control: true,
            state: Arc::clone(&self.state),
        })
    }

    /// 注册入站 JSON-RPC 方法 handler（同名重复注册 = 覆盖）。
    pub fn on_request(
        &self,
        method: impl Into<String>,
        handler: impl Fn(&JsonRpcRequest) -> RpcOutcome + Send + Sync + 'static,
    ) {
        let arc: Arc<RpcHandler> = Arc::new(handler);
        self.state
            .handlers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(method.into(), arc);
    }

    /// 注册 control subtype handler；subtype 用其 wire 拼写（`Unknown` 拒绝注册，
    /// 未认领请求走事件队列）。
    pub fn on_control(
        &self,
        subtype: ControlSubtype,
        handler: impl Fn(&ControlRequest) -> RpcOutcome + Send + Sync + 'static,
    ) {
        let key = subtype.as_str();
        if subtype == ControlSubtype::Unknown {
            return; // Unknown 无 wire 拼写可还原，注册它等于死代码。
        }
        let arc: Arc<ControlHandler> = Arc::new(handler);
        self.state
            .control_handlers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, arc);
    }

    /// 对未认领的 control 请求延后应答（事件队列路线的完成回传）。
    ///
    /// # Errors
    /// [`Error::Transport`]：连接已终止或写侧失败。
    pub fn respond_control(
        &self,
        request_id: &RequestId,
        outcome: RpcOutcome,
    ) -> crate::Result<()> {
        self.state.respond_control(request_id, outcome)
    }

    /// 阻塞取下一个事件，最多 `timeout`。
    #[must_use]
    pub fn next_event(&self, timeout: Duration) -> NextEvent {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let mut q = self.state.events.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(ev) = q.pop_front() {
                    return NextEvent::Event(ev);
                }
                if self.state.closed.load(Ordering::Acquire) {
                    return NextEvent::Closed;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return NextEvent::Idle;
                }
                let (guard, _wait) = self
                    .state
                    .event_cv
                    .wait_timeout(q, remaining)
                    .unwrap_or_else(|e| e.into_inner());
                drop(guard);
            }
            // 唤醒或超时后重查队列（wait_timeout 可能虚假唤醒）。
        }
    }

    /// 非阻塞取下一个事件（队列空 → `None`，无论连接是否存活）。
    pub fn poll_event(&self) -> Option<ClientEvent> {
        self.state
            .events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
    }

    /// 连接是否已终止（对端退出/下毒/主动 close）。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state.closed.load(Ordering::Acquire)
    }

    /// 终止原因（若有）。
    #[must_use]
    pub fn closed_reason(&self) -> Option<String> {
        self.state
            .closed_reason
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 事件队列容量上限。
    #[must_use]
    pub fn max_events(&self) -> usize {
        self.state.max_events
    }

    /// 因队列满被丢弃的最旧事件数。
    #[must_use]
    pub fn dropped_event_count(&self) -> u64 {
        self.state.dropped_events.load(Ordering::Acquire)
    }

    /// 畸形帧（字节流仍对齐）计数。
    #[must_use]
    pub fn bad_frame_count(&self) -> u64 {
        self.state.bad_frames.load(Ordering::Acquire)
    }

    /// 未知 id 回执计数（迟到/伪造响应）。
    #[must_use]
    pub fn unknown_id_count(&self) -> u64 {
        self.state.unknown_ids.load(Ordering::Acquire)
    }

    /// 主动拆除：停路由线程 → 关写侧 → 执行传输拆除钩子（一次）。幂等。
    pub fn close(&mut self) {
        self.state.stop.store(true, Ordering::Release);
        {
            let mut sink = self.state.sink.lock().unwrap_or_else(|e| e.into_inner());
            sink.close();
        }
        let handle = self.router.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(h) = handle {
            // 路由线程每 poll_interval 醒一次查 stop，故内置帧源（stdio/mock）下
            // 该 join 有界。代价：自定义 FrameSource 若无视 timeout 一直阻塞，
            // close 会跟着挂住——这是「路由线程独占帧源」换来的确定性。
            let _ = h.join();
        }
        let hook = self
            .teardown
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(mut hook) = hook {
            hook.run();
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}
