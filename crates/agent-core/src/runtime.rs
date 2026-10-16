//! Runtime：会话/任务热态与回合执行（开工说明 §3/§4/§5）。
//!
//! - 热态是进程内并发表（§5：UI 读取走内存，不做同步磁盘 IO）；
//! - 事件一律经 `EventLog` 落 JSONL 并广播到 `EventHub`（发送端不阻塞）；
//! - 大结果落 `BlobStore`，消息 `content` 只留收窄摘要；
//! - 工具输出与审批摘要进事件流前必须过脱敏器（§4）。
//!
//! 本模块是同步域逻辑（不依赖 tokio）；网关层在自己的运行时里调度。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use uuid::Uuid;

use crate::blobs::BlobStore;
use crate::bus::{EventBus, EventHub};
use crate::config::RuntimeConfig;
use crate::error::CoreError;
use crate::event_log::{EventLog, JsonlEventLog};
use crate::permission::{Decision, PermissionGate};
use crate::provider::{Provider, ProviderStep};
use crate::redact::Redactor;
use crate::schema::{
    ApprovalOutcome, ApprovalRequest, Event, Isolation, Message, Mode, PermissionMode, Role,
    Session, SessionStatus, ToolInfo,
};
use crate::tool::ToolRegistry;

/// `content` 里保留的最大字符数（大结果走 `result_ref`）。
pub const CONTENT_PREVIEW_CHARS: usize = 400;

/// 新建会话入参。
#[derive(Debug, Clone)]
pub struct CreateSession {
    pub title: String,
    pub workspace_root: Option<String>,
    pub mode: Mode,
    pub permission_mode: PermissionMode,
    pub env_binding: Option<String>,
    pub isolation: Isolation,
}

impl CreateSession {
    /// 最简构造（测试与 `session:create` 默认值用）。
    pub fn plain(title: impl Into<String>, isolation: Isolation) -> Self {
        Self {
            title: title.into(),
            workspace_root: None,
            mode: Mode::Ask,
            permission_mode: PermissionMode::ReadOnly,
            env_binding: isolation.env_id.clone(),
            isolation,
        }
    }
}

/// 一个回合的结果（网关 `session:send` 的 data）。
#[derive(Debug, Clone)]
pub struct TurnReceipt {
    pub session_id: Uuid,
    /// 本回合产生的事件（已落盘并广播）。
    pub events: Vec<Event>,
    pub last_seq: u64,
}

/// 会话热态记录。
struct HotSession {
    session: Session,
}

/// 运行时句柄（克隆共享）。
#[derive(Clone)]
pub struct Runtime {
    workdir: PathBuf,
    sessions: Arc<Mutex<BTreeMap<Uuid, HotSession>>>,
    log: Arc<dyn EventLog>,
    blobs: Arc<BlobStore>,
    hub: Arc<EventHub>,
    gate: Arc<PermissionGate>,
    provider: Arc<dyn Provider>,
    redactor: Redactor,
    config: Arc<Mutex<RuntimeConfig>>,
}

impl Runtime {
    pub fn builder() -> RuntimeBuilder {
        RuntimeBuilder::default()
    }

    /// 工作目录（`<workdir>/events`、`<workdir>/blobs`）。
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    /// 权限门（网关 `tool:list` / 审批 RPC 用）。
    pub fn gate(&self) -> &PermissionGate {
        &self.gate
    }

    /// 事件日志（网关回放 RPC 用）。
    pub fn event_log(&self) -> &dyn EventLog {
        self.log.as_ref()
    }

    /// 当前配置快照。
    pub fn config_get(&self) -> RuntimeConfig {
        self.config.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// 应用配置补丁；失败不改现值。
    pub fn config_set(&self, patch: &Value) -> Result<RuntimeConfig, CoreError> {
        let mut guard = self
            .config
            .lock()
            .map_err(|_| CoreError::InvalidConfig("配置锁毒化".into()))?;
        let next = guard.apply_patch(patch)?;
        *guard = next.clone();
        Ok(next)
    }

    // ---------- 会话 CRUD ----------

    /// 创建会话（写 `session_update` 事件）。
    pub fn create_session(&self, input: &CreateSession) -> Result<Session, CoreError> {
        let now = now_ms();
        let mut session = Session {
            id: Uuid::new_v4(),
            title: input.title.clone(),
            workspace_root: input
                .workspace_root
                .clone()
                .unwrap_or_else(|| self.workdir.display().to_string()),
            mode: input.mode,
            permission_mode: input.permission_mode,
            env_binding: input.env_binding.clone(),
            isolation: input.isolation.clone(),
            messages: Vec::new(),
            created_at_ms: now,
            updated_at_ms: now,
            status: SessionStatus::Idle,
            last_seq: 0,
        };
        // 会话绑定环境时，隔离键 env_id 必须与绑定一致（环境隔离边界）。
        if let Some(env) = &session.env_binding {
            session.isolation.env_id = Some(env.clone());
        }
        let id = session.id;
        self.sessions.lock().expect("会话表锁不得毒化").insert(
            id,
            HotSession {
                session: session.clone(),
            },
        );
        self.emit(
            &session,
            "session_update",
            json!({ "status": session.status, "title": session.title, "mode": session.mode }),
        )?;
        Ok(session)
    }

    /// 取会话快照。
    pub fn get_session(&self, id: Uuid) -> Result<Session, CoreError> {
        let guard = self.sessions.lock().expect("会话表锁不得毒化");
        let Some(hot) = guard.get(&id) else {
            return Err(CoreError::SessionNotFound(id));
        };
        Ok(hot.session.clone())
    }

    /// 按隔离键列会话（摘要，不带消息体）。
    pub fn list_sessions(&self, isolation: &Isolation) -> Vec<Session> {
        let key = isolation.key();
        let guard = self.sessions.lock().expect("会话表锁不得毒化");
        guard
            .values()
            .filter(|h| h.session.isolation.key() == key)
            .map(|h| h.session.clone())
            .collect()
    }

    /// 会话摘要列表（网关 `session:list` 的 data）。
    pub fn list_session_summaries(&self, isolation: &Isolation) -> Vec<Value> {
        self.list_sessions(isolation)
            .iter()
            .map(Session::summary)
            .collect()
    }

    /// 更新会话字段（模式/权限模式/标题/环境绑定；`None` 表示不改）。
    pub fn update_session(
        &self,
        id: Uuid,
        title: Option<&str>,
        mode: Option<Mode>,
        permission_mode: Option<PermissionMode>,
        env_binding: Option<Option<&str>>,
    ) -> Result<Session, CoreError> {
        let mut guard = self.sessions.lock().expect("会话表锁不得毒化");
        let Some(hot) = guard.get_mut(&id) else {
            return Err(CoreError::SessionNotFound(id));
        };
        if let Some(title) = title {
            hot.session.title = title.to_string();
        }
        if let Some(mode) = mode {
            hot.session.mode = mode;
        }
        if let Some(pm) = permission_mode {
            hot.session.permission_mode = pm;
        }
        if let Some(env) = env_binding {
            hot.session.env_binding = env.map(str::to_string);
        }
        hot.session.updated_at_ms = now_ms();
        let session = hot.session.clone();
        drop(guard);
        self.emit(
            &session,
            "session_update",
            json!({ "status": session.status, "title": session.title, "mode": session.mode }),
        )?;
        Ok(session)
    }

    /// 停止回合：状态回 idle（不销毁历史）。
    pub fn stop_session(&self, id: Uuid) -> Result<Session, CoreError> {
        self.set_status(id, SessionStatus::Idle)
    }

    /// 结束会话：`done` 后拒绝新输入。
    pub fn finish_session(&self, id: Uuid) -> Result<Session, CoreError> {
        self.set_status(id, SessionStatus::Done)
    }

    /// 标记失败（回合内部错误）。
    pub fn fail_session(&self, id: Uuid) -> Result<Session, CoreError> {
        self.set_status(id, SessionStatus::Failed)
    }

    fn set_status(&self, id: Uuid, status: SessionStatus) -> Result<Session, CoreError> {
        let mut guard = self.sessions.lock().expect("会话表锁不得毒化");
        let Some(hot) = guard.get_mut(&id) else {
            return Err(CoreError::SessionNotFound(id));
        };
        hot.session.status = status;
        hot.session.updated_at_ms = now_ms();
        let session = hot.session.clone();
        drop(guard);
        self.emit(&session, "session_update", json!({ "status": status }))?;
        Ok(session)
    }

    // ---------- 回合 ----------

    /// 发送一条用户输入，跑一个回合（echo provider 下即回显）。
    pub fn send_text(&self, id: Uuid, text: &str) -> Result<TurnReceipt, CoreError> {
        self.push_message(id, Role::User, text.to_string(), None)?;
        self.run_turn(id, text)
    }

    fn run_turn(&self, id: Uuid, text: &str) -> Result<TurnReceipt, CoreError> {
        let session = self.get_session(id)?;
        if matches!(session.status, SessionStatus::Done | SessionStatus::Failed) {
            return Err(CoreError::SessionClosed(id));
        }
        let mut events = Vec::new();
        let steps = self.provider.next_steps(id, text)?;
        for step in steps {
            match step {
                ProviderStep::Thinking(note) => {
                    events.push(self.emit(
                        &session,
                        "thinking",
                        json!({ "text": self.redact(&note) }),
                    )?);
                }
                ProviderStep::Text(reply) => {
                    let reply = self.redact(&reply);
                    events.push(self.emit(&session, "text", json!({ "text": reply }))?);
                    self.push_message(id, Role::Assistant, reply, None)?;
                }
                ProviderStep::ToolCall { name, args } => {
                    let args = self.redactor.redact_json(&args);
                    events.push(self.emit(
                        &session,
                        "tool_use",
                        json!({ "name": name, "args": args }),
                    )?);
                }
                ProviderStep::Finished => {
                    events.push(self.emit(&session, "done", json!({}))?);
                }
            }
        }
        let current = self.get_session(id)?;
        let last_seq = current.last_seq;
        Ok(TurnReceipt {
            session_id: id,
            events,
            last_seq,
        })
    }

    /// 记录一次工具结果：大输出进 blob，消息只留摘要（§3 防分页打爆）。
    pub fn record_tool_result(
        &self,
        id: Uuid,
        tool: &str,
        args: Value,
        result: &str,
    ) -> Result<Message, CoreError> {
        let args = self.redactor.redact_json(&args);
        let args_ref = self
            .blobs
            .put(args.to_string().as_bytes())
            .map(|r| r.0)
            .ok();
        let raw = self.redactor.redact_str(result);
        let (preview, result_ref) = if raw.chars().count() > CONTENT_PREVIEW_CHARS {
            let blob = self.blobs.put(raw.as_bytes())?;
            (narrow(&raw, CONTENT_PREVIEW_CHARS), Some(blob.0))
        } else {
            (raw.clone(), None)
        };
        let message = Message {
            role: Role::ToolResult,
            content: preview.clone(),
            tool: Some(ToolInfo {
                name: tool.to_string(),
                args_ref,
                result_ref: result_ref.clone(),
                ms: None,
            }),
            ts_ms: now_ms(),
        };
        let session = self.push_message(
            id,
            Role::ToolResult,
            preview,
            Some(message.tool.clone().expect("刚构造")),
        )?;
        self.emit(
            &session,
            "tool_result",
            json!({ "name": tool, "chars": raw.chars().count(), "resultRef": result_ref, "preview": message.content }),
        )?;
        Ok(message)
    }

    /// 追加工具调用消息（权限门放行后由宿主调用）。
    pub fn record_tool_call(
        &self,
        id: Uuid,
        tool: &str,
        args: &Value,
    ) -> Result<Session, CoreError> {
        let args = self.redactor.redact_json(args);
        let args_ref = self
            .blobs
            .put(args.to_string().as_bytes())
            .map(|r| r.0)
            .ok();
        let summary = self.redactor.summarize_args(&args);
        self.push_message(
            id,
            Role::ToolCall,
            summary,
            Some(ToolInfo {
                name: tool.to_string(),
                args_ref,
                result_ref: None,
                ms: None,
            }),
        )
    }

    /// 权限判定（工具执行前的唯一入口）。
    pub fn check_tool(&self, id: Uuid, tool: &str, args: &Value) -> Result<Decision, CoreError> {
        let session = self.get_session(id)?;
        if matches!(session.status, SessionStatus::Done | SessionStatus::Failed) {
            return Err(CoreError::SessionClosed(id));
        }
        Ok(self
            .gate
            .check(session.mode, session.permission_mode, tool, args))
    }

    /// 发起审批（挂起；超时按 deny）。
    pub fn request_approval(
        &self,
        id: Uuid,
        tool: &str,
        args: &Value,
    ) -> Result<ApprovalRequest, CoreError> {
        let session = self.get_session(id)?;
        Ok(self
            .gate
            .request_approval(&session.isolation.key(), tool, args))
    }

    /// 应答审批（`approval:respond`）。
    pub fn respond_approval(
        &self,
        approval_id: Uuid,
        approved: bool,
    ) -> Result<ApprovalOutcome, CoreError> {
        self.gate.respond(approval_id, approved)
    }

    /// 阻塞等待审批结果（网关在 spawn_blocking 里调用）。
    pub fn wait_approval(
        &self,
        approval_id: Uuid,
        timeout: Duration,
    ) -> Result<ApprovalOutcome, CoreError> {
        self.gate.wait(approval_id, timeout)
    }

    /// 某会话隔离键下挂起的审批。
    pub fn pending_approvals(&self, session_id: Uuid) -> Vec<Uuid> {
        let Ok(session) = self.get_session(session_id) else {
            return Vec::new();
        };
        self.gate.list_pending(&session.isolation.key())
    }

    /// 事件回放（`seq > after_seq`）。
    pub fn replay(
        &self,
        session_id: Uuid,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<Event>, CoreError> {
        self.log.replay(session_id, after_seq, limit)
    }

    /// 订阅指定隔离键的事件流（网关 WS 用）。
    pub fn subscribe(&self, isolation_key: &str) -> crate::bus::Subscription {
        self.hub.bus(isolation_key).subscribe()
    }

    /// 总线句柄（观测/测试）。
    pub fn bus(&self, isolation_key: &str) -> EventBus {
        self.hub.bus(isolation_key)
    }

    /// 已登记会话 id（内存热态）。
    pub fn session_ids(&self) -> Vec<Uuid> {
        let guard = self.sessions.lock().expect("会话表锁不得毒化");
        guard.keys().copied().collect()
    }

    // ---------- 内部 ----------

    fn push_message(
        &self,
        id: Uuid,
        role: Role,
        content: String,
        tool: Option<ToolInfo>,
    ) -> Result<Session, CoreError> {
        let mut guard = self.sessions.lock().expect("会话表锁不得毒化");
        let Some(hot) = guard.get_mut(&id) else {
            return Err(CoreError::SessionNotFound(id));
        };
        if matches!(
            hot.session.status,
            SessionStatus::Done | SessionStatus::Failed
        ) {
            return Err(CoreError::SessionClosed(id));
        }
        hot.session.messages.push(Message {
            role,
            content,
            tool,
            ts_ms: now_ms(),
        });
        hot.session.updated_at_ms = now_ms();
        Ok(hot.session.clone())
    }

    /// 落盘 + 广播一条事件（脱敏后）。
    fn emit(&self, session: &Session, kind: &str, payload: Value) -> Result<Event, CoreError> {
        let payload = self.redactor.redact_json(&payload);
        let event = self.log.append(session.id, kind, payload)?;
        if let Ok(mut guard) = self.sessions.lock() {
            if let Some(hot) = guard.get_mut(&session.id) {
                hot.session.last_seq = hot.session.last_seq.max(event.seq);
                hot.session.updated_at_ms = now_ms();
            }
        }
        self.hub
            .bus(&session.isolation.key())
            .publish(event.clone());
        Ok(event)
    }

    fn redact(&self, text: &str) -> String {
        self.redactor.redact_str(text)
    }
}

fn narrow(text: &str, chars: usize) -> String {
    let mut out: String = text.chars().take(chars).collect();
    if out.chars().count() < text.chars().count() {
        out.push_str("…（截断，完整结果见 result_ref）");
    }
    out
}

/// 运行时构造器。
#[derive(Default)]
pub struct RuntimeBuilder {
    workdir: Option<PathBuf>,
    provider: Option<Arc<dyn Provider>>,
    gate: Option<PermissionGate>,
    config: Option<RuntimeConfig>,
}

impl RuntimeBuilder {
    #[must_use]
    pub fn workdir(mut self, path: impl AsRef<Path>) -> Self {
        self.workdir = Some(path.as_ref().to_path_buf());
        self
    }

    #[must_use]
    pub fn provider(mut self, provider: Arc<dyn Provider>) -> Self {
        self.provider = Some(provider);
        self
    }

    #[must_use]
    pub fn gate(mut self, gate: PermissionGate) -> Self {
        self.gate = Some(gate);
        self
    }

    #[must_use]
    pub fn config(mut self, config: RuntimeConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// 组装：事件日志与 blob 目录建在 workdir 下；启动回放恢复 seq 与会话索引。
    pub fn build(self) -> Result<Runtime, CoreError> {
        let workdir = self
            .workdir
            .unwrap_or_else(|| std::env::temp_dir().join("lengsuo-agent-runtime"));
        std::fs::create_dir_all(&workdir).map_err(|e| CoreError::Io {
            path: workdir.clone(),
            source: e,
        })?;
        let log: Arc<dyn EventLog> = Arc::new(JsonlEventLog::open(workdir.join("events"))?);
        let gate = self
            .gate
            .unwrap_or_else(|| PermissionGate::new(ToolRegistry::new()));
        let provider = self
            .provider
            .ok_or_else(|| CoreError::InvalidConfig("Runtime 必须注入 provider".into()))?;
        let mut sessions: BTreeMap<Uuid, HotSession> = BTreeMap::new();
        // 启动回放：恢复既有会话的 seq 锚点（消息历史 v0 从事件重建为最小集）。
        for id in log.sessions() {
            let last_seq = log.last_seq(id).unwrap_or_default();
            let title = replay_title(&log, id);
            sessions.insert(
                id,
                HotSession {
                    session: Session {
                        id,
                        title,
                        workspace_root: workdir.display().to_string(),
                        mode: Mode::Ask,
                        permission_mode: PermissionMode::ReadOnly,
                        env_binding: None,
                        isolation: Isolation::local_default(),
                        messages: Vec::new(),
                        created_at_ms: now_ms(),
                        updated_at_ms: now_ms(),
                        status: SessionStatus::Idle,
                        last_seq,
                    },
                },
            );
        }
        Ok(Runtime {
            workdir: workdir.clone(),
            sessions: Arc::new(Mutex::new(sessions)),
            log,
            blobs: Arc::new(BlobStore::new(workdir.join("blobs"))),
            hub: Arc::new(EventHub::new()),
            gate: Arc::new(gate),
            provider,
            redactor: Redactor::default_v0(),
            config: Arc::new(Mutex::new(
                self.config.unwrap_or_else(RuntimeConfig::default_v0),
            )),
        })
    }
}

/// 从事件回放里取最近一次标题（重启后 `session:list` 仍能显示标题）。
fn replay_title(log: &Arc<dyn EventLog>, id: Uuid) -> String {
    let events = log.replay(id, 0, 500).unwrap_or_default();
    for event in events.iter().rev() {
        if event.kind == "session_update" {
            if let Some(title) = event.payload.get("title").and_then(Value::as_str) {
                return title.to_string();
            }
        }
    }
    format!("会话 {id}")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}
