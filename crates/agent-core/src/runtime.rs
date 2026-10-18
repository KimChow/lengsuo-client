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
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use uuid::Uuid;

use crate::blobs::BlobStore;
use crate::bus::EventHub;
use crate::config::RuntimeConfig;
use crate::error::CoreError;
use crate::event_log::{EventLog, JsonlEventLog};
use crate::permission::PermissionGate;
use crate::provider::{Provider, TurnContext};
use crate::redact::Redactor;
use crate::schema::{Event, Isolation, Message, Mode, PermissionMode, Session, SessionStatus};
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
    /// 单队列投递锁：同一会话的回合串行执行，后到的输入不插入进行中的步。
    drain: Arc<Mutex<()>>,
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
}

mod approvals;
mod bus;
mod internals;
mod sessions;
mod turns;

pub(super) fn narrow(text: &str, chars: usize) -> String {
    let mut out: String = text.chars().take(chars).collect();
    if out.chars().count() < text.chars().count() {
        out.push_str("…（截断，完整结果见 result_ref）");
    }
    out
}

mod builder;
pub use builder::RuntimeBuilder;

mod context;

/// 字符级预览截断（≤max 字符，超限加省略标记）。
pub(super) fn preview(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let cut: String = text.chars().take(max).collect();
        format!("{cut}…")
    }
}

pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}
