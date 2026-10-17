//! 任务看板：内存任务表 + 会话索引（规格冻结点：方法签名与 JSON 字段名）。

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use uuid::Uuid;

use crate::error::TaskError;
use crate::task::{Task, TaskStatus};

/// 可注入时钟（Unix 毫秒）；确定性测试用固定值，避免时间抖动。
pub type NowMs = fn() -> u64;

/// 会话内任务看板。纯内存，不落盘；持久化由上层会话存储负责（对照 参照平台
/// 「任务存内存 + 会话存储」）。
#[derive(Debug, Clone)]
pub struct TaskBoard {
    tasks: HashMap<Uuid, Task>,
    /// 会话索引：session_id → 该会话的任务 id 列表。
    by_session: HashMap<Uuid, Vec<Uuid>>,
    now: NowMs,
}

impl Default for TaskBoard {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskBoard {
    /// 使用系统时钟新建看板。
    pub fn new() -> Self {
        Self::with_clock(system_now_ms)
    }

    /// 使用注入时钟新建看板（测试用，保证时间戳确定）。
    pub fn with_clock(now: NowMs) -> Self {
        Self {
            tasks: HashMap::new(),
            by_session: HashMap::new(),
            now,
        }
    }

    /// 创建任务：subject 去空白后非空，初始状态 `pending`。
    pub fn create(
        &mut self,
        session_id: Uuid,
        subject: &str,
        description: &str,
    ) -> Result<Task, TaskError> {
        if subject.trim().is_empty() {
            return Err(TaskError::EmptySubject);
        }
        let now_ms = (self.now)();
        let task = Task {
            id: Uuid::new_v4(),
            session_id,
            subject: subject.to_string(),
            description: description.to_string(),
            status: TaskStatus::default(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        };
        self.tasks.insert(task.id, task.clone());
        self.by_session.entry(session_id).or_default().push(task.id);
        Ok(task)
    }

    pub fn get(&self, id: Uuid) -> Result<&Task, TaskError> {
        self.tasks.get(&id).ok_or(TaskError::NotFound)
    }

    /// 状态迁移：同状态幂等返回当前任务；非法迁移报 `InvalidTransition`；
    /// `done`/`cancelled` 为终态，不可再出。
    pub fn update_status(&mut self, id: Uuid, to: TaskStatus) -> Result<Task, TaskError> {
        let task = self.tasks.get_mut(&id).ok_or(TaskError::NotFound)?;
        if task.status == to {
            return Ok(task.clone());
        }
        if !task.status.can_transition(to) {
            return Err(TaskError::InvalidTransition {
                from: task.status,
                to,
            });
        }
        task.status = to;
        task.updated_at_ms = (self.now)();
        Ok(task.clone())
    }

    /// 更新文本：给出的 subject 不得为空白；字段未变化则不刷新 updated_at_ms。
    pub fn update_text(
        &mut self,
        id: Uuid,
        subject: Option<&str>,
        description: Option<&str>,
    ) -> Result<Task, TaskError> {
        if let Some(subject) = subject {
            if subject.trim().is_empty() {
                return Err(TaskError::EmptySubject);
            }
        }
        let task = self.tasks.get_mut(&id).ok_or(TaskError::NotFound)?;
        let mut changed = false;
        if let Some(subject) = subject {
            if task.subject != subject {
                task.subject = subject.to_string();
                changed = true;
            }
        }
        if let Some(description) = description {
            if task.description != description {
                task.description = description.to_string();
                changed = true;
            }
        }
        if changed {
            task.updated_at_ms = (self.now)();
        }
        Ok(task.clone())
    }

    /// 会话内任务列表：按 created_at_ms 升序；同毫秒按 id 升序，保证顺序可复现。
    pub fn list_by_session(&self, session_id: Uuid) -> Vec<&Task> {
        let Some(ids) = self.by_session.get(&session_id) else {
            return Vec::new();
        };
        let mut items: Vec<&Task> = ids.iter().filter_map(|id| self.tasks.get(id)).collect();
        items.sort_by(|a, b| {
            a.created_at_ms
                .cmp(&b.created_at_ms)
                .then_with(|| a.id.cmp(&b.id))
        });
        items
    }

    /// 任务的 JSON 表示；字段名与状态字符串冻结（轨道 E 直接依赖）。
    pub fn to_json(&self, id: Uuid) -> Result<Value, TaskError> {
        let task = self.get(id)?;
        serde_json::to_value(task).map_err(|e| TaskError::Json(e.to_string()))
    }
}

fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}
