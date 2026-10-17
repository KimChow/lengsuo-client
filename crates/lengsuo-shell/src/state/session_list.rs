//! 会话列表视图状态（导航/侧栏供数）。

use std::collections::BTreeMap;

use super::StateError;

/// 会话状态，照协议 §3 的四态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// 正在跑（有在途任务）。
    Running,
    /// 空闲，等待用户输入。
    Idle,
    /// 已完成。
    Done,
    /// 失败。
    Failed,
}

impl SessionStatus {
    /// 解析网关字符串；未知值返回 `None`，由调用方按协议缺口处理（不猜测）。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "running" => Some(Self::Running),
            "idle" => Some(Self::Idle),
            "done" => Some(Self::Done),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// 终态（进入后不再被 `session_update` 改写）。
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed)
    }
}

/// 列表里的一行。`mode`/`env_binding` 用字符串承载，避免与网关枚举定义强耦合。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionListItem {
    /// 会话 id。
    pub id: String,
    /// 标题。
    pub title: String,
    /// 模式名（quick|ask|plan|craft|expert）。
    pub mode: String,
    /// 状态。
    pub status: SessionStatus,
    /// 更新时间（毫秒）。
    pub updated_at_ms: u64,
    /// 环境绑定（v0 预留，可能为空）。
    pub env_binding: Option<String>,
}

/// 会话列表状态。顺序即 UI 顺序：按 `updated_at_ms` 倒序，同值按 id 升序保证确定性。
#[derive(Debug, Clone, Default)]
pub struct SessionListState {
    items: BTreeMap<String, SessionListItem>,
    selected: Option<String>,
}

impl SessionListState {
    /// 空列表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 用 `session:list` 的返回整体替换（不做增量猜测，全量刷新是列表的权威来源）。
    pub fn replace(&mut self, items: Vec<SessionListItem>) {
        self.items = items
            .into_iter()
            .map(|item| (item.id.clone(), item))
            .collect();
        // 选中的会话若已被删掉，选中状态一并清除（不留悬空引用）。
        if let Some(id) = &self.selected {
            if !self.items.contains_key(id) {
                self.selected = None;
            }
        }
    }

    /// 插入或更新一条。终态会话不被更旧的时间戳回退覆盖。
    pub fn upsert(&mut self, item: SessionListItem) -> Result<(), StateError> {
        if let Some(existing) = self.items.get(&item.id) {
            if existing.status.is_terminal() && !item.status.is_terminal() {
                return Err(StateError::Sealed(item.id));
            }
            if existing.updated_at_ms > item.updated_at_ms {
                return Err(StateError::InvalidTransition {
                    phase: format!("{:?}", existing.status),
                    action: "更旧时间戳的 upsert".to_string(),
                });
            }
        }
        self.items.insert(item.id.clone(), item);
        Ok(())
    }

    /// 删除一条（会话被关掉）。
    pub fn remove(&mut self, id: &str) -> Option<SessionListItem> {
        let removed = self.items.remove(id);
        if self.selected.as_deref() == Some(id) {
            self.selected = None;
        }
        removed
    }

    /// 选中一条；不存在则返回 [`StateError::UnknownSession`]，不静默改选。
    pub fn select(&mut self, id: &str) -> Result<(), StateError> {
        if !self.items.contains_key(id) {
            return Err(StateError::UnknownSession(id.to_string()));
        }
        self.selected = Some(id.to_string());
        Ok(())
    }

    /// 当前选中 id。
    #[must_use]
    pub fn selected(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    /// 按 UI 顺序返回行的引用视图。
    #[must_use]
    pub fn ordered(&self) -> Vec<&SessionListItem> {
        let mut rows: Vec<&SessionListItem> = self.items.values().collect();
        rows.sort_by(|a, b| {
            b.updated_at_ms
                .cmp(&a.updated_at_ms)
                .then_with(|| a.id.cmp(&b.id))
        });
        rows
    }

    /// 行数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// 是否空列表。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// 应用一条 `session_update` 事件的状态字段（只改 status/updated_at/mode/env_binding，
    /// 缺失字段保持原值）。会话未知则报错，由上层触发列表全量刷新；
    /// 时间戳严格更旧的事件报错且整行不变（与 [`Self::upsert`] 一致）。
    pub fn apply_update(
        &mut self,
        id: &str,
        status: Option<SessionStatus>,
        updated_at_ms: u64,
        mode: Option<&str>,
        env_binding: Option<Option<&str>>,
    ) -> Result<(), StateError> {
        let item = self
            .items
            .get_mut(id)
            .ok_or_else(|| StateError::UnknownSession(id.to_string()))?;
        if item.status.is_terminal() && status.is_some_and(|s| !s.is_terminal()) {
            return Err(StateError::Sealed(id.to_string()));
        }
        // 活跃时间只前进：与 `upsert` 同款回退保护，更旧事件整行不变。
        if item.updated_at_ms > updated_at_ms {
            return Err(StateError::InvalidTransition {
                phase: format!("{:?}", item.status),
                action: "更旧时间戳的 session_update".to_string(),
            });
        }
        if let Some(status) = status {
            item.status = status;
        }
        if let Some(mode) = mode {
            item.mode = mode.to_string();
        }
        if let Some(env_binding) = env_binding {
            item.env_binding = env_binding.map(str::to_string);
        }
        item.updated_at_ms = updated_at_ms;
        Ok(())
    }

    /// 按 id 取行。
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&SessionListItem> {
        self.items.get(id)
    }
}
