//! 会话生命周期：创建、查询、列表、更新与状态迁移。

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use uuid::Uuid;

use crate::error::CoreError;
use crate::schema::{Isolation, Mode, PermissionMode, Session, SessionStatus};

use super::{now_ms, preview, CreateSession, HotSession, Runtime};

impl Runtime {
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
            memory_digest: None,
        };
        // 会话绑定环境时，隔离键 env_id 必须与绑定一致（环境隔离边界）。
        if let Some(env) = &session.env_binding {
            session.isolation.env_id = Some(env.clone());
        }
        // 三层记忆注入（agent-memory-spec §4）：增强项，失败不阻断建会话。
        if self.config.lock().expect("配置锁不得毒化").memory_enabled {
            match self.compose_memory_digest(&session.workspace_root) {
                Ok(digest) => session.memory_digest = Some(digest),
                Err(e) => {
                    self.emit(
                        &session,
                        "warning",
                        json!({ "kind": "memory_compose_failed", "reason": e.to_string() }),
                    )?;
                }
            }
        }
        let id = session.id;
        self.sessions.lock().expect("会话表锁不得毒化").insert(
            id,
            HotSession {
                session: session.clone(),
                drain: Arc::new(Mutex::new(())),
            },
        );
        self.emit(
            &session,
            "session_update",
            json!({ "status": session.status, "title": session.title, "mode": session.mode }),
        )?;
        Ok(session)
    }

    /// 组装记忆摘要（身份恒有；各层前 200 字符预览；总 ≤8000 字符）。
    pub(super) fn compose_memory_digest(&self, workspace_root: &str) -> Result<String, CoreError> {
        use agent_memory::{MemoryEngine, MemoryPaths};
        let engine = MemoryEngine::new(
            MemoryPaths::new(self.workdir.join(".lengsuo"), workspace_root),
            true,
        );
        let bundle = engine
            .compose()
            .map_err(|e| CoreError::InvalidConfig(format!("记忆组装失败: {e}")))?;
        let mut out = String::new();
        out.push_str(&format!(
            "[身份] AI={} 用户={}\n",
            bundle.identity.ai_name, bundle.identity.user_name
        ));
        if !bundle.identity.soul.is_empty() {
            out.push_str(&format!("[人格] {}\n", preview(&bundle.identity.soul, 200)));
        }
        if let Some(m) = &bundle.user_memory {
            out.push_str(&format!("[用户记忆] {}\n", preview(m, 200)));
        }
        if let Some(m) = &bundle.project_memory {
            out.push_str(&format!("[项目记忆] {}\n", preview(m, 200)));
        }
        if let Some(t) = &bundle.daily_tail {
            out.push_str(&format!("[当日日志尾] {}\n", preview(t, 200)));
        }
        Ok(preview(&self.redact(&out), 8000))
    }

    /// 记忆工具执行入口（权限门放行后由宿主调用；每次成功发 memory_update 事件）。
    pub fn execute_memory_tool(
        &self,
        id: Uuid,
        name: &str,
        args: &Value,
    ) -> Result<Value, CoreError> {
        use agent_memory::{MemoryEngine, MemoryPaths};
        let enabled = self.config.lock().expect("配置锁不得毒化").memory_enabled;
        let session = self.get_session(id)?;
        let engine = MemoryEngine::new(
            MemoryPaths::new(self.workdir.join(".lengsuo"), &session.workspace_root),
            enabled,
        );
        let arg = |key: &str| -> Result<String, CoreError> {
            args.get(key)
                .and_then(Value::as_str)
                .map(|text| self.redact(text))
                .ok_or_else(|| CoreError::InvalidConfig(format!("缺少参数 {key}")))
        };
        let kind = match name {
            "memory.append_daily" => {
                let date = chrono::NaiveDate::parse_from_str(&arg("date")?, "%Y-%m-%d")
                    .map_err(|_| CoreError::InvalidConfig("date 非法（YYYY-MM-DD）".into()))?;
                let paths = agent_memory::MemoryPaths::new(
                    self.workdir.join(".lengsuo"),
                    &session.workspace_root,
                );
                if !enabled {
                    return Err(agent_memory::MemoryError::Disabled.into());
                }
                agent_memory::append_daily(&paths, date, &arg("text")?)?;
                "daily_append"
            }
            "memory.set_user" => {
                engine.set_user_memory(&arg("text")?)?;
                "user_memory"
            }
            "memory.set_project" => {
                engine.set_project_memory(&arg("text")?)?;
                "project_memory"
            }
            "identity.set_soul" => {
                engine.set_soul(&arg("text")?)?;
                "soul"
            }
            other => return Err(CoreError::InvalidConfig(format!("未知记忆工具: {other}"))),
        };
        self.emit(&session, "memory_update", json!({ "kind": kind }))?;
        Ok(json!({ "ok": true, "kind": kind }))
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
    ///
    /// 比较完整 `Isolation`（用户/租户/环境），不用 `key()`：后者是
    /// `user_id-tenant_id` 拼接且不含 env，分段歧义会串列表。
    pub fn list_sessions(&self, isolation: &Isolation) -> Vec<Session> {
        let guard = self.sessions.lock().expect("会话表锁不得毒化");
        guard
            .values()
            .filter(|h| &h.session.isolation == isolation)
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
}
