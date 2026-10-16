//! 权限门 v0（开工说明 §4）：三态 ask/auto/deny，**默认 deny**。
//!
//! 判定顺序（任何一步命中即返回，后续规则不再放宽）：
//! 1. 工具未注册 → deny；
//! 2. 不在当前模式白名单（白名单缺失视为空集）→ deny；
//! 3. `readonly` 权限模式挡住非只读类别 → deny；
//! 4. 参数命中敏感动作表 → **强制 ask**（即使已显式 auto 放行，不可配置跳过）；
//! 5. 已显式 auto 放行 → allow；
//! 6. 其余 → ask（白名单内但未显式放行，默认要确认）。
//!
//! 审批：`request_approval` 挂起，`wait` 带超时（超时按 deny 语义并清理挂起项），
//! `respond` 一次性应答（重复应答 → `ApprovalAnswered`，未知 id → `ApprovalNotFound`）。
//! 判定说明与审批摘要只含键名/规则名，凭据值绝不回显。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use uuid::Uuid;

use crate::error::CoreError;
use crate::redact::Redactor;
use crate::schema::{ApprovalOutcome, ApprovalRequest, Mode, PermissionMode};
use crate::tool::ToolRegistry;

// 敏感动作规则表由权限门统一出口（调用方无需知道其所在模块）。
pub use crate::sensitive::SensitiveRules;

/// 默认审批超时（§4：120s → deny）。
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

/// 权限判定三态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// 放行。
    Allow,
    /// 需要用户确认（审批）。
    Ask,
    /// 拒绝（携带静态原因，不含参数值）。
    Deny(String),
}

impl Decision {
    /// 判定说明（审计/事件用）：静态构造，不回显任何参数值。
    pub fn explain(&self) -> String {
        match self {
            Decision::Allow => "allow: 白名单内且已显式放行".to_string(),
            Decision::Ask => "ask: 需要用户确认".to_string(),
            Decision::Deny(reason) => format!("deny: {reason}"),
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    pub fn is_ask(&self) -> bool {
        matches!(self, Decision::Ask)
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, Decision::Deny(_))
    }
}

/// 单个审批的应答槽（wait/respond 汇合点）。
#[derive(Default)]
struct SlotState {
    /// 是否已应答（应答后不可重复）。
    answered: bool,
    /// 应答/超时结果；`wait` 取走后置回 `None`。
    outcome: Option<ApprovalOutcome>,
}

struct Slot {
    state: Mutex<SlotState>,
    changed: Condvar,
}

impl Slot {
    fn new() -> Self {
        Self {
            state: Mutex::new(SlotState::default()),
            changed: Condvar::new(),
        }
    }

    /// 已产生的结果（不移除；供应答判重）。
    fn answered(&self) -> bool {
        self.state.lock().map(|s| s.answered).unwrap_or(true)
    }
}

/// 挂起审批的索引项。
struct Pending {
    session_id: String,
    slot: Arc<Slot>,
}

/// 权限门句柄；克隆共享挂起审批集合，策略配置为写时复制。
#[derive(Clone)]
pub struct PermissionGate {
    registry: Arc<ToolRegistry>,
    whitelists: Arc<BTreeMap<Mode, BTreeSet<String>>>,
    auto_allowed: Arc<BTreeSet<String>>,
    rules: SensitiveRules,
    redactor: Redactor,
    approval_timeout: Duration,
    pending: Arc<Mutex<HashMap<Uuid, Pending>>>,
}

impl PermissionGate {
    /// 空策略门：无白名单、无放行集 → 一切工具 deny-by-default。
    pub fn new(registry: ToolRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
            whitelists: Arc::new(BTreeMap::new()),
            auto_allowed: Arc::new(BTreeSet::new()),
            rules: SensitiveRules::v0(),
            redactor: Redactor::default_v0(),
            approval_timeout: DEFAULT_APPROVAL_TIMEOUT,
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 设置某模式的工具白名单（同模式覆盖）。
    #[must_use]
    pub fn with_whitelist(mut self, mode: Mode, allowed: BTreeSet<String>) -> Self {
        Arc::make_mut(&mut self.whitelists).insert(mode, allowed);
        self
    }

    /// 显式 auto 放行某工具（仍受白名单与敏感动作约束）。
    #[must_use]
    pub fn with_auto_allowed(mut self, name: &str) -> Self {
        Arc::make_mut(&mut self.auto_allowed).insert(name.to_string());
        self
    }

    /// 覆盖默认审批超时。
    #[must_use]
    pub fn with_approval_timeout(mut self, timeout: Duration) -> Self {
        self.approval_timeout = timeout;
        self
    }

    /// 工具注册表（网关 `tool:list` 用）。
    pub fn registry(&self) -> Arc<ToolRegistry> {
        Arc::clone(&self.registry)
    }

    /// 某模式的白名单（未配置为空集）。
    pub fn whitelist(&self, mode: Mode) -> BTreeSet<String> {
        self.whitelists.get(&mode).cloned().unwrap_or_default()
    }

    /// 当前审批超时。
    pub fn approval_timeout(&self) -> Duration {
        self.approval_timeout
    }

    /// 三态判定。
    pub fn check(
        &self,
        mode: Mode,
        permission_mode: PermissionMode,
        tool: &str,
        args: &Value,
    ) -> Decision {
        let Some(spec) = self.registry.get(tool) else {
            return Decision::Deny(format!("工具未注册: {tool}"));
        };
        let name = spec.name.clone();
        let kind = spec.kind;
        let scan_arguments = spec.sensitive_arguments;
        let mode_label = mode.as_str();
        if !self
            .whitelists
            .get(&mode)
            .is_some_and(|set| set.contains(&name))
        {
            // deny-by-default：未显式配置该模式白名单即拒（空集同样拒）。
            return Decision::Deny(format!("{tool} 不在 {mode_label} 模式白名单（默认拒绝）"));
        }
        if permission_mode == PermissionMode::ReadOnly && !kind.allowed_when_readonly() {
            return Decision::Deny(format!(
                "readonly 权限模式不允许 {} 类工具: {tool}",
                kind.as_str()
            ));
        }
        if scan_arguments {
            // 敏感动作表命中即强制 ask：放在 auto 判定之前，配置无法跳过。
            if string_values(args)
                .iter()
                .any(|value| self.rules.match_reason(value).is_some())
            {
                return Decision::Ask;
            }
        }
        if self.auto_allowed.contains(&name) {
            return Decision::Allow;
        }
        Decision::Ask
    }

    /// 发起审批：生成挂起请求（摘要已脱敏，不含凭据值）。
    pub fn request_approval(&self, session_id: &str, tool: &str, args: &Value) -> ApprovalRequest {
        let id = Uuid::new_v4();
        let summary = self.redactor.summarize_args(args);
        let reason = format!("{tool} 需要用户确认");
        let expires_at_ms = now_ms().saturating_add(self.approval_timeout.as_millis() as u64);
        let entry = Pending {
            session_id: session_id.to_string(),
            slot: Arc::new(Slot::new()),
        };
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(id, entry);
        }
        ApprovalRequest {
            id,
            session_id: session_id.to_string(),
            tool_name: tool.to_string(),
            summary,
            reason,
            expires_at_ms,
        }
    }

    /// 某会话仍未应答的审批 id（升序）。
    pub fn list_pending(&self, session_id: &str) -> Vec<Uuid> {
        let Ok(pending) = self.pending.lock() else {
            return Vec::new();
        };
        let mut ids: Vec<Uuid> = pending
            .iter()
            .filter(|(_, entry)| entry.session_id == session_id && !entry.slot.answered())
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// 应答审批（一次性）。
    pub fn respond(&self, id: Uuid, approved: bool) -> Result<ApprovalOutcome, CoreError> {
        let slot = {
            let pending = self
                .pending
                .lock()
                .map_err(|_| CoreError::InvalidConfig("审批锁毒化".into()))?;
            let Some(entry) = pending.get(&id) else {
                return Err(CoreError::ApprovalNotFound(id));
            };
            Arc::clone(&entry.slot)
        };
        let outcome = ApprovalOutcome {
            approved,
            timed_out: false,
        };
        {
            let mut state = slot
                .state
                .lock()
                .map_err(|_| CoreError::InvalidConfig("审批槽锁毒化".into()))?;
            if state.answered {
                return Err(CoreError::ApprovalAnswered(id));
            }
            state.answered = true;
            state.outcome = Some(outcome);
        }
        slot.changed.notify_all();
        Ok(outcome)
    }

    /// 等待审批结果，带超时；超时按 deny 语义返回并清理挂起项。
    pub fn wait(&self, id: Uuid, timeout: Duration) -> Result<ApprovalOutcome, CoreError> {
        let slot = {
            let pending = self
                .pending
                .lock()
                .map_err(|_| CoreError::InvalidConfig("审批锁毒化".into()))?;
            let Some(entry) = pending.get(&id) else {
                return Err(CoreError::ApprovalNotFound(id));
            };
            Arc::clone(&entry.slot)
        };
        let deadline = Instant::now() + timeout;
        let mut guard = slot
            .state
            .lock()
            .map_err(|_| CoreError::InvalidConfig("审批槽锁毒化".into()))?;
        loop {
            if let Some(outcome) = guard.outcome.take() {
                drop(guard);
                self.forget(id);
                return Ok(outcome);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                drop(guard);
                self.forget(id);
                return Ok(ApprovalOutcome {
                    approved: false,
                    timed_out: true,
                });
            }
            let (next, _wait_result) = slot
                .changed
                .wait_timeout(guard, remaining)
                .map_err(|_| CoreError::InvalidConfig("审批条件变量毒化".into()))?;
            guard = next;
        }
    }

    /// 挂起审批总数（观测用）。
    pub fn pending_count(&self) -> usize {
        self.pending.lock().map(|p| p.len()).unwrap_or_default()
    }

    fn forget(&self, id: Uuid) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&id);
        }
    }
}

/// 收集 JSON 值里的全部字符串（敏感扫描用；参数规模有限）。
fn string_values(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_strings(value, &mut out);
    out
}

fn collect_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                collect_strings(item, out);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                collect_strings(item, out);
            }
        }
        _ => {}
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}
