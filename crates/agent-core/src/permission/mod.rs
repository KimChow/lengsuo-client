//! 权限门（开工说明 §4 + 权限精简设计）：三态 ask/auto/deny，**默认 deny**。
//!
//! 判定顺序（工具级门保持短路，资源级门/沙箱门在其后叠加）：
//! 1. 工具未注册 → deny；
//! 2. 不在当前模式白名单（白名单缺失视为空集）→ deny；
//! 3. `readonly` 权限模式挡住非只读类别 → deny；
//! 4. 参数命中敏感动作表 → **强制 ask**（即使已显式 auto 放行，不可配置跳过，
//!    资源级门与沙箱门均不越过此步）；
//! 5. 已显式 auto 放行 → allow（工具级结论）；其余 → ask；
//! 6. 资源级门（agent-execpolicy）：工具调用派生 `AccessRequest[]`，
//!    - phase1：任一请求在**配置层**（项目/会话策略 + 内置安全基线）命中 deny → deny；
//!    - phase2：全部请求在 **saved 层 + 配置层 + 内置基线**（层序：saved 在前 = 后层覆盖）
//!      都命中 allow → allow；否则维持工具级结论（deny 可收紧，全 allow 可放宽，不升级）。
//! 7. 沙箱优先门（wb A22-1）：命令执行类工具结论为 ask 且沙箱后端可用
//!    → allow（跳过人工审批；执行层沙箱失败时自行降级回审批链）。
//!
//! 审批：`request_approval` 挂起，`wait` 带超时（超时按 deny 语义并清理挂起项），
//! `respond` 一次性应答（重复应答 → `ApprovalAnswered`，未知 id → `ApprovalNotFound`）。
//! 判定说明与审批摘要只含键名/规则名，凭据值绝不回显。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use uuid::Uuid;

use agent_execpolicy::Policy;

use crate::redact::Redactor;
use crate::schema::{Mode, PermissionMode};
use crate::tool::{ToolKind, ToolRegistry};

mod approval;
mod resource;

use approval::Pending;

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

/// 权限门句柄；克隆共享挂起审批集合，策略配置为写时复制。
#[derive(Clone)]
pub struct PermissionGate {
    registry: Arc<ToolRegistry>,
    whitelists: Arc<BTreeMap<Mode, BTreeSet<String>>>,
    auto_allowed: Arc<BTreeSet<String>>,
    /// 配置层策略（项目/会话，按添加顺序生效，首个命中优先）；
    /// 内置安全基线恒在其后隐式追加（不落字段，判定时拼接）。
    configured: Arc<Vec<Policy>>,
    /// saved 层（用户「永久允许」）：排在配置层之前，phase2 生效、phase1 deny 检查不生效。
    saved: Arc<Vec<Policy>>,
    /// 注入式沙箱后端探测（测试/宿主接线用）：`Some(非空后端名)` 视为可沙箱。
    sandbox_probe: Option<Arc<dyn Fn() -> Option<String> + Send + Sync>>,
    rules: SensitiveRules,
    redactor: Redactor,
    approval_timeout: Duration,
    pending: Arc<Mutex<HashMap<Uuid, Pending>>>,
}

impl PermissionGate {
    /// 空策略门：无白名单、无放行集 → 一切工具 deny-by-default。
    /// 资源级判定仍带内置安全基线（`.ssh/**`、`.gnupg/**` deny 等）。
    pub fn new(registry: ToolRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
            whitelists: Arc::new(BTreeMap::new()),
            auto_allowed: Arc::new(BTreeSet::new()),
            configured: Arc::new(Vec::new()),
            saved: Arc::new(Vec::new()),
            sandbox_probe: None,
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

    /// 追加一层配置策略（项目/会话层；按调用顺序即层序，首个命中优先）。
    #[must_use]
    pub fn with_policy(mut self, policy: Policy) -> Self {
        Arc::make_mut(&mut self.configured).push(policy);
        self
    }

    /// 追加一条 saved「永久允许」策略：插到 saved 层最前（最新覆盖旧层）。
    /// 只影响 phase2（allow/ask 汇总），不影响 phase1 deny 检查。
    #[must_use]
    pub fn with_saved_policy(mut self, policy: Policy) -> Self {
        Arc::make_mut(&mut self.saved).insert(0, policy);
        self
    }

    /// 注入沙箱后端探测：返回 `Some(后端名)` 视为可沙箱（沙箱优先门生效前提）。
    #[must_use]
    pub fn with_sandbox_probe<F>(mut self, probe: F) -> Self
    where
        F: Fn() -> Option<String> + Send + Sync + 'static,
    {
        self.sandbox_probe = Some(Arc::new(probe));
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

    /// 三态判定：工具级门（短路）→ 资源级门（两阶段汇总）→ 沙箱优先门。
    pub fn check(
        &self,
        mode: Mode,
        permission_mode: PermissionMode,
        tool: &str,
        args: &Value,
    ) -> Decision {
        // ---- 工具级门 1–3：未注册/白名单/readonly，原样短路 ----
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
        // ---- 工具级门 4：敏感动作强制 ask（不可配置跳过，后续门不越过）----
        if scan_arguments
            && string_values(args)
                .iter()
                .any(|value| self.rules.match_reason(value).is_some())
        {
            return Decision::Ask;
        }
        // ---- 工具级门 5–6：auto → allow，其余 → ask（资源级门的底案）----
        let tool_verdict = if self.auto_allowed.contains(&name) {
            Decision::Allow
        } else {
            Decision::Ask
        };
        // ---- 资源级门：工具调用 → AccessRequest[] → execpolicy 两阶段汇总 ----
        let requests = resource::access_requests(kind, args);
        if !requests.is_empty() {
            if let Some(reason) = resource::configured_deny(&self.configured, &requests) {
                return Decision::Deny(reason);
            }
            if resource::all_allowed(&self.saved, &self.configured, &requests) {
                return Decision::Allow;
            }
        }
        // ---- 沙箱优先门（A22-1）：可沙箱的命令执行类跳过人工审批 ----
        if tool_verdict.is_ask() && matches!(kind, ToolKind::Exec) && self.sandbox_probe_active() {
            return Decision::Allow;
        }
        tool_verdict
    }

    fn sandbox_probe_active(&self) -> bool {
        self.sandbox_probe
            .as_ref()
            .and_then(|probe| probe())
            .is_some_and(|backend| !backend.is_empty())
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
