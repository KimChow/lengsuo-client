//! 凭据引用：只含元数据（id、作用域、过期时刻），绝不含明文。
//!
//! `Debug`/`Display` 对 id 与作用域目标恒输出固定掩码，便于安全地写入诊断输出。

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// 掩码文本：不含任何字段值，也不泄露长度。
pub(crate) const REDACTED: &str = "<redacted>";

/// 引用的不透明标识。id 本身可定位具体凭据，因此展示面恒为掩码。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RefId(Uuid);

impl RefId {
    /// 生成新的随机 id（UUIDv4）。
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    /// 由 UUID 构造（用于从加密容器还原）。
    pub const fn from_uuid(inner: Uuid) -> Self {
        Self(inner)
    }

    /// 取回底层 UUID。
    ///
    /// 敏感访问器：可用于关联具体凭据，禁止写入日志、错误信息或 `Debug`。
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for RefId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Debug for RefId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// 作用域类别。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub enum ScopeKind {
    /// 环境隔离键。
    Env,
    /// 会话隔离键。
    Session,
    /// 租户隔离键。
    Tenant,
}

impl ScopeKind {
    /// 稳定短名，用于展示与容器编码。
    pub const fn as_str(&self) -> &'static str {
        match self {
            ScopeKind::Env => "env",
            ScopeKind::Session => "session",
            ScopeKind::Tenant => "tenant",
        }
    }
}

impl fmt::Display for ScopeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 引用作用域：`Env(env_id) | Session(session_id) | Tenant(tenant_id)`。
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Scope {
    /// 绑定某个环境。
    Env(String),
    /// 绑定某个会话。
    Session(String),
    /// 绑定某个租户。
    Tenant(String),
}

impl Scope {
    /// 作用域类别。
    pub const fn kind(&self) -> ScopeKind {
        match self {
            Scope::Env(_) => ScopeKind::Env,
            Scope::Session(_) => ScopeKind::Session,
            Scope::Tenant(_) => ScopeKind::Tenant,
        }
    }

    /// 作用域目标 id。
    ///
    /// 敏感访问器：目标 id 属隔离标识，禁止写入日志或错误信息。
    pub fn target(&self) -> &str {
        match self {
            Scope::Env(value) | Scope::Session(value) | Scope::Tenant(value) => value.as_str(),
        }
    }

    /// 类别与目标是否完全一致（跨类别即使目标字面量相同也不算同作用域）。
    pub fn same_scope(&self, other: &Scope) -> bool {
        self.kind() == other.kind() && self.target() == other.target()
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{REDACTED}", self.kind())
    }
}

impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{REDACTED}", self.kind())
    }
}

/// 凭据引用：id + 作用域 + 过期时刻，永不含明文。
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    id: RefId,
    scope: Scope,
    expires_at_ms: u64,
}

impl CredentialRef {
    /// 由作用域与过期时刻构造，自动分配随机 id。
    pub fn new(scope: Scope, expires_at_ms: u64) -> Self {
        Self {
            id: RefId::generate(),
            scope,
            expires_at_ms,
        }
    }

    /// 以指定 id 构造（用于从加密容器还原，不重新随机）。
    pub fn with_id(id: RefId, scope: Scope, expires_at_ms: u64) -> Self {
        Self {
            id,
            scope,
            expires_at_ms,
        }
    }

    /// 环境作用域引用。
    pub fn env(env_id: impl Into<String>, expires_at_ms: u64) -> Self {
        Self::new(Scope::Env(env_id.into()), expires_at_ms)
    }

    /// 会话作用域引用。
    pub fn session(session_id: impl Into<String>, expires_at_ms: u64) -> Self {
        Self::new(Scope::Session(session_id.into()), expires_at_ms)
    }

    /// 租户作用域引用。
    pub fn tenant(tenant_id: impl Into<String>, expires_at_ms: u64) -> Self {
        Self::new(Scope::Tenant(tenant_id.into()), expires_at_ms)
    }

    /// 引用 id（`RefId` 是 `Copy`，按值返回）。
    pub const fn id(&self) -> RefId {
        self.id
    }

    /// 引用作用域。
    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    /// 过期时刻（unix 毫秒）；达到该时刻即视为过期。
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// 在 `now_ms` 时刻是否已过期。
    pub const fn is_expired_at(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }

    /// 引用是否可安全使用。
    ///
    /// fail-closed 拒绝两类：空作用域目标；目标字节长度超过容器长度域（u16）。
    /// 后者必须在写入前拒绝——截断长度域会让记录解出被污染的回引用。
    pub fn is_valid(&self) -> bool {
        let target = self.scope.target();
        !target.is_empty() && target.len() <= super::container::MAX_TARGET_LEN
    }
}

impl fmt::Debug for CredentialRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CredentialRef {{ id: {REDACTED}, scope: {:?}, expires_at_ms: {} }}",
            self.scope, self.expires_at_ms
        )
    }
}

impl fmt::Display for CredentialRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cred-ref({REDACTED}, {}, expires_at_ms={})",
            self.scope, self.expires_at_ms
        )
    }
}
