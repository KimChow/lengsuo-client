//! 启动层的失败类型。
//!
//! **全部 fail-closed**：任何一条失败路径都意味着「不启动」或「启动失败后
//! 立即回收进程」，绝不允许降级成「没有代理的裸连」。
//!
//! 错误里**不得**出现代理口令、用户名或任何凭据明文：本 crate 的错误只
//! 携带种类、计数与阶段，调用方要写日志时直接用 `Display` 即可。

use std::io::ErrorKind;

use lengsuo_browser_lifecycle::LifecycleError;

/// 代理配置的失败原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProxyError {
    /// 至少要有一个代理端点，空配置会让浏览器**直连**，这是不允许的。
    #[error("代理配置没有任何端点")]
    NoEndpoint,
    /// 同一种 scheme 出现了两次，后写的会覆盖先写的 ⇒ 拒绝。
    #[error("同一 scheme 重复配置代理端点")]
    DuplicateScheme,
    /// 主机名含非法字符（含空白、`@`、`/` 等）。
    #[error("代理主机名非法")]
    InvalidHost,
    /// 端口为 0 或超出 u16。
    #[error("代理端口非法")]
    InvalidPort,
    /// 凭据的用户名或口令为空。
    #[error("代理凭据不完整")]
    EmptyCredential,
    /// 绕过列表条目含非法字符。
    #[error("代理绕过列表条目非法")]
    InvalidBypass,
}

/// 浏览器启动层的失败原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LaunchError {
    /// 浏览器包/可执行文件缺失。**不降级**：没有浏览器就没有隔离。
    #[error("浏览器可执行文件缺失（fail-closed，不得降级为裸连）")]
    BinaryMissing,
    /// 路径存在但不是普通文件（目录、管道等）。
    #[error("浏览器可执行文件不是一个普通文件")]
    BinaryNotAFile,
    /// 环境身份非法（不是 ASCII 标识符）。
    #[error("环境身份非法：{0}")]
    InvalidEnvironment(&'static str),
    /// 代理配置非法。
    #[error("代理配置非法：{0}")]
    Proxy(#[from] ProxyError),
    /// 启动参数非法。
    #[error("启动参数非法：{0}")]
    Argument(&'static str),
    /// 渲染后的命令行里出现了凭据材料 ⇒ 拒绝启动。
    #[error("命令行中出现凭据材料，拒绝启动")]
    CredentialLeak,
    /// 用户数据目录已经被本 Launcher 下的另一次启动占用 ⇒ 环境隔离被破坏。
    #[error("用户数据目录已被另一次启动占用，拒绝共享")]
    UserDataDirInUse,
    /// 就绪探测超时（含总预算）。
    #[error("就绪探测超时（预算 {budget_ms} ms）")]
    ProbeTimeout {
        /// 本次探测的总预算（毫秒）。
        budget_ms: u64,
    },
    /// 浏览器在就绪之前就退出了。
    #[error("浏览器在就绪探测完成前退出")]
    ExitedBeforeReady,
    /// 进程启动失败。
    #[error("启动浏览器进程失败：{kind:?}")]
    SpawnFailed {
        /// 底层 I/O 错误种类（不含路径、不含任何命令行内容）。
        kind: ErrorKind,
    },
    /// 进程回收失败。
    #[error("回收浏览器进程失败：{kind:?}")]
    ReapFailed {
        /// 底层 I/O 错误种类。
        kind: ErrorKind,
    },
    /// 拿不到可用的进程身份（PID 为 0 或进程已消失）。
    #[error("拿不到可用的进程身份")]
    IdentityUnavailable,
    /// 生命周期状态机拒绝了本次启动。
    #[error("生命周期状态机拒绝了本次启动：{0}")]
    Lifecycle(#[from] LifecycleError),
    /// 附带的环境配置（profile）不合法。
    #[error("环境配置不合法：{0}")]
    ProfileInvalid(String),
    /// 目录准备失败。
    #[error("准备用户数据目录失败：{kind:?}")]
    Io {
        /// 底层 I/O 错误种类。
        kind: ErrorKind,
    },
}

impl LaunchError {
    /// 稳定短标签，适合写进结构化日志字段。
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BinaryMissing => "launch:binary_missing",
            Self::BinaryNotAFile => "launch:binary_not_file",
            Self::InvalidEnvironment(_) => "launch:environment",
            Self::Proxy(_) => "launch:proxy",
            Self::Argument(_) => "launch:argument",
            Self::CredentialLeak => "launch:credential_leak",
            Self::UserDataDirInUse => "launch:dir_in_use",
            Self::ProbeTimeout { .. } => "launch:probe_timeout",
            Self::ExitedBeforeReady => "launch:exited_early",
            Self::SpawnFailed { .. } => "launch:spawn_failed",
            Self::ReapFailed { .. } => "launch:reap_failed",
            Self::IdentityUnavailable => "launch:identity",
            Self::Lifecycle(_) => "launch:lifecycle",
            Self::ProfileInvalid(_) => "launch:profile",
            Self::Io { .. } => "launch:io",
        }
    }
}
