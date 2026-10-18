//! 跨平台沙箱类型层：平台枚举、偏好、命令规格、执行结果与错误（语义照抄 codex `protocol/src/sandbox.rs` 与
//! `sandboxing/src/manager.rs`，命名按 D4 拍板冻结）。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// 标识某条命令最终选择的沙箱实现（对照 codex `SandboxType`）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SandboxType {
    /// 不沙箱执行。
    #[default]
    None,
    /// macOS seatbelt（本卡仅骨架，TODO）。
    MacosSeatbelt,
    /// Linux bubblewrap + seccomp。
    LinuxSeccomp,
    /// Windows 受限令牌（本卡 fail-closed 桩）。
    WindowsRestrictedToken,
    /// Windows MXC（本卡 fail-closed 桩）。
    WindowsMxc,
}

impl SandboxType {
    /// 指标/日志用短标签。
    pub fn as_metric_tag(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MacosSeatbelt => "seatbelt",
            Self::LinuxSeccomp => "seccomp",
            Self::WindowsRestrictedToken => "windows_restricted_token",
            Self::WindowsMxc => "windows_mxc",
        }
    }
}

/// 沙箱偏好（对照 codex `SandboxablePreference`）：
/// `Auto` = 能沙箱则沙箱，否则按策略降级；`Require` = 沙箱不可用则拒绝（fail-closed）；
/// `Forbid` = 明确不沙箱执行。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SandboxablePreference {
    #[default]
    Auto,
    Require,
    Forbid,
}

/// 网络模式：默认封网（fail-closed）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkMode {
    #[default]
    Blocked,
    Allow,
}

impl NetworkMode {
    /// 是否需要为命令创建独立网络命名空间。
    pub fn should_unshare_network(self) -> bool {
        matches!(self, Self::Blocked)
    }
}

/// 待执行的命令请求。`env` 是请求方提供的派生进程环境候选；构造层负责按白名单清洗（R8）。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSpec {
    /// 可执行文件路径。
    pub program: PathBuf,
    /// 透传给 program 的参数。
    pub args: Vec<String>,
    /// 请求上下文环境（构造时只透传白名单键）。
    pub env: Vec<(String, String)>,
    /// 工作目录；None 表示沿用当前目录语义由平台层决定。
    pub cwd: Option<PathBuf>,
    /// 可读写绑定根（安全基线路径会在构造时被剔除并遮蔽）。
    pub writable_roots: Vec<PathBuf>,
    /// 只读绑定根。
    pub read_only_roots: Vec<PathBuf>,
    /// 网络模式。
    pub network: NetworkMode,
}

/// 退出状态的可序列化投影（ExitStatus-like；`signal` 仅 Unix 平台有值）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecStatus {
    /// 正常退出码；被信号终止时为 None。
    pub code: Option<i32>,
    /// 进程终止信号编号（非 Unix 恒为 None）。
    pub signal: Option<i32>,
    /// 是否成功退出。
    pub success: bool,
}

/// 沙箱执行结果。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecOutcome {
    /// 退出状态。
    pub status: ExecStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// 实际生效的沙箱类型。
    pub sandbox: SandboxType,
}

/// 沙箱策略：无沙箱时 `Auto` 偏好是否允许转人工审批。默认 `false`（fail-closed）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Auto 且平台沙箱不可用时，是否返回 `NeedsApproval` 转人工审批。
    pub allow_approval_fallback: bool,
}

/// 沙箱分发层错误。
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// 沙箱按偏好/平台要求必须存在但不可用（Require 降级失败、Windows 桩等）。
    #[error("sandbox unavailable: {0}")]
    Unavailable(String),
    /// 策略拒绝（如无沙箱且未开审批降级）。
    #[error("denied by sandbox policy: {0}")]
    Denied(String),
    /// Auto 降级链末端：需要转人工审批，调用方据此发起审批流程。
    #[error("command requires manual approval: {0}")]
    NeedsApproval(String),
    /// IO 错误。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// 进程 spawn 失败。
    #[error("spawn failed: {0}")]
    Spawn(String),
}
