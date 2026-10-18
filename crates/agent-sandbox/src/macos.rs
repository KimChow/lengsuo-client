//! macOS 骨架：本卡只保证编译通过；seatbelt 由后续卡实现。

use crate::types::{
    CommandSpec, ExecOutcome, SandboxError, SandboxPolicy, SandboxType, SandboxablePreference,
};

/// 平台沙箱探测：macOS 理论上有 seatbelt，但本卡未实现 → 返回 None（fail-closed）。
pub fn get_platform_sandbox() -> Option<SandboxType> {
    // TODO(seatbelt): 探测 /usr/bin/sandbox-exec，实现 seatbelt profile 构造与降级链
    // （对照 codex sandboxing/src/seatbelt.rs）。实现前保持 None，不假装可用。
    None
}

/// 主 API（macOS 桩）。
pub fn run_sandboxed(
    _spec: CommandSpec,
    pref: SandboxablePreference,
    _policy: SandboxPolicy,
) -> Result<ExecOutcome, SandboxError> {
    match pref {
        SandboxablePreference::Require => Err(SandboxError::Unavailable(
            "macos seatbelt sandbox not yet implemented".into(),
        )),
        _ => Err(SandboxError::Unavailable(
            "macos seatbelt sandbox not yet implemented".into(),
        )),
    }
}
