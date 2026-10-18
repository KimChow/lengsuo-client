//! Windows fail-closed 桩：仅做 CreateRestrictedToken 可用性的只读探测；
//! `run_sandboxed` 一律 `Err(Unavailable)`，不得假装已实现（真实沙箱由后续卡交付）。

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

use crate::types::{
    CommandSpec, ExecOutcome, SandboxError, SandboxPolicy, SandboxType, SandboxablePreference,
};

/// 只读探测：advapi32 是否导出 CreateRestrictedToken（不加载新库、不调用任何沙箱 API）。
///
/// # Safety
/// `GetModuleHandleW`/`GetProcAddress` 是受 WinAPI 契约保证的只读查询；
/// 传入静态 UTF-16 缓冲与静态 ASCII 函数名，不释放任何句柄，解引用仅限返回指针非空分支。
pub fn restricted_token_available() -> bool {
    const ADVAPI32: &[u16] = &[
        b'a' as u16,
        b'd' as u16,
        b'v' as u16,
        b'a' as u16,
        b'p' as u16,
        b'i' as u16,
        b'3' as u16,
        b'2' as u16,
        b'.' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        0,
    ];
    const FUNC: &[u8] = b"CreateRestrictedToken\0";
    let module: HMODULE = unsafe { GetModuleHandleW(ADVAPI32.as_ptr()) };
    if module.is_null() {
        return false;
    }
    let proc = unsafe { GetProcAddress(module, FUNC.as_ptr()) };
    proc.is_some()
}

/// 平台沙箱探测：restricted token 可用也只表示底层 API 在——本卡没有任何 Windows 沙箱实现，
/// 因此恒返回 None（fail-closed；`WindowsRestrictedToken`/`WindowsMxc` 留给后续卡接线）。
pub fn get_platform_sandbox() -> Option<SandboxType> {
    // TODO(windows): 后续卡在此返回 Some(WindowsRestrictedToken)（或按 MXC 可用性返回
    // WindowsMxc），并实现命令转换与降级链。实现前即使探测成功也保持 None，不假装可用。
    let _ = restricted_token_available();
    None
}

/// 主 API（Windows 桩）：一律拒绝。
pub fn run_sandboxed(
    _spec: CommandSpec,
    _pref: SandboxablePreference,
    _policy: SandboxPolicy,
) -> Result<ExecOutcome, SandboxError> {
    Err(SandboxError::Unavailable(
        "windows sandbox not yet implemented".into(),
    ))
}
