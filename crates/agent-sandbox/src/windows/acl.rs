//! 凭据目录的 deny-read ACL（windows-sys FFI，仅 `cfg(windows)` 编译）。
//!
//! 照抄 codex `windows-sandbox-rs/src/acl.rs:1005-1016` 的思路：
//! `SetEntriesInAclW` 把新建的 deny ACE 排在 allow ACE **之前**，满足 Windows
//! 「deny 优先」的判定顺序；ACE 带 `CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE`，
//! 覆盖此后在该目录下新建的对象。
//!
//! ## ⚠ 副作用（务必知悉）
//! 本期没有专用 sandbox 账户（design §1：不做 Elevated），deny ACE 的受托者是**当前用户 SID**
//! 本身，而受限令牌仍保留该 SID。因此这条 ACE 对**用户自己的普通进程同样生效**——
//! 加过之后，交互式用户自己也读不了 `%USERPROFILE%\.ssh`，且本卡**不做撤销**
//! （codex 的 deny_read_state.rs 有生命周期管理，我们只取最小版）。
//! 这是 design §3.6「token_user; DENY; FILE_GENERIC_READ」的直接后果，已列入报告遗留项；
//! 正式启用前需要专用账户/Elevated 或「退出时撤销」的 journal。
//!
//! TODO(design §6)：不做递归 walker（codex `deny_read_walker.rs` 全套约 50KB），
//! 只 deny 目录本身；深层渗透留人工审批。

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, GENERIC_READ, HLOCAL};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, DENY_ACCESS, EXPLICIT_ACCESS_W,
    SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE, PSID,
};
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;

use super::construct::to_utf16_nul;
use crate::types::SandboxError;

/// deny 掩码：`FILE_GENERIC_READ | GENERIC_READ`（codex `acl.rs:847` 的 `DenyAceKind::Read`）。
///
/// design §3.6 只写 `FILE_GENERIC_READ`；codex 另加 `GENERIC_READ` 以覆盖泛型读取请求，照抄 codex。
const DENY_READ_MASK: u32 = FILE_GENERIC_READ | GENERIC_READ;

fn win32_error(what: &str, code: u32) -> SandboxError {
    SandboxError::Spawn(format!(
        "windows restricted token: {what} failed (Win32 {code})"
    ))
}

/// 给 `path` 的 DACL 加一条 `(sid; DENY; FILE_GENERIC_READ | GENERIC_READ)` 继承 ACE。
///
/// 返回 `true` 表示本次真的写入了新 ACE；`false` 表示 ACE 数未变（近似幂等，重复运行不叠加）。
///
/// # Safety
/// `sid` 必须是有效的 SID 指针（本卡传当前用户 SID），且 `path` 必须存在。
pub fn add_deny_read_ace(path: &Path, sid: PSID) -> Result<bool, SandboxError> {
    let wide = to_utf16_nul(&path.to_string_lossy());
    let mut old_dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: *mut c_void = std::ptr::null_mut();
    let code = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old_dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(win32_error("GetNamedSecurityInfoW", code));
    }
    // null DACL = 隐式全放行；在它上面只写一条 deny ACE 会把目录变成除本用户外全部拒绝，
    // 语义不可控 → fail-closed 报错，交由上层转人工审批。
    if old_dacl.is_null() {
        unsafe { LocalFree(descriptor as HLOCAL) };
        return Err(win32_error("GetNamedSecurityInfoW(null DACL)", 0));
    }

    let explicit = EXPLICIT_ACCESS_W {
        grfAccessPermissions: DENY_READ_MASK,
        grfAccessMode: DENY_ACCESS,
        grfInheritance: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast(),
        },
    };
    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    let code = unsafe { SetEntriesInAclW(1, &explicit, old_dacl, &mut new_dacl) };
    if code != ERROR_SUCCESS || new_dacl.is_null() {
        unsafe { LocalFree(descriptor as HLOCAL) };
        return Err(win32_error("SetEntriesInAclW(deny read)", code));
    }

    // 近似幂等：ACE 数未变说明同一条 deny 已在（不做逐条扫描，避免搬 codex 的 1.1k 行 acl.rs）。
    let changed = unsafe { (*new_dacl).AceCount != (*old_dacl).AceCount };
    let result = if changed {
        let code = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                new_dacl,
                std::ptr::null_mut(),
            )
        };
        if code == ERROR_SUCCESS {
            Ok(true)
        } else {
            Err(win32_error("SetNamedSecurityInfoW", code))
        }
    } else {
        Ok(false)
    };

    unsafe {
        LocalFree(new_dacl as HLOCAL);
        LocalFree(descriptor as HLOCAL);
    }
    result
}

/// 对一批路径逐条加 deny-read ACE：不存在的路径跳过（本来不可见），
/// 其余失败一律 fail-closed 返回 `Err`（绝不静默放过凭据目录）。
///
/// 返回本次真正写入 ACE 的路径列表（供日志/报告）。
pub fn apply_deny_acls(paths: &[PathBuf], sid: PSID) -> Result<Vec<PathBuf>, SandboxError> {
    let mut applied = Vec::new();
    for path in paths {
        if !path.exists() {
            continue;
        }
        if add_deny_read_ace(path, sid)? {
            applied.push(path.clone());
        }
    }
    Ok(applied)
}
