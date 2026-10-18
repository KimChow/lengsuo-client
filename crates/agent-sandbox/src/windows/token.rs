//! 受限令牌构造（windows-sys FFI，仅 `cfg(windows)` 编译）。
//!
//! 构造参数**照抄** 参考实现 `windows-sandbox-rs/src/token.rs:455-525`：
//! `flags = DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED`，
//! `entries = [caps…, extra_restricting…, logon, Everyone]`（顺序即语义），
//! 后处理 `set_default_dacl(logon_sid)` + `enable_single_privilege("SeChangeNotifyPrivilege")`。
//!
//! TODO(design §6)：caps（AppContainer capability）与 extra_restricting 本期均为空——
//! entries 只放 logon + Everyone；Elevated 专用 sandbox 账户不做。

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, HANDLE, HLOCAL, LUID};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, SetEntriesInAclW, EXPLICIT_ACCESS_W, GRANT_ACCESS, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, CreateRestrictedToken, CreateWellKnownSid, GetTokenInformation,
    LookupPrivilegeValueW, SetTokenInformation, TokenDefaultDacl, TokenGroups, TokenUser,
    WinWorldSid, ACL, DISABLE_MAX_PRIVILEGE, LUA_TOKEN, PSID, SE_PRIVILEGE_ENABLED,
    SID_AND_ATTRIBUTES, TOKEN_ALL_ACCESS, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_PRIVILEGES,
    WRITE_RESTRICTED,
};
use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::construct::to_utf16_nul;
use crate::types::SandboxError;

/// `CreateRestrictedToken` 的 SID 顺序即语义（参考实现 token.rs:481）。
/// TODO(design §6)：caps 与 extra_restricting 本期为空，未来按
/// `[caps…, extra_restricting…, logon, Everyone]` 插入。
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
/// `GENERIC_ALL`（参考实现 token.rs:45；windows-sys 未导出该名）。
const GENERIC_ALL: u32 = 0x1000_0000;
/// SID 固定头长度：Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6)。
const SID_HEADER_LEN: usize = 8;
/// 特权名：跳过遍历重解析点。项目位于 OneDrive 下，不开会让重解析目录全 0x80070091（design §3.5）。
const SE_CHANGE_NOTIFY_PRIVILEGE: &str = "SeChangeNotifyPrivilege";

/// 拥有所有权的令牌句柄：`Drop` 时 `CloseHandle`。
pub struct OwnedToken(HANDLE);

impl OwnedToken {
    /// 裸句柄（借用语义；生命周期由 `OwnedToken` 保证）。
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// 失败一律映射为 [`SandboxError::Spawn`]（沙箱无法建立 → 调用方 fail-closed 处理）。
fn last_error(what: &str) -> SandboxError {
    let code = unsafe { GetLastError() };
    win32_error(what, code)
}

fn win32_error(what: &str, code: u32) -> SandboxError {
    SandboxError::Spawn(format!(
        "windows restricted token: {what} failed (Win32 {code})"
    ))
}

/// 基础令牌：`OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS)`（design §3.1）。
///
/// 受限令牌从当前用户令牌派生，无需登录别的账户。
pub fn open_current_token() -> Result<OwnedToken, SandboxError> {
    let mut handle: HANDLE = std::ptr::null_mut();
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut handle) };
    if ok == 0 {
        return Err(last_error("OpenProcessToken"));
    }
    Ok(OwnedToken(handle))
}

/// 两段式查询 token information（先探长度，再取数据）。
fn query_token_info(
    token: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
) -> Result<Vec<u8>, SandboxError> {
    let mut needed: u32 = 0;
    unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(last_error("GetTokenInformation(size)"));
    }
    let mut buffer = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(last_error("GetTokenInformation"));
    }
    buffer.truncate(needed as usize);
    Ok(buffer)
}

/// 从 token information 缓冲中复制一个 SID：校验指针落在缓冲内、revision = 1、长度不越界。
///
/// # Safety
/// `psid` 必须来自 `buffer` 内部（Windows 返回的 token information 布局保证）。
unsafe fn copy_sid_from_buffer(buffer: &[u8], psid: PSID) -> Result<Vec<u8>, SandboxError> {
    let offset = (psid as usize)
        .checked_sub(buffer.as_ptr() as usize)
        .ok_or_else(|| win32_error("copy_sid", 0))?;
    let header = buffer
        .get(offset..offset + SID_HEADER_LEN)
        .ok_or_else(|| win32_error("copy_sid(header)", 0))?;
    if header[0] != 1 {
        return Err(win32_error("copy_sid(revision)", 0));
    }
    let len = SID_HEADER_LEN + usize::from(header[1]) * 4;
    let bytes = buffer
        .get(offset..offset + len)
        .ok_or_else(|| win32_error("copy_sid(len)", 0))?;
    Ok(bytes.to_vec())
}

/// 当前用户 SID（`TokenUser`）字节——deny ACE 的受托者（design §3.6）。
pub fn token_user_sid_bytes(token: HANDLE) -> Result<Vec<u8>, SandboxError> {
    let buffer = query_token_info(token, TokenUser)?;
    if buffer.len() < std::mem::size_of::<SID_AND_ATTRIBUTES>() {
        return Err(win32_error("TokenUser(short)", 0));
    }
    let entry: SID_AND_ATTRIBUTES = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast()) };
    unsafe { copy_sid_from_buffer(&buffer, entry.Sid) }
}

/// Everyone（World）SID 字节。
fn world_sid_bytes() -> Result<Vec<u8>, SandboxError> {
    let mut size: u32 = 0;
    unsafe {
        CreateWellKnownSid(
            WinWorldSid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if size == 0 {
        return Err(last_error("CreateWellKnownSid(size)"));
    }
    let mut buffer = vec![0u8; size as usize];
    let ok = unsafe {
        CreateWellKnownSid(
            WinWorldSid,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if ok == 0 {
        return Err(last_error("CreateWellKnownSid"));
    }
    buffer.truncate(size as usize);
    Ok(buffer)
}

/// Logon SID 字节（`TokenGroups` 中带 `SE_GROUP_LOGON_ID` 属性的组）。
///
/// 必须保留进 entries：否则桌面/管道全断（design §3.2）。参考实现 在缺失时还会回退查
/// `TokenLinkedToken`——本 crate 不做提权账户，直接报错（fail-closed）。
pub fn logon_sid_bytes(token: HANDLE) -> Result<Vec<u8>, SandboxError> {
    let buffer = query_token_info(token, TokenGroups)?;
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    let stride = std::mem::size_of::<SID_AND_ATTRIBUTES>();
    let count = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
    for index in 0..count {
        let at = offset + index * stride;
        let Some(raw) = buffer.get(at..at + stride) else {
            break;
        };
        let entry: SID_AND_ATTRIBUTES = unsafe { std::ptr::read_unaligned(raw.as_ptr().cast()) };
        if entry.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID {
            return unsafe { copy_sid_from_buffer(&buffer, entry.Sid) };
        }
    }
    Err(win32_error("logon SID not present on token", 0))
}

/// 用 `ConvertStringSidToSidW` 分配的 SID，`Drop` 时 `LocalFree`。
struct LocalSid(PSID);

impl LocalSid {
    fn from_string(sid: &str) -> Result<Self, SandboxError> {
        let wide = to_utf16_nul(sid);
        let mut psid: PSID = std::ptr::null_mut();
        let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut psid) };
        if ok == 0 || psid.is_null() {
            return Err(last_error("ConvertStringSidToSidW"));
        }
        Ok(Self(psid))
    }

    fn as_ptr(&self) -> PSID {
        self.0
    }
}

impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn explicit_access(sid: PSID, access: u32) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: access,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: 0,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast(),
        },
    }
}

#[repr(C)]
struct TokenDefaultDaclInfo {
    default_dacl: *mut ACL,
}

/// 新对象的默认 DACL 只授权 logon SID（自研 token.rs:56-112），
/// 防止继承过宽的父 DACL；附加 `S-1-3-4`（OWNER RIGHTS）只给 `READ_CONTROL`，
/// 抑制对象所有者的隐式 `WRITE_DAC`。
unsafe fn set_default_dacl(token: HANDLE, logon_sid: PSID) -> Result<(), SandboxError> {
    let owner_rights = LocalSid::from_string("S-1-3-4")?;
    let entries = [
        explicit_access(logon_sid, GENERIC_ALL),
        explicit_access(owner_rights.as_ptr(), READ_CONTROL),
    ];
    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    let code = SetEntriesInAclW(
        entries.len() as u32,
        entries.as_ptr(),
        std::ptr::null_mut(),
        &mut new_dacl,
    );
    if code != windows_sys::Win32::Foundation::ERROR_SUCCESS {
        return Err(win32_error("SetEntriesInAclW(default dacl)", code));
    }
    let mut info = TokenDefaultDaclInfo {
        default_dacl: new_dacl,
    };
    let info_ptr = std::ptr::from_mut(&mut info).cast::<c_void>().cast_const();
    let ok = SetTokenInformation(
        token,
        TokenDefaultDacl,
        info_ptr,
        std::mem::size_of::<TokenDefaultDaclInfo>() as u32,
    );
    let result = if ok == 0 {
        Err(last_error("SetTokenInformation(TokenDefaultDacl)"))
    } else {
        Ok(())
    };
    if !new_dacl.is_null() {
        LocalFree(new_dacl as HLOCAL);
    }
    result
}

/// 打开单个特权（自研 token.rs:339-368）。
///
/// `AdjustTokenPrivileges` 成功返回后仍须查 `GetLastError`——它可能只调整了部分特权。
unsafe fn enable_single_privilege(token: HANDLE, name: &str) -> Result<(), SandboxError> {
    let name_wide = to_utf16_nul(name);
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let ok = LookupPrivilegeValueW(std::ptr::null(), name_wide.as_ptr(), &mut luid);
    if ok == 0 {
        return Err(last_error("LookupPrivilegeValueW"));
    }
    let mut privileges: TOKEN_PRIVILEGES = std::mem::zeroed();
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    let ok = AdjustTokenPrivileges(
        token,
        0,
        &privileges,
        0,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    if ok == 0 {
        return Err(last_error("AdjustTokenPrivileges"));
    }
    let code = GetLastError();
    if code != 0 {
        return Err(win32_error("AdjustTokenPrivileges(partial)", code));
    }
    Ok(())
}

/// 构造受限令牌（design §3.2–§3.5）：
/// `entries = [logon, Everyone]`（caps/extra_restricting 本期为空），全部 `Attributes = 0`；
/// `flags = DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED`；
/// 随后 `set_default_dacl(logon)` + 开 `SeChangeNotifyPrivilege`。
pub fn create_restricted_token(base: HANDLE) -> Result<OwnedToken, SandboxError> {
    let mut logon = logon_sid_bytes(base)?;
    let mut everyone = world_sid_bytes()?;
    let logon_ptr: PSID = logon.as_mut_ptr().cast();
    let everyone_ptr: PSID = everyone.as_mut_ptr().cast();
    let entries = [
        SID_AND_ATTRIBUTES {
            Sid: logon_ptr,
            Attributes: 0,
        },
        SID_AND_ATTRIBUTES {
            Sid: everyone_ptr,
            Attributes: 0,
        },
    ];

    let flags = DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED;
    let mut new_token: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        CreateRestrictedToken(
            base,
            flags,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            entries.len() as u32,
            entries.as_ptr(),
            &mut new_token,
        )
    };
    if ok == 0 {
        return Err(last_error("CreateRestrictedToken"));
    }
    // 后处理失败必须销毁令牌，避免泄漏半个沙箱令牌。
    let token = OwnedToken(new_token);
    unsafe {
        set_default_dacl(token.raw(), logon_ptr)?;
        enable_single_privilege(token.raw(), SE_CHANGE_NOTIFY_PRIVILEGE)?;
    }
    Ok(token)
}

/// 干跑探测（design §4）：真建一次受限令牌再销毁；成功即表示本机可用受限令牌沙箱。
///
/// 不返回令牌本身——探测只回答"能不能"，避免调用方误用未配套 ACL 的令牌。
pub fn probe_create_restricted_token() -> bool {
    let Ok(base) = open_current_token() else {
        return false;
    };
    create_restricted_token(base.raw()).is_ok()
}
