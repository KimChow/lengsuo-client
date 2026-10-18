//! 受限令牌下的进程启动与输出捕获（windows-sys FFI，仅 `cfg(windows)` 编译）。
//!
//! 自研 `windows-sandbox-rs/src/process.rs:104-203` 的调用形状：
//! `lpApplicationName = null`（可执行文件由命令行首项解析）、`bInheritHandles = TRUE`、
//! `CREATE_UNICODE_ENVIRONMENT`、stdout/stderr 走匿名管道 + 读线程 + `WaitForSingleObject`。
//!
//! 与 参考实现 的差异（本期取最小版）：
//! - **不建 Job Object**（design §3.7：参考实现 基础路径亦未依赖它）；进程树/资源限额留 TODO(§6)；
//! - 不做 `ProcThreadAttributeList` handle 白名单与 `lpDesktop` 设置——后者 参考实现 是为
//!   PowerShell 在受限令牌下 `STATUS_DLL_INIT_FAILED` 而加；若本机冒烟遇到再补（见卡报告）。
//!
//! ⚠ **待本机验证**（design §7）：`CreateProcessAsUserW` 对「从自身令牌派生的受限令牌」
//! 是否需要 `SE_ASSIGNPRIMARYTOKEN_NAME`。文档要求该特权，但同 logon 会话下普通用户实践可用。
//! 若失败，退化路径为 `CreateProcessWithTokenW`（需 `SE_IMPERSONATE`）。

use std::ffi::c_void;
use std::thread;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetExitCodeProcess, WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT,
    INFINITE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

use super::construct::{build_command_line, build_env_block, to_utf16_nul};
use crate::types::{CommandSpec, ExecOutcome, ExecStatus, SandboxError, SandboxType};

/// 读管道缓冲大小（与 参考实现 `process.rs:350` 一致）。
const READ_CHUNK: usize = 8192;

fn last_error(what: &str) -> SandboxError {
    let code = unsafe { GetLastError() };
    SandboxError::Spawn(format!(
        "windows restricted token: {what} failed (Win32 {code})"
    ))
}

/// 拥有所有权的句柄：`Drop` 时 `CloseHandle`；[`OwnedHandle::into_raw`] 交出所有权。
struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }

    /// 放弃所有权，返回裸句柄（调用方负责关闭）。
    fn into_raw(mut self) -> HANDLE {
        let handle = self.0;
        self.0 = std::ptr::null_mut();
        handle
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// 匿名管道两端（非继承创建；子进程侧句柄随后单独置为可继承）。
struct PipePair {
    read: OwnedHandle,
    write: OwnedHandle,
}

impl PipePair {
    fn create() -> Result<Self, SandboxError> {
        let mut read: HANDLE = std::ptr::null_mut();
        let mut write: HANDLE = std::ptr::null_mut();
        if unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) } == 0 {
            return Err(last_error("CreatePipe"));
        }
        Ok(Self {
            read: OwnedHandle(read),
            write: OwnedHandle(write),
        })
    }
}

/// 后台读句柄直到 EOF，返回读到的全部字节；结束时关闭句柄。
fn spawn_reader(handle: OwnedHandle) -> thread::JoinHandle<Vec<u8>> {
    let raw = handle.into_raw() as usize;
    thread::spawn(move || {
        let handle = raw as HANDLE;
        let mut collected = Vec::new();
        let mut buffer = [0u8; READ_CHUNK];
        loop {
            let mut read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || read == 0 {
                break;
            }
            collected.extend_from_slice(&buffer[..read as usize]);
        }
        unsafe { CloseHandle(handle) };
        collected
    })
}

/// 在受限令牌下启动 `spec`，等待退出并捕获 stdout/stderr（env 由调用方按 R8 清洗后传入）。
pub fn spawn_and_wait(
    token: HANDLE,
    spec: &CommandSpec,
    env: &[(String, String)],
) -> Result<ExecOutcome, SandboxError> {
    // 命令行必须可变：CreateProcessAsUserW 可能就地改写该缓冲。
    let mut cmdline = to_utf16_nul(&build_command_line(&spec.program, &spec.args));
    let env_block = build_env_block(env);
    let cwd = spec
        .cwd
        .as_ref()
        .map(|path| to_utf16_nul(&path.to_string_lossy()));
    let cwd_ptr = cwd.as_ref().map_or(std::ptr::null(), |wide| wide.as_ptr());

    let stdin = PipePair::create()?;
    let stdout = PipePair::create()?;
    let stderr = PipePair::create()?;

    // 只有子进程侧的三个句柄需要可继承；父进程侧保持不可继承，避免句柄泄漏进子进程。
    for handle in [stdin.read.raw(), stdout.write.raw(), stderr.write.raw()] {
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(last_error("SetHandleInformation"));
        }
    }

    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = stdin.read.raw();
    startup.hStdOutput = stdout.write.raw();
    startup.hStdError = stderr.write.raw();

    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessAsUserW(
            token,
            std::ptr::null(),
            cmdline.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_UNICODE_ENVIRONMENT,
            env_block.as_ptr().cast::<c_void>(),
            cwd_ptr,
            &startup,
            &mut info,
        )
    };
    if ok == 0 {
        return Err(last_error("CreateProcessAsUserW"));
    }
    let process = OwnedHandle(info.hProcess);
    let thread_handle = OwnedHandle(info.hThread);

    // 关掉父进程侧的写端与 stdin 读端：子进程读 stdin 立刻见 EOF，
    // stdout/stderr 的读端在子进程退出并关闭写端后自然 EOF。
    drop(stdin.write);
    drop(stdin.read);
    drop(stdout.write);
    drop(stderr.write);

    // 必须先起读线程再 Wait：管道缓冲写满会让子进程阻塞在写，形成死锁。
    let stdout_reader = spawn_reader(stdout.read);
    let stderr_reader = spawn_reader(stderr.read);

    let waited = unsafe { WaitForSingleObject(process.raw(), INFINITE) };
    if waited != WAIT_OBJECT_0 {
        return Err(last_error("WaitForSingleObject"));
    }
    let stdout_bytes = stdout_reader.join().unwrap_or_default();
    let stderr_bytes = stderr_reader.join().unwrap_or_default();

    let mut exit_code: u32 = 0;
    if unsafe { GetExitCodeProcess(process.raw(), &mut exit_code) } == 0 {
        return Err(last_error("GetExitCodeProcess"));
    }
    drop(thread_handle);

    Ok(ExecOutcome {
        status: ExecStatus {
            code: Some(exit_code as i32),
            signal: None,
            success: exit_code == 0,
        },
        stdout: stdout_bytes,
        stderr: stderr_bytes,
        sandbox: SandboxType::WindowsRestrictedToken,
    })
}
