//! seccomp profile 构造（文本/JSON 表达）。
//!
//! 本卡交付：确定性 profile 内容与单元测试断言。
//! TODO(seccomp-apply): 将 profile 编译为 BPF，经 fd 传给 `bwrap --seccomp <fd>`
//! （参照 codex `linux-sandbox/src/seccomp.rs` 的 in-process 应用）——**尚未应用，不得声称已生效**。

use serde_json::{json, Value};

/// profile 默认动作：违反即返回 EPERM（与 codex 的软失败策略一致，不杀进程）。
pub const DEFAULT_ACTION: &str = "SCMP_ACT_ERRNO";

/// 允许的系统调用（排序去重后写入 profile；仅覆盖典型 sh/git/cargo 链路所需最小集）。
pub const ALLOWED_SYSCALLS: &[&str] = &[
    "arch_prctl",
    "brk",
    "clone",
    "close",
    "dup",
    "dup2",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "execve",
    "exit",
    "exit_group",
    "faccessat",
    "fchdir",
    "fcntl",
    "fork",
    "fstat",
    "getcwd",
    "getdents64",
    "getegid",
    "geteuid",
    "getgid",
    "getpgrp",
    "getpid",
    "getppid",
    "getuid",
    "lseek",
    "mkdir",
    "mmap",
    "mprotect",
    "munmap",
    "nanosleep",
    "open",
    "openat",
    "pipe",
    "pipe2",
    "read",
    "readlink",
    "rmdir",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "stat",
    "statfs",
    "uname",
    "unlink",
    "vfork",
    "wait4",
    "write",
];

/// 明确不得出现在 allowlist 的网络类 syscall（网络封禁在 seccomp 层的兜底断言）。
pub const NETWORK_SYSCALLS: &[&str] = &[
    "socket", "connect", "bind", "listen", "sendto", "recvfrom", "sendmsg", "recvmsg",
];

/// 构造 seccomp profile（JSON Value）。输出确定性：syscall 名排序后单组写入。
pub fn linux_seccomp_profile() -> Value {
    let mut names: Vec<&str> = ALLOWED_SYSCALLS.to_vec();
    names.sort_unstable();
    names.dedup();
    json!({
        "defaultAction": DEFAULT_ACTION,
        "defaultErrno": 1, // EPERM
        "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
        "syscalls": [
            {
                "names": names,
                "action": "SCMP_ACT_ALLOW",
            }
        ]
    })
}

/// profile 的字节序列化（供未来 BPF 编译层消费；键序由构造保证确定性）。
pub fn seccomp_profile_bytes() -> Vec<u8> {
    linux_seccomp_profile().to_string().into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_has_deterministic_shape() {
        let v = linux_seccomp_profile();
        assert_eq!(v["defaultAction"], DEFAULT_ACTION);
        assert_eq!(v["defaultErrno"], 1);
        let group = &v["syscalls"][0];
        assert_eq!(group["action"], "SCMP_ACT_ALLOW");
        let names = group["names"].as_array().unwrap();
        // 断言内容而非条数漂移：关键基础调用必在。
        for required in ["read", "write", "openat", "execve", "exit_group"] {
            assert!(
                names.iter().any(|n| n.as_str() == Some(required)),
                "missing {required}"
            );
        }
    }

    #[test]
    fn profile_denies_network_syscalls() {
        let bytes = seccomp_profile_bytes();
        let text = String::from_utf8(bytes).unwrap();
        for net in NETWORK_SYSCALLS {
            let quoted = format!("\"{net}\"");
            assert!(!text.contains(&quoted), "{net} must not be allowlisted");
        }
    }

    #[test]
    fn profile_bytes_are_deterministic() {
        assert_eq!(seccomp_profile_bytes(), seccomp_profile_bytes());
        // 两次构造完全一致（排序去重保证）。
        let mut v2 = linux_seccomp_profile();
        let v1 = linux_seccomp_profile();
        v2["defaultErrno"] = json!(1);
        assert_eq!(v1.to_string(), v2.to_string());
    }
}
