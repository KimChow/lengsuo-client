//! 安全基线（对照 参考端 tsbx 规则形态 + R8 环境清洗）：
//! - 凭据目录 deny 全操作：路径中出现 `.ssh` / `.gnupg` 组件即拒绝，连读取都不允许；
//! - 包管理器缓存目录允许读写绑定（开发链路可用）；
//! - 派生进程 env 只透传白名单（先清洗请求上下文再注入）。

use std::path::{Component, Path};

/// 组件级 denylist 基名：路径分量命中 `<基名>`、`.<基名>` 或 `.<基名>-…` 变体即视为凭据路径
/// （参考端 基线的 .ssh/**、.gnupg/** 两段；`ssh-lib` 这类项目目录不误伤）。
pub const DENY_PATH_COMPONENTS: &[&str] = &["ssh", "gnupg"];

/// 包管理器/工具链缓存目录名（相对家目录），允许读写绑定。
/// 对照 参考端 基线：Node/npm、Rust（.cargo/.rustup）、Go（go-build）、Python、Java、通用 .cache。
pub const CACHE_DIR_NAMES: &[&str] = &[
    ".cargo",
    ".rustup",
    ".npm",
    ".cache",
    ".m2",
    ".gradle",
    ".cache/go-build",
    "go/pkg/mod",
];

/// env 透传白名单（R8：请求上下文里的其他键一律不进入沙箱/派生进程）。
pub const ENV_PASSLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// 判断路径是否命中凭据 denylist（组件等于 `ssh`/`gnupg`，或以其为前缀的点目录 `.ssh*`/`.gnupg*`）。
pub fn is_denied_path(path: &Path) -> bool {
    path.components().any(|c| match c {
        Component::Normal(name) => {
            let name = name.to_string_lossy();
            DENY_PATH_COMPONENTS
                .iter()
                .any(|d| name.as_ref() == *d || (name.starts_with('.') && name[1..].starts_with(d)))
        }
        _ => false,
    })
}

/// 过滤出可安全透传的环境变量（保持请求顺序；重复键保留首次出现）。
pub fn env_passlist(env: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in env {
        if ENV_PASSLIST.contains(&k.as_str()) && !out.iter().any(|(ek, _)| ek == k) {
            out.push((k.clone(), v.clone()));
        }
    }
    out
}

/// 列出家目录下的缓存根（绝对路径），供上层组装 writable_roots。
/// 纯路径函数，不做存在性检查（探测/绑定由 linux.rs 在运行时完成）。
pub fn cache_roots_for_home(home: &Path) -> Vec<std::path::PathBuf> {
    CACHE_DIR_NAMES.iter().map(|d| home.join(d)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn denies_dot_ssh_and_dot_gnupg_any_depth() {
        assert!(is_denied_path(&PathBuf::from("/home/u/.ssh")));
        assert!(is_denied_path(&PathBuf::from("/home/u/.ssh/id_ed25519")));
        assert!(is_denied_path(&PathBuf::from(
            "/home/u/.gnupg/private-keys-v1.d/k.key"
        )));
        // 无点前缀的同名组件也拒绝（fail-closed 从严）。
        assert!(is_denied_path(&PathBuf::from("/data/ssh/config")));
        // 后缀扩展的点目录（如 .ssh-config）同样命中前缀规则。
        assert!(is_denied_path(&PathBuf::from("/home/u/.ssh-keys")));
    }

    #[test]
    fn allows_ordinary_and_cache_paths() {
        assert!(!is_denied_path(&PathBuf::from("/home/u/.cargo/registry")));
        assert!(!is_denied_path(&PathBuf::from("/home/u/.cache/go-build")));
        assert!(!is_denied_path(&PathBuf::from("/home/u/projects/ssh-lib")));
        assert!(!is_denied_path(&PathBuf::from("/tmp/workspace")));
    }

    #[test]
    fn env_passlist_filters_and_dedupes_in_order() {
        let req = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "sk".to_string()),
            ("SSH_AUTH_SOCK".to_string(), "/tmp/s".to_string()),
            ("HOME".to_string(), "/home/u".to_string()),
            ("PATH".to_string(), "/dup".to_string()),
        ];
        assert_eq!(
            env_passlist(&req),
            vec![
                ("PATH".to_string(), "/usr/bin".to_string()),
                ("HOME".to_string(), "/home/u".to_string()),
            ]
        );
    }

    #[test]
    fn cache_roots_under_home() {
        let roots = cache_roots_for_home(Path::new("/home/u"));
        assert!(roots.contains(&PathBuf::from("/home/u/.cargo")));
        assert!(roots.contains(&PathBuf::from("/home/u/.rustup")));
        assert!(roots.contains(&PathBuf::from("/home/u/.cache/go-build")));
        assert!(roots.contains(&PathBuf::from("/home/u/go/pkg/mod")));
        assert!(roots.iter().all(|p| !is_denied_path(p)));
    }
}
