//! 网关握手文件解析：`gateway.json`（`{port, pid, token}`）。
//!
//! 协议（AGENT-KICKOFF.md §2）：网关监听 `127.0.0.1` 随机端口，启动时写握手
//! 文件，token 启动时生成、退出即失效。本模块只负责**读与校验**，不做任何网络
//! IO；token 只驻留内存，禁止出现在 `Debug`/错误信息/日志里（AGENTS.md §3）。

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// 已校验的握手内容。`Debug` 对 token 脱敏。
#[derive(Clone, Eq, PartialEq)]
pub struct GatewayHandshake {
    /// 网关监听端口（127.0.0.1 上的随机端口）。
    pub port: u16,
    /// 网关进程 pid，仅做存在性记录，v0 不做存活探测。
    pub pid: u32,
    /// 鉴权 token。只驻留内存，不落盘副本、不进日志。
    pub token: String,
}

impl fmt::Debug for GatewayHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayHandshake")
            .field("port", &self.port)
            .field("pid", &self.pid)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl GatewayHandshake {
    /// 从指定路径读取并校验握手文件。
    ///
    /// 校验失败一律 fail-closed：文件缺失、JSON 非法、字段缺失/越界、
    /// token 为空都会返回 [`HandshakeError`]，不存在回退默认值的路径。
    pub async fn load(path: &Path) -> Result<Self, HandshakeError> {
        let text = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| HandshakeError::io(path, e))?;
        Self::parse(&text, path)
    }

    /// 从字符串解析并校验；`path` 仅用于错误信息归因。
    pub fn parse(text: &str, path: &Path) -> Result<Self, HandshakeError> {
        let raw: RawHandshake =
            serde_json::from_str(text).map_err(|e| HandshakeError::Invalid {
                path: path.display().to_string(),
                reason: format!("JSON 解析失败：{e}"),
            })?;
        let port = raw.port.ok_or_else(|| invalid(path, "缺少 port"))?;
        if port == 0 {
            return Err(invalid(path, "port 为 0，不是有效监听端口"));
        }
        let pid = raw.pid.ok_or_else(|| invalid(path, "缺少 pid"))?;
        if pid == 0 {
            return Err(invalid(path, "pid 为 0，不是有效进程号"));
        }
        let token = raw.token.ok_or_else(|| invalid(path, "缺少 token"))?;
        if token.is_empty() {
            return Err(invalid(path, "token 为空"));
        }
        Ok(Self { port, pid, token })
    }

    /// v0 默认路径：`%LOCALAPPDATA%/lengsuo/gateway.json`（Windows），
    /// 其余平台回退 `$XDG_DATA_HOME/lengsuo/gateway.json` 或
    /// `~/.local/share/lengsuo/gateway.json`。环境变量缺失且无 home 时返回 `None`。
    pub fn default_path() -> Option<PathBuf> {
        if let Ok(dir) = std::env::var("LOCALAPPDATA") {
            return Some(PathBuf::from(dir).join("lengsuo").join("gateway.json"));
        }
        let base = match std::env::var("XDG_DATA_HOME") {
            Ok(dir) if Path::new(&dir).is_absolute() => PathBuf::from(dir),
            _ => std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".local").join("share"))?,
        };
        Some(base.join("lengsuo").join("gateway.json"))
    }
}

/// `gateway.json` 的宽松中间形态：字段可选，缺失统一报 `Invalid` 而非 serde 报错，
/// 保证错误信息里不含 token 相关内容。
#[derive(Deserialize)]
struct RawHandshake {
    port: Option<u16>,
    pid: Option<u32>,
    token: Option<String>,
}

fn invalid(path: &Path, reason: &str) -> HandshakeError {
    HandshakeError::Invalid {
        path: path.display().to_string(),
        reason: reason.to_string(),
    }
}

/// 握手文件读取/校验错误。错误信息只含路径与原因，不含 token。
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// 文件不存在。
    #[error("网关握手文件不存在：{path}")]
    NotFound {
        /// 出错的文件路径。
        path: String,
    },
    /// 其他 IO 错误（权限、磁盘等）。
    #[error("读取网关握手文件失败：{path}")]
    Io {
        /// 出错的文件路径。
        path: String,
        /// 底层 IO 错误。
        source: std::io::Error,
    },
    /// 内容非法：JSON 错误或字段校验失败，一律拒绝。
    #[error("网关握手文件非法：{path}（{reason}）")]
    Invalid {
        /// 出错的文件路径。
        path: String,
        /// 具体原因。
        reason: String,
    },
}

impl HandshakeError {
    fn io(path: &Path, e: std::io::Error) -> Self {
        let path = path.display().to_string();
        if e.kind() == std::io::ErrorKind::NotFound {
            HandshakeError::NotFound { path }
        } else {
            HandshakeError::Io { path, source: e }
        }
    }
}
