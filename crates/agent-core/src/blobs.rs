//! BlobStore：大结果与受控凭据的落盘引用（开工说明 §3/§4）。
//!
//! - 会话消息 `content` 只放收窄摘要，大输出写入本存储，消息带 `result_ref`。
//! - 凭据同理：工具参数只出现 `cred_ref`，真实值由外部注入，不进事件流与日志。
//! - 引用即不透明 id（uuid）；文件名 `{id}.bin`，读取不存在的引用返回 `BlobNotFound`。
//! - 目录由调用方给定（网关用 `<workdir>/blobs`）；无 unsafe，路径只由 id 拼装。
//! - 路径授权外沿：`{id}.bin` 与 blobs 目录本身都必须是**非 symlink 的普通文件/真实
//!   目录**，否则按非法引用处理（`BlobNotFound`，不泄漏外部内容）。硬链接与
//!   检查-使用竞态（TOCTOU）未解决，见 `docs/blob-path-status.md`。

use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::error::CoreError;

/// 落盘引用（`result_ref` / `cred_ref` 的字面值）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRef(pub String);

impl BlobRef {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 内容寻址的简单 blob 存储（按 id 取回，不做去重）。
#[derive(Debug, Clone)]
pub struct BlobStore {
    dir: PathBuf,
}

impl BlobStore {
    /// 指定目录（不存在时写入前自动创建）。
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    /// 写入一段内容，返回引用。
    pub fn put(&self, bytes: &[u8]) -> Result<BlobRef, CoreError> {
        if !self.dir_exists() {
            std::fs::create_dir_all(&self.dir).map_err(|e| CoreError::Io {
                path: self.dir.clone(),
                source: e,
            })?;
        }
        // 目录必须是真实目录：symlink 目录不授权（拒绝写入外部目录）。
        self.require_writable_dir()?;
        let id = Uuid::new_v4();
        let path = self.path_of(&id.to_string());
        std::fs::write(&path, bytes).map_err(|e| CoreError::Io {
            path: path.clone(),
            source: e,
        })?;
        Ok(BlobRef(id.to_string()))
    }

    /// 按引用读取；引用非法、文件缺失或路径不是普通文件 → `BlobNotFound`。
    ///
    /// symlink 引用一律按非法引用处理，不读出其外部目标内容（fail-closed）。
    pub fn get(&self, reference: &str) -> Result<Vec<u8>, CoreError> {
        let id = Uuid::parse_str(reference)
            .map_err(|_| CoreError::BlobNotFound(reference.to_string()))?;
        let path = self.path_of(&id.to_string());
        // 目录不可信（symlink 等）或引用路径不是普通文件 → 视为非法引用，不读外部内容。
        if !self.dir_is_trusted() || !Self::is_regular_reference_path(&path) {
            return Err(CoreError::BlobNotFound(reference.to_string()));
        }
        match std::fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(CoreError::BlobNotFound(reference.to_string()))
            }
            Err(e) => Err(CoreError::Io { path, source: e }),
        }
    }

    /// 删除引用（会话清理用）；不存在视为已清理。
    ///
    /// 只 unlink 引用路径本身：symlink 引用删除的是链接，不跟随、不删外部目标
    /// （POSIX unlink 不解析链接目标）。blobs 目录本身是 symlink 时 unlink 会落到
    /// 外部目录里的文件，故整条引用按非法处理并拒绝。
    pub fn remove(&self, reference: &str) -> Result<(), CoreError> {
        let Ok(id) = Uuid::parse_str(reference) else {
            return Err(CoreError::BlobNotFound(reference.to_string()));
        };
        let path = self.path_of(&id.to_string());
        if self.dir_exists() && !self.dir_is_trusted() {
            return Err(CoreError::BlobNotFound(reference.to_string()));
        }
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(CoreError::Io { path, source: e }),
        }
    }

    /// 已存储的引用列表（升序；审计视图用）。
    ///
    /// 只列出 blobs 真实目录下的普通文件引用；symlink、目录、FIFO 等一律不列。
    pub fn list(&self) -> Vec<String> {
        if !self.dir_is_trusted() {
            return Vec::new();
        }
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut ids: Vec<String> = entries
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|ft| ft.is_file()))
            .filter_map(|e| {
                let name = e.file_name().to_str()?.to_string();
                let stem = name.strip_suffix(".bin")?;
                let id = Uuid::parse_str(stem).ok()?;
                // 只认自产的可逆文件名，避免规范化后指向另一个路径的条目混入。
                let canonical = format!("{id}.bin");
                (canonical == name).then_some(id.to_string())
            })
            .collect();
        ids.sort();
        ids
    }

    /// 引用集能否安全解析（防路径穿越：只接受规范 uuid 字面值）。
    pub fn is_valid_reference(reference: &str) -> bool {
        Uuid::parse_str(reference).is_ok()
    }

    fn path_of(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.bin"))
    }

    fn dir_exists(&self) -> bool {
        std::fs::symlink_metadata(&self.dir).is_ok()
    }

    /// blobs 目录是否为可信的真实目录（非 symlink 的目录）。
    fn dir_is_trusted(&self) -> bool {
        std::fs::symlink_metadata(&self.dir)
            .map(|m| m.is_dir() && !m.file_type().is_symlink())
            .unwrap_or(false)
    }

    fn require_writable_dir(&self) -> Result<(), CoreError> {
        if self.dir_is_trusted() {
            return Ok(());
        }
        Err(CoreError::Io {
            path: self.dir.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "blob 目录不存在或不是真实目录（symlink 目录不授权）",
            ),
        })
    }

    /// 引用路径是否为普通文件（`symlink_metadata` 不跟随链接，故 symlink 为 false）。
    fn is_regular_reference_path(path: &Path) -> bool {
        std::fs::symlink_metadata(path)
            .map(|m| m.is_file() && !m.file_type().is_symlink())
            .unwrap_or(false)
    }
}

/// 凭据解析回调：工具执行期由宿主注入真实值，核心不持有凭据。
///
/// v0 只有类型与"未接入"占位（真实凭据库属私仓业务，不进本仓）。
pub trait CredentialResolver: Send + Sync {
    /// 取引用对应的凭据值；实现者保证不写日志。
    fn resolve(&self, cred_ref: &str) -> Result<Vec<u8>, CoreError>;
}

/// 占位实现：一律 `Unsupported`，避免误报能力。
pub struct NoopCredentialResolver;

impl CredentialResolver for NoopCredentialResolver {
    fn resolve(&self, _cred_ref: &str) -> Result<Vec<u8>, CoreError> {
        Err(CoreError::Unsupported(
            "凭据库未接入（cred_ref 需由宿主注入）",
        ))
    }
}
