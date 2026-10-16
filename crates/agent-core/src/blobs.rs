//! BlobStore：大结果与受控凭据的落盘引用（开工说明 §3/§4）。
//!
//! - 会话消息 `content` 只放收窄摘要，大输出写入本存储，消息带 `result_ref`。
//! - 凭据同理：工具参数只出现 `cred_ref`，真实值由外部注入，不进事件流与日志。
//! - 引用即不透明 id（uuid）；文件名 `{id}.bin`，读取不存在的引用返回 `BlobNotFound`。
//! - 目录由调用方给定（网关用 `<workdir>/blobs`）；无 unsafe，路径只由 id 拼装。

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
        std::fs::create_dir_all(&self.dir).map_err(|e| CoreError::Io {
            path: self.dir.clone(),
            source: e,
        })?;
        let id = Uuid::new_v4();
        let path = self.path_of(&id.to_string());
        std::fs::write(&path, bytes).map_err(|e| CoreError::Io {
            path: path.clone(),
            source: e,
        })?;
        Ok(BlobRef(id.to_string()))
    }

    /// 按引用读取；引用非法或文件缺失 → `BlobNotFound`（不静默给空内容）。
    pub fn get(&self, reference: &str) -> Result<Vec<u8>, CoreError> {
        let id = Uuid::parse_str(reference)
            .map_err(|_| CoreError::BlobNotFound(reference.to_string()))?;
        let path = self.path_of(&id.to_string());
        match std::fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(CoreError::BlobNotFound(reference.to_string()))
            }
            Err(e) => Err(CoreError::Io { path, source: e }),
        }
    }

    /// 删除引用（会话清理用）；不存在视为已清理。
    pub fn remove(&self, reference: &str) -> Result<(), CoreError> {
        let Ok(id) = Uuid::parse_str(reference) else {
            return Err(CoreError::BlobNotFound(reference.to_string()));
        };
        let path = self.path_of(&id.to_string());
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(CoreError::Io { path, source: e }),
        }
    }

    /// 已存储的引用列表（升序；审计视图用）。
    pub fn list(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut ids: Vec<String> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_str()?.to_string();
                name.strip_suffix(".bin")
                    .and_then(|stem| Uuid::parse_str(stem).ok().map(|u| u.to_string()))
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
