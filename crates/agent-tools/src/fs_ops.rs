//! `FsToolbox` 本体与不依赖分页的通道：
//! `file:exists / info / makeDir / remove / rename` + 原子落盘辅助。

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use uuid::Uuid;

use crate::error::ToolError;
use crate::types::{modified_ms, FileInfo};

/// 文件能力层入口。`workspace` 是安全闸基准，所有路径必须先过 `guard`。
///
/// `seen` 记录本实例读/写过的绝对路径，供 `write(expect_read = true)` 的
/// 协议防呆使用（旧内容存在但本次未见 ⇒ 拒绝）。
#[derive(Debug)]
pub struct FsToolbox {
    pub workspace: PathBuf,
    seen: Mutex<HashSet<PathBuf>>,
}

impl Clone for FsToolbox {
    fn clone(&self) -> Self {
        Self {
            workspace: self.workspace.clone(),
            seen: Mutex::new(self.seen.lock().map(|s| s.clone()).unwrap_or_default()),
        }
    }
}

impl FsToolbox {
    /// 以工作区为安全闸基准构造。相对工作区路径按当前目录展开为绝对路径。
    pub fn new(workspace: impl Into<PathBuf>) -> Self {
        let raw: PathBuf = workspace.into();
        let absolute = if raw.is_absolute() {
            raw
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(&raw))
                .unwrap_or(raw)
        };
        Self {
            workspace: crate::pathguard::normalize(&absolute),
            seen: Mutex::new(HashSet::new()),
        }
    }

    pub(crate) fn mark_seen(&self, abs: &Path) {
        if let Ok(mut s) = self.seen.lock() {
            s.insert(abs.to_path_buf());
        }
    }

    pub(crate) fn is_seen(&self, abs: &Path) -> bool {
        self.seen
            .lock()
            .map(|s| s.contains(abs))
            .unwrap_or_default()
    }

    /// `file:exists`：越界与不存在一律 false（不报错，供协议层前置探测）。
    pub fn exists(&self, p: &str) -> bool {
        match self.guard(Path::new(p)) {
            Ok(abs) => fs::symlink_metadata(&abs).is_ok(),
            Err(_) => false,
        }
    }

    /// `file:info`：大小 / 是否目录 / 修改毫秒时间戳。
    pub fn get_info(&self, p: &str) -> Result<FileInfo, ToolError> {
        let abs = self.guard(Path::new(p))?;
        let meta = fs::metadata(&abs).map_err(|e| ToolError::from_io(abs.clone(), e))?;
        Ok(FileInfo {
            size: meta.len(),
            is_dir: meta.is_dir(),
            modified_ms: modified_ms(&meta),
        })
    }

    /// `file:makeDir`：递归建目录，已存在目录视为成功（幂等）。
    pub fn make_dir(&self, p: &str) -> Result<(), ToolError> {
        let abs = self.guard(Path::new(p))?;
        if abs.is_dir() {
            return Ok(());
        }
        if fs::symlink_metadata(&abs).is_ok() {
            return Err(ToolError::AlreadyExists(abs));
        }
        fs::create_dir_all(&abs).map_err(|e| ToolError::from_io(abs, e))
    }

    /// `file:remove`：进回收站（trash），不直删；目录同样支持。
    /// 工作区根本身拒绝，避免一次调用清掉整个工作区。
    pub fn remove(&self, p: &str) -> Result<(), ToolError> {
        let abs = self.guard(Path::new(p))?;
        if abs == self.workspace {
            return Err(ToolError::Denied(abs));
        }
        if fs::symlink_metadata(&abs).is_err() {
            return Err(ToolError::NotFound(abs));
        }
        trash::delete(&abs).map_err(|e| ToolError::other(abs.clone(), e.to_string()))?;
        let mut guard = self.seen.lock().ok();
        if let Some(s) = guard.as_mut() {
            s.remove(&abs);
        }
        Ok(())
    }

    /// `file:rename`：目标已存在 ⇒ `TargetExists`（不覆盖）。
    /// 跨盘（EXDEV）退化为复制 + 删除。
    pub fn rename(&self, from: &str, to: &str) -> Result<(), ToolError> {
        let src = self.guard(Path::new(from))?;
        let dst = self.guard(Path::new(to))?;
        let src_meta =
            fs::symlink_metadata(&src).map_err(|e| ToolError::from_io(src.clone(), e))?;
        if fs::symlink_metadata(&dst).is_ok() {
            return Err(ToolError::TargetExists(dst));
        }
        let dst_parent = dst
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        if !dst_parent.is_dir() {
            return Err(ToolError::NotFound(dst_parent));
        }
        match fs::rename(&src, &dst) {
            Ok(()) => Ok(()),
            Err(e) if is_cross_device(&e) => {
                if src_meta.is_dir() {
                    copy_tree(&src, &dst)?;
                    remove_tree(&src)?;
                } else {
                    fs::copy(&src, &dst).map_err(|e2| ToolError::from_io(dst.clone(), e2))?;
                    fs::remove_file(&src).map_err(|e2| ToolError::from_io(src.clone(), e2))?;
                }
                Ok(())
            }
            Err(e) => Err(ToolError::from_io(dst, e)),
        }
    }

    /// 原子写字节：同目录临时文件 → 继承原文件权限 → rename 覆盖目标。
    /// 父目录不存在 ⇒ `NotFound`；目标是目录 ⇒ `AlreadyExists`；失败清理临时文件。
    pub(crate) fn atomic_write_bytes(abs: &Path, bytes: &[u8]) -> Result<(), ToolError> {
        let parent = abs
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        if !parent.is_dir() {
            return Err(ToolError::NotFound(parent));
        }
        if abs.is_dir() {
            return Err(ToolError::AlreadyExists(abs.to_path_buf()));
        }
        let file_name = abs
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let tmp = tmp_sibling(&parent, &file_name);
        let result = write_then_rename(&tmp, abs, bytes);
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }
}

fn write_then_rename(tmp: &Path, abs: &Path, bytes: &[u8]) -> Result<(), ToolError> {
    let tmp_path = tmp.to_path_buf();
    let mut f = fs::File::create(tmp).map_err(|e| ToolError::from_io(tmp_path.clone(), e))?;
    f.write_all(bytes)
        .and_then(|_| f.flush())
        .and_then(|_| f.sync_all())
        .map_err(|e| ToolError::from_io(tmp_path.clone(), e))?;
    drop(f);
    if let Ok(meta) = fs::metadata(abs) {
        let _ = fs::set_permissions(tmp, meta.permissions());
    }
    fs::rename(tmp, abs).map_err(|e| ToolError::from_io(abs.to_path_buf(), e))
}

/// 同目录临时文件名：`.原名.<uuid>.tmp`，保证 rename 不跨盘。
pub(crate) fn tmp_sibling(dir: &Path, file_name: &str) -> PathBuf {
    dir.join(format!(".{file_name}.{}.tmp", Uuid::new_v4().simple()))
}

/// EXDEV 判定：优先稳定的 `ErrorKind::CrossesDevices`，退化到原始 errno 18。
pub(crate) fn is_cross_device(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::CrossesDevices || e.raw_os_error() == Some(18)
}

/// 递归复制目录（跨盘退化路径）。
pub(crate) fn copy_tree(src: &Path, dst: &Path) -> Result<(), ToolError> {
    fs::create_dir_all(dst).map_err(|e| ToolError::from_io(dst.to_path_buf(), e))?;
    let entries = fs::read_dir(src).map_err(|e| ToolError::from_io(src.to_path_buf(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| ToolError::from_io(src.to_path_buf(), e))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry
            .file_type()
            .map_err(|e| ToolError::from_io(from.clone(), e))?;
        if ft.is_dir() {
            copy_tree(&from, &to)?;
        } else if ft.is_file() {
            fs::copy(&from, &to).map_err(|e| ToolError::from_io(to, e))?;
        } else if ft.is_symlink() {
            link_like(&from, &to)?;
        }
    }
    Ok(())
}

fn link_like(from: &Path, to: &Path) -> Result<(), ToolError> {
    let target = fs::read_link(from).map_err(|e| ToolError::from_io(from.to_path_buf(), e))?;
    #[cfg(unix)]
    let r = std::os::unix::fs::symlink(&target, to);
    #[cfg(windows)]
    let r = if target.is_dir() {
        std::os::windows::fs::symlink_dir(&target, to)
    } else {
        std::os::windows::fs::symlink_file(&target, to)
    };
    r.map_err(|e| ToolError::from_io(to.to_path_buf(), e))
}

/// 递归删除（仅用于跨盘 rename 的源清理，非 `file:remove` 通道）。
fn remove_tree(p: &Path) -> Result<(), ToolError> {
    let meta = fs::symlink_metadata(p).map_err(|e| ToolError::from_io(p.to_path_buf(), e))?;
    if meta.is_dir() {
        for entry in fs::read_dir(p).map_err(|e| ToolError::from_io(p.to_path_buf(), e))? {
            let entry = entry.map_err(|e| ToolError::from_io(p.to_path_buf(), e))?;
            remove_tree(&entry.path())?;
        }
        fs::remove_dir(p).map_err(|e| ToolError::from_io(p.to_path_buf(), e))
    } else {
        fs::remove_file(p).map_err(|e| ToolError::from_io(p.to_path_buf(), e))
    }
}
