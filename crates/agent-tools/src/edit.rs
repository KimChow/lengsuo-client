//! 写入通道：`file:write / writeBatch`（原子落盘 + 组回滚 + 协议防呆）。

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::ToolError;
use crate::{FsToolbox, WriteOp};

/// 组回滚的内存备份：写前的原始字节，`None` 表示当时文件不存在。
type Backup = (PathBuf, Option<Vec<u8>>);

impl FsToolbox {
    /// `file:write`：原子写。`expect_read == true` 时要求本次已读过该文件
    /// （协议防呆：旧内容存在但未读过 ⇒ `Denied`），避免模型盲覆盖。
    pub fn write(&self, p: &str, content: &str, expect_read: bool) -> Result<(), ToolError> {
        let abs = self.guard(Path::new(p))?;
        if expect_read && fs::symlink_metadata(&abs).is_ok() && !self.is_seen(&abs) {
            return Err(ToolError::Denied(abs));
        }
        self.write_one(&abs, content.as_bytes())
    }

    /// `file:writeBatch`：任一失败 ⇒ 已改动的文件全部恢复原内容（原本不存在的删除），
    /// 返回 `BatchRolledBack { failed_index, reason }`。空批次直接成功。
    pub fn write_batch(&self, ops: &[WriteOp]) -> Result<(), ToolError> {
        let mut backups: Vec<Backup> = Vec::with_capacity(ops.len());
        for (idx, op) in ops.iter().enumerate() {
            let guarded = self.guard(Path::new(&op.path));
            let abs = match guarded {
                Ok(a) => a,
                Err(e) => return Err(rolled_back(&mut backups, idx, e)),
            };
            // 写前快照；失败的操作本身未改动文件，不需要快照。
            let snapshot = read_if_exists(&abs);
            if let Err(e) = self.write_one(&abs, op.content.as_bytes()) {
                return Err(rolled_back(&mut backups, idx, e));
            }
            backups.push((abs, snapshot));
        }
        Ok(())
    }

    /// 单文件原子写 + 记入「本次已见」（写成功后调用方即持有最新内容）。
    fn write_one(&self, abs: &Path, bytes: &[u8]) -> Result<(), ToolError> {
        FsToolbox::atomic_write_bytes(abs, bytes)?;
        self.mark_seen(abs);
        Ok(())
    }
}

/// 回滚并组装 `BatchRolledBack`（reason 取原始错误的显示文本）。
fn rolled_back(backups: &mut Vec<Backup>, idx: usize, err: ToolError) -> ToolError {
    let reason = err.to_string();
    rollback(backups);
    backups.clear();
    ToolError::BatchRolledBack {
        failed_index: idx,
        reason,
    }
}

/// 写前快照：不存在或非普通文件 ⇒ `None`（此时写入本身会失败并回滚）。
fn read_if_exists(abs: &Path) -> Option<Vec<u8>> {
    fs::symlink_metadata(abs)
        .ok()
        .filter(|m| m.is_file())
        .and_then(|_| fs::read(abs).ok())
}

/// 恢复：每个路径只认**最早**的快照（组内重复写同一路径时回到批量前的原内容）。
/// 原本有内容的重写，原本不存在的删除。
fn rollback(backups: &[(PathBuf, Option<Vec<u8>>)]) {
    let mut done: HashSet<PathBuf> = HashSet::new();
    for (abs, snapshot) in backups {
        if !done.insert(abs.clone()) {
            continue;
        }
        match snapshot {
            Some(bytes) => {
                let _ = FsToolbox::atomic_write_bytes(abs, bytes);
            }
            None => {
                let _ = fs::remove_file(abs);
            }
        }
    }
}
