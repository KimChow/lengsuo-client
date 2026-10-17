//! 读取通道：`file:list / read / readChunked`。

use std::fs;
use std::io::Read;
use std::path::Path;

use crate::error::ToolError;
use crate::types::{modified_ms, EntryInfo};
use crate::{FsToolbox, MAX_SINGLE_READ_BYTES};

impl FsToolbox {
    /// `file:list`：先按名排序再分页，返回 `(本页条目, 总数)`。
    /// `limit == 0` 或 `offset` 越界 ⇒ 本页为空但总数照常返回。
    pub fn list_dir(
        &self,
        p: &str,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<EntryInfo>, usize), ToolError> {
        let abs = self.guard(Path::new(p))?;
        let meta = fs::metadata(&abs).map_err(|e| ToolError::from_io(abs.clone(), e))?;
        if !meta.is_dir() {
            return Err(ToolError::NotADirectory(abs));
        }
        let read = fs::read_dir(&abs).map_err(|e| ToolError::from_io(abs.clone(), e))?;
        let mut entries: Vec<EntryInfo> = Vec::new();
        for item in read {
            let item = item.map_err(|e| ToolError::from_io(abs.clone(), e))?;
            let child = item.path();
            let child_meta =
                fs::metadata(&child).map_err(|e| ToolError::from_io(child.clone(), e))?;
            entries.push(EntryInfo {
                name: item.file_name().to_string_lossy().into_owned(),
                rel_path: self.rel_display(&child),
                size: child_meta.len(),
                is_dir: child_meta.is_dir(),
                modified_ms: modified_ms(&child_meta),
            });
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let total = entries.len();
        let page = if limit == 0 {
            Vec::new()
        } else {
            entries.into_iter().skip(offset).take(limit).collect()
        };
        Ok((page, total))
    }

    /// `file:read`：整读为 UTF-8 字符串，并把路径记入「本次已见」集合。
    /// 上限 = `max_bytes` 与 8 MiB 取小；超限 ⇒ `TooLarge`；非 UTF-8 ⇒ `Io(InvalidData)`。
    pub fn read(&self, p: &str, max_bytes: u64) -> Result<String, ToolError> {
        let abs = self.guard(Path::new(p))?;
        let limit = max_bytes.min(MAX_SINGLE_READ_BYTES);
        let meta = fs::metadata(&abs).map_err(|e| ToolError::from_io(abs.clone(), e))?;
        if meta.is_dir() {
            return Err(ToolError::Io {
                path: abs,
                source: std::io::Error::from(std::io::ErrorKind::IsADirectory),
            });
        }
        if meta.len() > limit {
            return Err(ToolError::TooLarge { path: abs, limit });
        }
        let mut buf = Vec::with_capacity(meta.len() as usize);
        fs::File::open(&abs)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .map_err(|e| ToolError::from_io(abs.clone(), e))?;
        let text = String::from_utf8(buf).map_err(|e| ToolError::Io {
            path: abs.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        })?;
        self.mark_seen(&abs);
        Ok(text)
    }

    /// `file:readChunked`：按行对齐分块，行号 0 基，返回 `(本块行, has_more)`。
    /// 起始行越界 ⇒ 空块且 `has_more == false`；`max_lines == 0` ⇒ 空块但如实报告 `has_more`。
    pub fn read_chunked(
        &self,
        p: &str,
        start_line: usize,
        max_lines: usize,
    ) -> Result<(Vec<String>, bool), ToolError> {
        let content = self.read(p, MAX_SINGLE_READ_BYTES)?;
        let lines: Vec<&str> = content.lines().collect();
        let total = lines.len();
        let start = start_line.min(total);
        let end = start.saturating_add(max_lines).min(total);
        let chunk: Vec<String> = lines[start..end].iter().map(|l| (*l).to_string()).collect();
        Ok((chunk, end < total))
    }
}
