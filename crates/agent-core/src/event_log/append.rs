//! 追加落盘：append 一行到会话文件；新文件写文件头，已有文件缺尾换行则补齐。

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use uuid::Uuid;

use crate::error::CoreError;
use crate::event_log::format::HeadLine;

/// 追加一行（必要时先补齐换行，保证半行不粘连）。
pub(crate) fn append_line(path: &Path, session_id: Uuid, line: &str) -> Result<(), CoreError> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)
        .map_err(|e| CoreError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    ensure_head(&mut file, session_id, path)?;
    file.write_all(line.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|e| CoreError::Io {
            path: path.to_path_buf(),
            source: e,
        })
}

/// 新文件首行必须是文件头；已有文件若缺尾换行则补一个（避免粘成半行）。
fn ensure_head(file: &mut File, session_id: Uuid, path: &Path) -> Result<(), CoreError> {
    let size = file.seek(SeekFrom::End(0)).map_err(|e| CoreError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if size == 0 {
        let head = serde_json::to_string(&HeadLine::new(session_id)).map_err(CoreError::Json)?;
        return file
            .write_all(head.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .map_err(|e| CoreError::Io {
                path: path.to_path_buf(),
                source: e,
            });
    }
    let mut last = [0u8; 1];
    file.seek(SeekFrom::End(-1)).map_err(|e| CoreError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    file.read_exact(&mut last).map_err(|e| CoreError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if last[0] != b'\n' {
        file.write_all(b"\n").map_err(|e| CoreError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    }
    Ok(())
}
