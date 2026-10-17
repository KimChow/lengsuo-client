//! 当日日志：append-only（规格 §1/§3）。
//!
//! 实现卡 B：追加 / 尾部读取 / 清除。三条路径全部先过路径安全校验（规格 §2），
//! 失败一律显式上抛 `MemoryError`（fail-closed，不静默降级、不 panic）。
//! 越界防护的**唯一**实现点是 `paths::MemoryPaths::ensure_within`（词法 + 真实路径
//! 复核），本模块不再自带副本——其余记忆层走同一函数，边界口径一致。

use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::io::Write;
use std::path::PathBuf;

use chrono::NaiveDate;

use crate::caps::CAP_DAILY_LINE;
use crate::error::MemoryError;
use crate::paths::MemoryPaths;

/// 追加一行到当日日志（自动建目录/文件；追加不覆盖；`text` ≤8000 字符）。
///
/// 顺序固定：容量校验 → 路径校验 → 建目录 → `append` 打开。
/// 超限行不落盘（不产生文件，也不部分写入），越界路径同样在触盘前拒绝。
pub fn append_daily(paths: &MemoryPaths, date: NaiveDate, text: &str) -> Result<(), MemoryError> {
    crate::caps::check_cap(CAP_DAILY_LINE, text)?;
    let file = guarded_daily_file(paths, date)?;
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
    }
    let mut handle = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file)
        .map_err(|e| io_err(&file, e))?;
    handle
        .write_all(text.as_bytes())
        .map_err(|e| io_err(&file, e))?;
    handle.write_all(b"\n").map_err(|e| io_err(&file, e))?;
    Ok(())
}

/// 读当日日志尾部 ≤`max_lines` 行；文件不存在 ⇒ None。
///
/// 只读「当日」文件（规格 §3：compose 仅注入当日日志尾部）；返回文本保留行序，
/// 末尾换行按行终止符处理（不作为额外空行）。`max_lines = 0` ⇒ 空文本。
pub fn read_daily_tail(
    paths: &MemoryPaths,
    date: NaiveDate,
    max_lines: usize,
) -> Result<Option<String>, MemoryError> {
    let file = guarded_daily_file(paths, date)?;
    let content = match fs::read_to_string(&file) {
        Ok(content) => content,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err(&file, e)),
    };
    let (start, end) = tail_bounds(&content, max_lines);
    Ok(Some(content[start..end].to_string()))
}

/// 删除当日日志；不存在视为成功（幂等）。
pub fn clear_daily(paths: &MemoryPaths, date: NaiveDate) -> Result<(), MemoryError> {
    let file = guarded_daily_file(paths, date)?;
    match fs::remove_file(&file) {
        Ok(()) => Ok(()),
        // 目录也不存在时 remove_file 同样报 NotFound ⇒ 视为已清空。
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err(&file, e)),
    }
}

/// 当日日志路径 + 越界防护：词法拒绝 `..` 后再按真实路径复核（规格 §2）。
fn guarded_daily_file(paths: &MemoryPaths, date: NaiveDate) -> Result<PathBuf, MemoryError> {
    let file = paths.daily_file(date);
    MemoryPaths::ensure_within(&paths.workspace, &file)?;
    Ok(file)
}

/// 尾部 `max_lines` 行的字节区间：自尾向前扫描换行符，避免为整个文件构造行向量。
///
/// 返回区间恒落在字符边界上（切点只在 `\n` 之后 / 文件首），故调用处可直接切片。
/// 行终止符按 `str::lines()` 语义处理：文件尾的 `\n`（及其前面的 `\r`）不属于内容，
/// 否则 CRLF 文件的末行会留下悬空 `\r`，与逐行 `lines()` 的结果不一致。
fn tail_bounds(content: &str, max_lines: usize) -> (usize, usize) {
    let bytes = content.as_bytes();
    let mut end = bytes.len();
    if end > 0 && bytes[end - 1] == b'\n' {
        end -= 1;
        if end > 0 && bytes[end - 1] == b'\r' {
            end -= 1;
        }
    }
    if max_lines == 0 {
        return (end, end);
    }
    let mut cursor = end;
    let mut seen = 0usize;
    while cursor > 0 {
        cursor -= 1;
        if bytes[cursor] == b'\n' {
            seen += 1;
            if seen == max_lines {
                return (cursor + 1, end);
            }
        }
    }
    (0, end)
}

/// 统一 IO 错误包装：带路径，不带内容（规格 §2 隐私要求）。
fn io_err(path: &std::path::Path, source: std::io::Error) -> MemoryError {
    MemoryError::Io {
        path: path.to_path_buf(),
        source,
    }
}
