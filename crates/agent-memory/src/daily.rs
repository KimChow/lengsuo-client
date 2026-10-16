//! 当日日志：append-only（规格 §1/§3）。
//!
//! **本文件全部由实现卡 B 完成**——签名已冻结，未实现处 `todo!()`（TDD 先红）。

use std::path::Path;

use chrono::NaiveDate;

use crate::caps::CAP_DAILY_LINE;
use crate::error::MemoryError;
use crate::paths::MemoryPaths;

/// 追加一行到当日日志（自动建目录/文件；追加不覆盖；`text` ≤8000 字符）。
pub fn append_daily(
    paths: &MemoryPaths,
    date: NaiveDate,
    text: &str,
) -> Result<(), MemoryError> {
    let _ = (paths, date, text);
    todo!("实现卡 B")
}

/// 读当日日志尾部 ≤`max_lines` 行；文件不存在 ⇒ None。
pub fn read_daily_tail(
    paths: &MemoryPaths,
    date: NaiveDate,
    max_lines: usize,
) -> Result<Option<String>, MemoryError> {
    let _ = (paths, date, max_lines);
    todo!("实现卡 B")
}

/// 删除当日日志；不存在视为成功。
pub fn clear_daily(paths: &MemoryPaths, date: NaiveDate) -> Result<(), MemoryError> {
    let _ = (paths, date);
    todo!("实现卡 B")
}

/// 容量校验的公共入口（卡 B 使用）。
pub(crate) fn check_line_cap(text: &str) -> Result<(), MemoryError> {
    crate::caps::check_cap(CAP_DAILY_LINE, text)
}

/// 路径越界防护的公共入口（卡 B 使用）。
pub(crate) fn ensure_within(base: &Path, candidate: &Path) -> Result<(), MemoryError> {
    MemoryPaths::ensure_within(base, candidate)
}
