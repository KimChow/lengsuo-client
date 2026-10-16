//! 层容量上限（规格 §1；字符计数按 chars().count()）。

/// 用户记忆上限（字符）。
pub const CAP_USER_MEMORY: usize = 4000;
/// 项目记忆上限（字符）。
pub const CAP_PROJECT_MEMORY: usize = 3000;
/// SOUL 上限（字符）。
pub const CAP_SOUL: usize = 8000;
/// 单条日志追加上限（字符；防单次写爆日志）。
pub const CAP_DAILY_LINE: usize = 8000;

/// 容量校验：`text` 的字符数 ≤ `cap`，否则 `CapExceeded`。
pub fn check_cap(cap: usize, text: &str) -> Result<(), crate::error::MemoryError> {
    let len = text.chars().count();
    if len <= cap {
        Ok(())
    } else {
        Err(crate::error::MemoryError::CapExceeded { cap, len })
    }
}
