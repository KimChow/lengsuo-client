//! 32 位回绕安全的序号比较原语（RFC 9293 §3.4 的 `SEG.LT` 系列）。

/// 32 位回绕安全比较：`a` 是否在 `b` 之前（RFC 9293 §3.4 的 `SEG.LT`）。
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
/// `a >= b`（回绕安全）。
pub fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}
/// `a` 是否落在半开区间 `[start, end)` 内（回绕安全）。
pub fn seq_in(a: u32, start: u32, end: u32) -> bool {
    seq_ge(a, start) && seq_lt(a, end)
}
