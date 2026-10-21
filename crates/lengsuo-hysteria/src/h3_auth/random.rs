//! 随机源与 padding 串生成（对齐参考 `padding.Padding.String()`）。
//!
//! 随机源：以 `RandomState`（每实例随机密钥）的 SipHash 输出充当随机字节。
//! 参考 Go 用 `math/rand`；此处只用于 padding 长度/内容与分片 packet id，
//! 不承担密码学职责（对齐参考实现同样非密码学随机的语义）。

use crate::padding::Range;

/// 随机源：以 `RandomState`（每实例随机密钥）的 SipHash 输出充当随机字节。
/// 参考 Go 用 `math/rand`；此处只用于 padding 长度/内容与分片 packet id，
/// 不承担密码学职责（对齐参考实现同样非密码学随机的语义）。
pub fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(std::process::id() as u64);
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    h.finish()
}

/// 生成参考 `padding.Padding.String()` 的随机填充串：长度取 `[min,max)`
/// 均匀抽样，字符取 `[a-zA-Z0-9]`。
pub fn random_padding(range: Range) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let span = range.span();
    let len = if span == 0 {
        range.min
    } else {
        range.min + (random_u64() % span as u64) as usize
    };
    let mut out = String::with_capacity(len);
    let mut counter = 0u64;
    while out.len() < len {
        for b in random_u64().wrapping_add(counter).to_le_bytes() {
            if out.len() == len {
                break;
            }
            out.push(CHARS[(b as usize) % CHARS.len()] as char);
        }
        counter += 1;
    }
    out
}
