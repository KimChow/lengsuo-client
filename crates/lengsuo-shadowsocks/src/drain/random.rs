//! 进程级全局随机源的小工具。
//!
//! 参考实现里对应 `dice.Roll` / `dice.RollUint64` 走的是 `math/rand` 的
//! **进程全局**源（非确定性）。本 crate 复刻同样的语义：这些调用点必须与种子
//! 无关地变化，否则攻击者只要观测到一次排空长度就能反推种子。

/// 熵源：取当前时间的纳秒并用 `RandomState` 混一遍。
pub(crate) fn os_entropy() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    h.finish()
}

/// splitmix64：把一个 64 位状态扩成一个伪随机字。
pub(crate) fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}
