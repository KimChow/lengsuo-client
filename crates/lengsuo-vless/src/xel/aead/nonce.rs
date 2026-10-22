//! 序号 → nonce 字节的映射。
//!
//! 从 [`super`] 拆出以保持单文件 ≤400 行（软约束）；纯函数、无状态。

use super::NONCE_LEN;

/// 序号 → nonce 字节（大端；高 4 字节恒零）。
///
/// `common.go` 起始 nonce 全 0 且**先加后用**，故首个使用的 nonce 是
/// `00…0001`（序号 1），第二个是 `00…0002`。本函数固化该映射，使线上 nonce 与
/// 序号一一对应、可观测。
pub fn nonce_for_sequence(sequence: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}
