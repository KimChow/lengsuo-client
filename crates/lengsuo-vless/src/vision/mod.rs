//! VLESS Vision（xtls-rprx-vision）客户端原语。
//!
//! 参考与 XEL 同基线：Xray v26.3.27 `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`。
//! 本模块只做 Vision 客户端的记录原语与流量层状态机，不含 REALITY、通用多会话
//! Mux 或 XUDP 跨连接恢复。
//!
//! **与 [`crate::xel`] 的区分**：两层在参考实现里虽然都来自
//! `proxy/vless/encryption/common.go` / `proxy/proxy.go`，但密钥派生假设不同——
//! XEL 把「已派生的会话密钥」注入记录层（`XelKey`），而本模块的 [`record::Aead`]
//! 按参考 `NewAEAD(ctx, key, useAES)` 在**内部**用 `blake3::derive_key(ctx, key)`
//! 从原始握手材料派生（ctx 非注入密钥），因此不复用 XEL 的密钥注入语义。
//!
//! 本模块不含 `unsafe`（crate 根 `lib.rs` 已 `#![forbid(unsafe_code)]`）；随机数
//! 通过 `aes_gcm::aead::rand_core::RngCore` 注入（真实运行时用
//! `aes_gcm::aead::OsRng`，测试用确定性计数器 RNG）。

pub mod client;
pub mod framing;
pub mod padding;
pub mod record;
pub mod server;
pub mod unpad;

/// 随机整数（`[0, limit)`）。limit == 0 时返回 0。
///
/// 参考 `crypto.RandBetween` 内部用 `crypto/rand` 的 `big.Int` 做无偏采样；这里用
/// `next_u64 % limit`（padding/流量混淆长度非安全关键，取模偏差可忽略）。
/// 参数取 `dyn` trait object，同时服务确定性测试 RNG 与 `aes_gcm::aead::OsRng`。
pub(crate) fn rand_below(rng: &mut dyn aes_gcm::aead::rand_core::RngCore, limit: u64) -> u64 {
    if limit == 0 {
        return 0;
    }
    rng.next_u64() % limit
}

/// 供本 crate 单元测试共用的确定性 RNG：`next_u64` 依次返回 0,1,2,…。
#[cfg(test)]
pub(crate) mod test_util {
    use aes_gcm::aead::rand_core::{Error as RngError, RngCore};

    pub struct CounterRng(pub u64);

    impl CounterRng {
        fn next(&mut self) -> u64 {
            let value = self.0;
            self.0 = self.0.wrapping_add(1);
            value
        }
    }

    impl RngCore for CounterRng {
        fn next_u32(&mut self) -> u32 {
            self.next() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.next()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = self.next() as u8;
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
}
