//! `vision_wire` 集成测试的**共用夹具**：确定性 RNG、假凭据、管道容量、读空助手。
//!
//! 单独成文件的原因：`tests/vision_wire.rs` 超过 400 行软目标，按职责拆到
//! `tests/vision_wire/` 子目录（与 `tests/exception_matrix/` 同一套路）。

use std::time::Duration;

use aes_gcm::aead::rand_core::{Error as RngError, RngCore};
use lengsuo_vless::vision::record::Cipher;
use lengsuo_vless::vision_wire::{RecordConfig, VisionWireConfig};

use tokio::io::AsyncReadExt;

/// 测试用 UUID（假凭据）。
pub(crate) const UUID: [u8; 16] = [0x11; 16];
/// 记录层派生上下文（假材料）。
pub(crate) const CTX: &str = "vision-wire-test-context";
/// 记录层密钥材料（假凭据）。
pub(crate) const KEY: [u8; 32] = [0xA1; 32];
/// 所有网络/管道操作的上限（超时必须存在）。
pub(crate) const LIMIT: Duration = Duration::from_secs(5);
/// 管道容量：足够放下一次 vision 写入（含最长 ~1.4 KiB 的长 padding 块）。
pub(crate) const PIPE: usize = 64 * 1024;

/// 确定性 RNG：`next_u64` 依次返回 0,1,2,…。
///
/// 与 `lengsuo_vless::vision::test_util::CounterRng` 语义相同，但那是
/// `#[cfg(test)]` 私有模块，集成测试取不到 ⇒ 这里自己实现一份**同语义**的
/// 计数器 RNG（不是第二份 vision 实现，只是测试熵源）。
pub(crate) struct CounterRng(pub u64);

impl RngCore for CounterRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let value = self.0;
        self.0 = self.0.wrapping_add(1);
        value
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.next_u64() as u8;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// 流量层配置（假凭据 + 参考默认 testseed）。
pub(crate) fn vision_config() -> VisionWireConfig {
    VisionWireConfig {
        uuid: UUID,
        testseed: None,
    }
}

/// 记录层配置（假材料 + AES-256-GCM）。
pub(crate) fn record_config() -> RecordConfig {
    RecordConfig {
        ctx: CTX.to_owned(),
        key: KEY.to_vec(),
        cipher: Cipher::Aes256Gcm,
    }
}

/// 把承载流里的字节全部读出来（读到 EOF 为止）。
pub(crate) async fn drain<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let read = tokio::time::timeout(LIMIT, reader.read(&mut buf))
            .await
            .expect("读超时")
            .unwrap();
        if read == 0 {
            break;
        }
        out.extend_from_slice(&buf[..read]);
    }
    out
}
