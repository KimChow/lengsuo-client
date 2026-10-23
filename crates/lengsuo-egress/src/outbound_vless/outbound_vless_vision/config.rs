//! 配置翻译层：node 配置 → 协议 crate 的流量层 / 记录层配置。

use lengsuo_vless::vision::record::Cipher;
use lengsuo_vless::vision_wire::{RecordConfig, VisionWireConfig};

use crate::config::NodeConfig;

use super::VisionConfigError;

/// 记录层 AEAD 套件名 → 协议 crate 的 [`Cipher`]（参考 `useAES` 二选一）。
fn cipher_from_name(name: &str) -> Result<Cipher, VisionConfigError> {
    match name {
        "aes-256-gcm" => Ok(Cipher::Aes256Gcm),
        "chacha20-poly1305" => Ok(Cipher::ChaCha20Poly1305),
        other => Err(VisionConfigError::UnknownCipher(other.to_owned())),
    }
}

/// 十六进制文本 → 字节（大小写不敏感；奇数长度或非法字符 ⇒ 失败）。
///
/// 参考的记录层密钥来自 ML-KEM 会话握手（**本仓没有**，见模块文档的偏离说明）
/// ⇒ `key` 由配置直接给出，用十六进制文本承载。
fn hex_to_bytes(text: &str) -> Result<Vec<u8>, VisionConfigError> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if !compact.len().is_multiple_of(2) {
        return Err(VisionConfigError::InvalidKey);
    }
    let mut out = Vec::with_capacity(compact.len() / 2);
    for pair in compact.as_bytes().chunks(2) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or(VisionConfigError::InvalidKey)?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or(VisionConfigError::InvalidKey)?;
        out.push(((high << 4) | low) as u8);
    }
    if out.is_empty() {
        return Err(VisionConfigError::EmptyKey);
    }
    Ok(out)
}

/// node 配置 → 协议 crate 的**流量层**配置（`VisionWireConfig`）。
///
/// `uuid` 取 `auth.password` 的 16 字节（参考 `TrafficState.UserUUID`）。
/// `testseed` 缺省 ⇒ 参考默认 `{900, 500, 900, 256}`（协议 crate 内处理）。
pub(super) fn vision_wire_config(config: &NodeConfig, uuid: [u8; 16]) -> VisionWireConfig {
    VisionWireConfig {
        uuid,
        testseed: config.vision.as_ref().and_then(|vision| vision.testseed),
    }
}

/// node 配置 → 协议 crate 的**记录层**配置（`RecordConfig`）。
pub(super) fn record_config(config: &NodeConfig) -> Result<RecordConfig, VisionConfigError> {
    let Some(encryption) = &config.encryption else {
        return Err(VisionConfigError::UnknownCipher("未配置记录层".to_owned()));
    };
    let cipher = cipher_from_name(&encryption.cipher)?;
    let key = hex_to_bytes(&encryption.key)?;
    Ok(RecordConfig {
        ctx: encryption.ctx.clone(),
        key,
        cipher,
    })
}

/// 记录层是否启用（参考 `account.Encryption != "" && != "none"`）。
#[must_use]
pub fn record_enabled(config: &NodeConfig) -> bool {
    config.encryption.is_some()
}

/// 流量层是否启用（参考 `account.Flow == vless.XRV`）。
///
/// 判据是「**配置了流量层段**」，而不是「flow 名恰好是 `xtls-rprx-vision`」：
/// 未知的 flow 名由 [`precheck`] **显式报错**（fail-closed），**不**静默退回
/// 无流量层路径。
#[must_use]
pub fn vision_enabled(config: &NodeConfig) -> bool {
    config.vision.is_some()
}
