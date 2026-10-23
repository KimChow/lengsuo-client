//! VLESS Vision 的两个**配置段**：**流量层**（`vision`）与**记录层**（`encryption`）。
//!
//! 这两段从 `config.rs` 拆出（`config.rs` 已超 400 行软目标），**结构与校验
//! 语义不变**：字段名、serde 名、fail-closed 判据全部与拆分前逐字一致。
//!
//! # 两个参考特性、两个独立开关
//!
//! | 配置段 | 参考 | 作用 |
//! |---|---|---|
//! | `vision` | `infra/conf/vless.go` 的 `flow` + `proxy/proxy.go` 的 `VisionWriter` / `VisionReader` | **流量层**：给流量加 padding 块 |
//! | `encryption` | `proxy/vless/encryption/common.go` 的 `CommonConn` | **记录层**：给整条连接加 AEAD 记录 |
//!
//! 参考把它们串起来用（`proxy/vless/outbound/outbound.go`：`VisionWriter` 套在
//! `CommonConn` 之上），但**互不依赖**：与参考互通时，普通 vision 流只有流量层
//! （`decryption: "none"`）。
//!
//! # fail-closed
//!
//! - 两段都**只允许**出现在 `protocol = vless` 的节点上 ⇒ 给了却挂在别的协议上，
//!   配置加载阶段**显式报错**（不静默忽略该配置段）。
//! - 未知 `flow` / 未知 `cipher` / 空 `ctx` / 空 `key` ⇒ **显式报错**，绝不静默
//!   退回「无流量层」或「明文路径」。
//!
//! # 与参考的有意偏离（ML-KEM）
//!
//! 参考的 `encryption` 走 `mlkem768x25519plus.` **会话握手**
//! （`infra/conf/vless.go:97`、`:321-357`；`proxy/vless/outbound/outbound.go:211-216`
//! 的 `h.encryption.Handshake(conn)`）：会话密钥与 IV 由 ML-KEM-768 + X25519 协商
//! 得出。本仓**没有 ML-KEM** ⇒ 本配置从「**会话密钥与 IV 已就绪**」这一层接：
//! `ctx` 与 `key` 由配置给出。
//!
//! ⇒ **与参考的进程级互通在结构上不可达**（参考的 `encryption` 特性需要本仓没有
//! 的 ML-KEM 握手）。这一点必须如实记为偏离，不许含糊过去。

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, NodeConfig, Protocol};

/// VLESS **Vision 流量层**配置（**仅 vless**）。
///
/// 对应参考 `infra/conf/vless.go` 的 `flow` 字段与 `proxy/proxy.go` 的
/// `VisionWriter` / `VisionReader`（流量层：给流量加 padding 块）。
///
/// 缺省（无此段）⇒ **不走流量层**，线上字节与改造前逐字节一致。
///
/// 未知 `flow` 名 ⇒ 配置校验**显式报错**（fail-closed，不静默退回明文路径）。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeVisionSettings {
    /// 流量层模式名。参考只认 `xtls-rprx-vision`（`vless.XRV`）。
    pub flow: String,
    /// 参考 `testseed`（4 个 u32）。缺省 ⇒ 参考默认 `{900, 500, 900, 256}`。
    #[serde(default)]
    pub testseed: Option<[u32; 4]>,
}

impl fmt::Debug for NodeVisionSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 本段没有凭据（用户 UUID 在 `auth.password`，已由 AuthConfig 脱敏）。
        f.debug_struct("NodeVisionSettings")
            .field("flow", &self.flow)
            .field("testseed", &self.testseed)
            .finish()
    }
}

/// VLESS **记录层**（AEAD）配置（**仅 vless**）。
///
/// 对应参考 `proxy/vless/encryption/common.go` 的 `CommonConn`（记录层：给整条
/// 连接加 AEAD 记录，`NewAEAD(ctx, key, useAES)`）。
///
/// 它与 [`NodeVisionSettings`]（流量层）是**两个不同**的特性、各自独立开关：
/// 参考把它们串起来用（`proxy/vless/outbound/outbound.go`：`VisionWriter` 套在
/// `CommonConn` 之上），但互不依赖。
///
/// ⚠️ 与参考的**有意偏离**（详见本模块文档与本卡报告）：参考的 `encryption` 走
/// `mlkem768x25519plus.` 会话握手（`infra/conf/vless.go:97`），本仓无 ML-KEM
/// ⇒ 本配置从「**会话密钥与 IV 已就绪**」这一层开始：`ctx` 与 `key` 由配置给出。
///
/// 密钥材料（`key`）是凭据 ⇒ 不进 Debug 输出。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeEncryptionSettings {
    /// AEAD 套件：`aes-256-gcm` / `chacha20-poly1305`（参考 `useAES` 二选一）。
    pub cipher: String,
    /// 记录层派生上下文（参考 `NewAEAD(ctx, key, useAES)` 的 `ctx`）。
    pub ctx: String,
    /// 记录层密钥材料（十六进制文本；参考会话密钥）。
    pub key: String,
}

impl fmt::Debug for NodeEncryptionSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 密钥材料是凭据 ⇒ 只报「是否给出」，不报原文（与 AuthConfig 同惯例）。
        f.debug_struct("NodeEncryptionSettings")
            .field("cipher", &self.cipher)
            .field("ctx", &self.ctx)
            .field("key", &crate::config::redacted(&self.key))
            .finish()
    }
}

impl NodeConfig {
    /// Vision **流量层**配置段的协议范围与取值校验（fail-closed）。
    ///
    /// - `protocol != vless` 却带 `vision` 段 ⇒ 显式报错（不静默忽略）。
    /// - `flow` 未知（参考只认 `xtls-rprx-vision`）⇒ 显式报错，**不**静默退回
    ///   明文/无流量层路径。
    pub(crate) fn validate_vision(
        &self,
        invalid: &impl Fn(&str) -> ConfigError,
    ) -> Result<(), ConfigError> {
        let Some(vision) = &self.vision else {
            return Ok(());
        };
        if self.protocol != Protocol::Vless {
            return Err(invalid("vision 配置段只允许用于 vless 协议"));
        }
        match vision.flow.as_str() {
            crate::outbound_vless::outbound_vless_vision::FLOW_XTLS_RPRX_VISION => {}
            other => {
                return Err(invalid(&format!(
                    "vision.flow 未知：{other}（只支持 xtls-rprx-vision）"
                )))
            }
        }
        Ok(())
    }

    /// **记录层**（AEAD）配置段的协议范围与取值校验（fail-closed）。
    ///
    /// - `protocol != vless` 却带 `encryption` 段 ⇒ 显式报错。
    /// - `cipher` 未知 ⇒ 显式报错，**不**静默退回明文/不加密路径。
    /// - `ctx` / `key` 为空 ⇒ 显式报错（记录层构造即失败，见
    ///   `lengsuo_vless::vision_wire::RecordStream::new`）。
    pub(crate) fn validate_encryption(
        &self,
        invalid: &impl Fn(&str) -> ConfigError,
    ) -> Result<(), ConfigError> {
        let Some(encryption) = &self.encryption else {
            return Ok(());
        };
        if self.protocol != Protocol::Vless {
            return Err(invalid("encryption 配置段只允许用于 vless 协议"));
        }
        match encryption.cipher.as_str() {
            "aes-256-gcm" | "chacha20-poly1305" => {}
            other => {
                return Err(invalid(&format!(
                    "encryption.cipher 未知：{other}（只支持 aes-256-gcm / chacha20-poly1305）"
                )))
            }
        }
        if encryption.ctx.trim().is_empty() {
            return Err(invalid("encryption.ctx 不能为空"));
        }
        if encryption.key.trim().is_empty() {
            return Err(invalid("encryption.key 不能为空"));
        }
        Ok(())
    }
}
