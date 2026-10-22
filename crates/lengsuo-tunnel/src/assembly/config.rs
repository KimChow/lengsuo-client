//! 装配层配置：角色、静态密钥材料、keepalive 节奏。
//!
//! # 边界
//!
//! ⛔ **不生成密钥、不做密钥分发**——静态私钥/对端公钥/PSK 一律由调用方注入
//! （与 `lengsuo-link-core` 的 `SessionConfig` 同一纪律：协调面归私有仓）。
//!
//! ⛔ **不写死任何节奏常量**：keepalive 的间隔由调用方给
//! （[`KeepaliveConfig::interval`] 为 `None` ⇒ 关闭）。

use std::time::Duration;

use lengsuo_wireguard::handshake::PSK_LEN;

/// 本端在装配层里的角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// 发起方：构造 initiation、消费 response。
    Initiator,
    /// 响应方：消费 initiation、构造 response。
    Responder,
}

impl Role {
    /// 角色的固定名字（错误文本与 `Debug` 用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
        }
    }
}

/// 装配层配置。
///
/// ⚠️ 持有本端静态私钥 ⇒ **绝不派生 `Debug`**（本文件手写 `Debug`，
/// 只输出角色与「有没有密钥」，不输出任何密钥字节）。
#[derive(Clone)]
pub struct AssemblyConfig {
    /// 本端角色。
    pub role: Role,
    /// 本端静态私钥（32 字节）。**由调用方注入**。
    pub local_static_private: [u8; 32],
    /// 对端静态公钥（32 字节）。**由调用方注入**。
    pub remote_static_public: [u8; 32],
    /// 可选预共享密钥（32 字节）。
    pub preshared_key: Option<[u8; PSK_LEN]>,
    /// keepalive 间隔。`None` = **关闭** keepalive。
    ///
    /// ⛔ 本 crate **不写死**任何节奏常量——间隔由上层配。
    pub keepalive_interval: Option<Duration>,
    /// 本端 index（每轮握手应当用**新**的 index）。
    ///
    /// 默认 `None` ⇒ 装配层按 [`local_index_from`] 的规则自行派生。
    pub local_index: Option<u32>,
}

impl AssemblyConfig {
    /// 构造一份配置（`keepalive` 关闭、无预共享密钥）。
    #[must_use]
    pub fn new(role: Role, local_static_private: [u8; 32], remote_static_public: [u8; 32]) -> Self {
        Self {
            role,
            local_static_private,
            remote_static_public,
            preshared_key: None,
            keepalive_interval: None,
            local_index: None,
        }
    }

    /// 附加预共享密钥。
    #[must_use]
    pub fn with_preshared_key(mut self, psk: [u8; PSK_LEN]) -> Self {
        self.preshared_key = Some(psk);
        self
    }

    /// 配置 keepalive 间隔（`None` = 关闭）。
    #[must_use]
    pub fn with_keepalive_interval(mut self, interval: Option<Duration>) -> Self {
        self.keepalive_interval = interval;
        self
    }

    /// 指定本端 index。
    #[must_use]
    pub fn with_local_index(mut self, index: u32) -> Self {
        self.local_index = Some(index);
        self
    }

    /// 校验密钥材料（fail-closed）。
    ///
    /// # Errors
    /// 对端公钥或本端私钥为全零 ⇒ [`AssemblyError::HandshakeRejected`]。
    pub fn validate(&self) -> Result<(), crate::assembly::AssemblyError> {
        if self.remote_static_public == [0u8; 32] {
            return Err(crate::assembly::AssemblyError::HandshakeRejected {
                reason: "对端静态公钥为全零",
            });
        }
        if self.local_static_private == [0u8; 32] {
            return Err(crate::assembly::AssemblyError::HandshakeRejected {
                reason: "本端静态私钥为全零",
            });
        }
        Ok(())
    }
}

impl core::fmt::Debug for AssemblyConfig {
    /// **只输出角色与密钥长度**，绝不输出任何密钥字节。
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AssemblyConfig")
            .field("role", &self.role)
            .field("has_preshared_key", &self.preshared_key.is_some())
            .field("keepalive_interval", &self.keepalive_interval)
            .field("local_index", &self.local_index)
            // 故意不输出任何密钥字节。
            .finish_non_exhaustive()
    }
}
