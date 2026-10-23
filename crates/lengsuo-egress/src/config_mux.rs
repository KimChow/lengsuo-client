//! VLESS **Mux** 配置段（`mux`）。
//!
//! 从 `config.rs` 拆出（`config.rs` 已超 400 行软目标），`config.rs` 只留
//! `pub use` 转发；公共路径仍是 `crate::config::NodeMuxSettings`。
//!
//! # 对应的参考字段
//!
//! 参考 `infra/conf/transport_internet.go:252-253` 的 `xmux` 段
//! （`maxConcurrency` / `maxConnections`）与
//! `app/proxyman/outbound/handler.go:138-139`：
//!
//! ```go
//! strategy := mux.ClientStrategy{
//!     MaxConcurrency: uint32(config.Concurrency),
//!     MaxConnection:  128,
//! }
//! ```
//!
//! ⇒ `concurrency` = `MaxConcurrency`（活跃会话上限），`max_connections` =
//! `MaxConnection`（累计会话上限；参考写死 128，本段缺省取同一值）。
//!
//! 给出 `mux` 段即「以 mux 承载业务」；`None` ⇒ 既有直连行为逐字节不变。
//!
//! # fail-closed
//!
//! - 只**允许**出现在 `protocol = vless` 的节点上（给了却挂在别的协议上 ⇒ 显式
//!   报错，不静默忽略该配置段）。

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, NodeConfig, Protocol};

/// 参考 `app/proxyman/outbound/handler.go:139` 的 `MaxConnection: 128`。
const fn default_mux_connections() -> u32 {
    128
}

/// VLESS **Mux** 配置（**仅 vless**）：一条承载连接上开多条逻辑会话。
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeMuxSettings {
    /// 单条承载连接上最大**活跃**会话数（参考 `maxConcurrency`）；0 = 不限制。
    pub concurrency: u32,
    /// 单条承载连接上最大**累计**会话数（参考 `MaxConnection`）；0 = 不限制。
    #[serde(default = "default_mux_connections")]
    pub max_connections: u32,
}

impl fmt::Debug for NodeMuxSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeMuxSettings")
            .field("concurrency", &self.concurrency)
            .field("max_connections", &self.max_connections)
            .finish()
    }
}

impl NodeConfig {
    /// `mux` 段的协议范围校验（fail-closed）。
    pub(crate) fn validate_mux(
        &self,
        invalid: &impl Fn(&str) -> ConfigError,
    ) -> Result<(), ConfigError> {
        if self.mux.is_some() && self.protocol != Protocol::Vless {
            return Err(invalid("mux 配置段只允许用于 vless 协议"));
        }
        Ok(())
    }
}
