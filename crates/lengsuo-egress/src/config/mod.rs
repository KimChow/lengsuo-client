//! 出口节点配置：加载、校验与脱敏 Debug。
//!
//! 本卡范围：八种出口协议全部注册（trojan / anytls / vless / vmess /
//! shadowsocks / ss2022 / hysteria / wireguard）。协议语义一律复用本仓对应
//! crate，本模块只做「配置 → 校验 → 交给 outbound」。
//!
//! 配置文件是 JSON 数组，每个元素一个 `NodeConfig`：
//!
//! ```json
//! [
//!   {
//!     "name": "node-a",
//!     "protocol": "trojan",
//!     "endpoint": { "host": "127.0.0.1", "port": 8443 },
//!     "tls": { "server_name": "example.com", "ca_pem": "..." },
//!     "auth": { "password": "secret" }
//!   }
//! ]
//! ```
//!
//! 所有凭据字段（`auth.*`、`secret_key`、`public_key`、`private_key`）都不得
//! 进入日志：`NodeConfig` 的 Debug 输出对凭据脱敏（见 `endpoint` / `reality` /
//! `node` 里的手写 impl），serde 反序列化保留原文但只存在内存中。校验失败一律
//! fail-closed，报错只带节点名与字段名/长度，不带口令原文或其摘要。
//!
//! 文件按职责拆分：`error`（错误类型）/ `protocol`（协议枚举）/
//! `endpoint`（端点与 TLS、凭据）/ `reality`（REALITY 段）/ `node`（节点结构）/
//! `validate`（校验规则）/ `load`（文件加载）/ `redact`（脱敏占位）。
//! 公共路径仍是 `crate::config::X`：拆分前的每个公开符号都在这里原样转出。

/// VLESS Vision 的两个配置段（**流量层** `vision` / **记录层** `encryption`）。
///
/// 拆到独立文件：`config.rs` 已超 400 行软目标。结构与校验语义与拆分前逐字
/// 一致；公共路径仍是 `crate::config::NodeVisionSettings` /
/// `crate::config::NodeEncryptionSettings`（本模块的转出）。
#[path = "../config_vision.rs"]
mod config_vision;
pub use config_vision::{NodeEncryptionSettings, NodeVisionSettings};

/// VLESS **XEL 记录层**配置段（`xel`）。
///
/// 拆到独立文件（同上）：结构与校验语义见 [`crate::config_xel::NodeXelSettings`]。
#[path = "../config_xel.rs"]
mod config_xel;
pub use config_xel::{NodeXelSettings, NodeXelXorSettings};

/// VLESS **Mux 承载**配置段（`mux`）。
///
/// 拆到独立文件（同上）：结构与校验语义见 [`crate::config_mux::NodeMuxSettings`]。
#[path = "../config_mux.rs"]
mod config_mux;
pub use config_mux::NodeMuxSettings;

mod endpoint;
mod error;
mod load;
mod node;
mod protocol;
mod reality;
mod redact;
mod validate;

pub use endpoint::{AuthConfig, Endpoint, TlsConfig};
pub use error::ConfigError;
pub use load::load_nodes;
pub use node::NodeConfig;
pub use protocol::Protocol;
pub use reality::NodeRealitySettings;
pub(crate) use redact::redacted;

#[cfg(test)]
mod tests;
