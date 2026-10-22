//! 客户端配置与分流规则。
//!
//! 规则语义、字段与限制条件对齐参考实现
//! `crates/ss-client/src/config.rs`（原 504 行死代码），差异只在**动作集合**：
//! 客户端没有 listen 语义，只有 `direct` / `proxy`，以及每规则的带宽上限。
//!
//! 模块分工：
//! - [`types`]：与文件格式无关的数据模型、默认值与校验；
//! - [`toml`]：TOML 子集读取器（手写，**不新增依赖**，见
//!   `docs/ss-client-config-activate.md` 偏离清单 D1）；
//! - [`load`]：反序列化与跨字段校验；
//! - [`matcher`]：规则匹配（首条命中 + 三态结论）；
//! - `ss_url`：`ss://` URL 的解析与校验。
//!
//! **凭据纪律**：`ss_url` 内含口令。[`OutboundConfig`] 的 `Debug` 走手写实现
//! 脱敏；所有错误消息只带字段名与形状，**不回显**口令 / 密钥 / 源行原文。

mod load;
mod matcher;
mod ss_url;
mod toml;
mod types;

pub use load::{load_config, load_config_str};
pub use matcher::{Decision, MatchOutcome, Target};
pub use types::{
    Action, ClientConfig, DnsConfig, Match, MuxConfig, OutboundConfig, PortRange, Rule,
};
