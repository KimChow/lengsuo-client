//! 转发服务的配置形态：监听地址、默认节点、路由规则与超时。
//!
//! **实现已移入 `lengsuo-egress::forward_config`**（ec1）。原因：`NodeConfig`
//! 的 `forward` 字段类型就是 `ForwardConfig`，而 `NodeConfig` 已随 `config`
//! 移入 egress —— 同一类型跨 crate 拆成两份只会造出两套同名结构体，serde 与
//! `PartialEq` 都对不上。本文件只转出，`crate::forward::ForwardConfig` /
//! `load_config` / `LoadedConfig` / `DEFAULT_LISTEN` / `DEFAULT_TIMEOUT_SECS`
//! 这些既有路径逐字保持可用，`forward/mod.rs` 一行未改。

pub use lengsuo_egress::forward_config::*;
