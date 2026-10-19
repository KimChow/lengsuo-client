#![forbid(unsafe_code)]
//! lengsuo-node — 出口节点运行时（第一版：trojan + anytls 的配置 / 分发 / dry-run）。
//!
//! - `config`：节点配置的 JSON 加载、校验与脱敏 Debug。
//! - `outbound`：按协议分发到本仓各协议 crate 的客户端 API，不复制 Xray。
//! - `dryrun`：每节点握手到认证完成并汇报结果，不传业务载荷。
//!
//! 状态与未做项见 `docs/node-status.md`。

pub mod config;
pub mod dryrun;
pub mod outbound;
