#![forbid(unsafe_code)]
//! lengsuo-node — 出口节点运行时（八协议出口：配置 / 分发 / dry-run）。
//!
//! - `config`：节点配置的 JSON 加载、校验与脱敏 Debug。
//! - `outbound`：按协议分发到本仓各协议 crate 的客户端 API，不复制 Xray。
//! - `outbound_*`：各协议的具体拨号实现（每种一个模块，便于单独审计）。
//! - `dryrun`：每节点握手到认证完成并汇报结果，不传业务载荷。
//!
//! 已接入：trojan / anytls / vless / vmess / shadowsocks / ss2022 /
//! hysteria / wireguard。状态与未做项见 `docs/node-status.md`。

pub mod config;
pub mod dryrun;
pub mod outbound;
pub mod outbound_hysteria;
pub mod outbound_ss;
pub mod outbound_ss2022;
pub mod outbound_vless;
pub mod outbound_vmess;
pub mod outbound_wireguard;
