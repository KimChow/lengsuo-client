#![forbid(unsafe_code)]
//! lengsuo-node — 出口节点运行时（八协议出口：配置 / 分发 / dry-run / 转发）。
//!
//! - `config`：节点配置的 JSON 加载、校验与脱敏 Debug。
//! - `outbound`：按协议分发到本仓各协议 crate 的客户端 API，不复制 Xray。
//! - `outbound_*`：各协议的具体拨号实现（每种一个模块，便于单独审计）。
//! - `dryrun`：每节点握手到认证完成并汇报结果，不传业务载荷。
//! - `route`：按目标地址选节点（规则形态、specificity 排序、冲突检测）。
//! - `forward`：**流量转发服务**（本地 SOCKS5 监听 → 选节点 → 出站会话 →
//!   双向转发），fail-closed，绝不回落到直连。
//!
//! 已接入：trojan / anytls / vless / vmess / shadowsocks / ss2022 /
//! hysteria / wireguard。**能真正转发载荷的只有 trojan 与 shadowsocks**，
//! 其余六协议本卡只到握手。状态与未做项见 `docs/node-status.md`。

pub mod config;
pub mod dryrun;
pub mod forward;
pub mod outbound;
pub mod outbound_anytls;
pub mod outbound_hysteria;
pub mod outbound_ss;
pub mod outbound_ss2022;
pub mod outbound_trojan;
pub mod outbound_vless;
pub mod outbound_vmess;
pub mod outbound_wireguard;
pub mod relay_bridge;
pub mod route;
