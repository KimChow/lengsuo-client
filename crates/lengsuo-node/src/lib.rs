#![forbid(unsafe_code)]
//! lengsuo-node — 出口节点运行时（八协议出口：配置 / 分发 / dry-run / 转发）。
//!
//! - `config`：节点配置的 JSON 加载、校验与脱敏 Debug。**实现已移入
//!   `lengsuo-egress`**（ec1），本 crate 只转出，路径不变。
//! - `outbound` / `outbound_*`：按协议分发到本仓各协议 crate 的客户端 API 与
//!   各协议的具体拨号实现（每种一个模块，便于单独审计）。**同样已移入
//!   `lengsuo-egress`**，由下面的 `pub use` 转出。
//! - `route`：按目标地址选节点（规则形态、specificity 排序、冲突检测）。
//!   随 `config` 一起移入 `lengsuo-egress`（`ConfigError::Route` 承载
//!   `RouteError`，两者必须同 crate）。
//! - `dryrun`：每节点握手到认证完成并汇报结果，不传业务载荷。
//! - `forward`：**流量转发服务**（本地 SOCKS5 监听 → 选节点 → 出站会话 →
//!   双向转发），fail-closed，绝不回落到直连。留在本 crate；其**配置形态**
//!   `forward::config` 已移入 `lengsuo-egress::forward_config` 并由该处转出。
//!
//! 已接入：trojan / anytls / vless / vmess / shadowsocks / ss2022 /
//! hysteria / wireguard。**能真正转发载荷的只有 trojan 与 shadowsocks**，
//! 其余六协议本卡只到握手。状态与未做项见 `docs/node-status.md`。

pub mod dryrun;
pub mod forward;
pub mod relay_bridge;

pub use lengsuo_egress::{
    config, outbound, outbound_anytls, outbound_hysteria, outbound_ss, outbound_ss2022,
    outbound_trojan, outbound_vless, outbound_vmess, outbound_wireguard, route,
};
