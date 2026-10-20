//! 主动方向的接入层：路由查表、IP 报文构造、入向报文分发。
//!
//! 本模块是 [`crate::tcp::active`] 状态机与「链路」之间的胶水层，分两个子模块：
//! - [`route`]：出接口路由表（最长前缀匹配，纯内存、由调用方注入）。
//! - [`connect`]：报文构造与入向分发。
//!
//! **不打开设备、不写 socket、不读系统路由表**：`crate::route` 只提供系统路由的
//! 安装/撤销原语，不提供查表。出站报文的长度受接口 MTU 约束：超 MTU 一律
//! fail-closed 报错，不发超大报文、不分片。
//!
//! 明确不做：不实现分片、不做拥塞控制、不做 PMTUD 探测、不碰真实网卡。

pub mod connect;
pub mod route;

pub use connect::{Connector, ConnectorResult};
pub use route::{RouteEntry, RouteTable};

// ---- 与 RFC 9293 / Linux 的有意差异（逐条列出）----
//
// 1. 路由表由调用方注入：本 crate 的 `src/route.rs` 只提供系统路由的安装/撤销
//    原语，不提供查表，也没有读取系统路由表的能力；出接口选择因此是纯内存的。
// 2. 出站报文固定 IPv4 IHL=5 / IPv6 固定 40 字节，不带 IP 选项，不分片。
// 3. 出站报文只做一次接口 MTU 判定，超 MTU 直接报错，不做 PMTUD 下调。
// 4. 入向报文只处理 TCP；地址族不一致、四元组不匹配、校验和失败一律拒绝。
// 5. 不做分片重组、不做拥塞控制、不碰真实网卡与 socket。
