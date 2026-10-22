//! UDP（XUDP）over REALITY 的端到端用例。
//!
//! 覆盖两层：
//!
//! 1. [`roundtrip`] —— 正向路径：本仓 REALITY 服务端 ↔ 本仓 REALITY 客户端，
//!    UDP 报文经 REALITY 承载往返（IPv4 / IPv6 / 域名目标 + 目标归属）。
//! 2. [`negative`] —— 异常路径：截断 / 篡改 / 超长，一律 fail-closed。
//!
//! **硬约束**：只用回环地址、临时端口、假凭据；日志不输出密钥/明文/口令；
//! 每个网络操作都有截止时间。

mod negative;
mod roundtrip;
mod support;
