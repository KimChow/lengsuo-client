//! 传统 Shadowsocks AEAD 的 TCP 双向 Xray 真实互通测试（仅回环、假口令）。
//!
//! 本文件把 `src/tcp.rs` 的字节 chunk 层接到固定基线 Xray（v26.3.27 /
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）上跑真实 TCP 中继，两个方向各自
//! spawn 一次参考进程并在结束时 `kill`（`support::Reference` 的 `Drop`）：
//!
//! 1. `rust_client_to_xray_server_tcp`：本端 `TcpWriter` 写 salt +
//!    `TargetAddr::encode_checked` 的目标地址 + 载荷，Xray 的 shadowsocks 入站
//!    解出地址并经 freedom 出站连到本仓 spawn 的 echo 服务，回程由
//!    `TcpReader` 读取，逐字节核对等于 echo 内容。
//! 2. `xray_client_to_rust_server_tcp`：Xray 的 socks 入站接收本端 SOCKS5 请求，
//!    shadowsocks 出站连到本端监听器；本端用 `TcpReader`（服务端视角）解请求
//!    方向、中继到 echo 目标，再用 `TcpWriter` 写回程，核对端到端载荷。
//!
//! 载荷规格取 1 / 512 / 8158（= `MAX_SEGMENT_PAYLOAD`，单 chunk 明文上限）/
//! 8158+4096（超上限，必须跨 chunk）。所有异步读写都由 `tokio::time::timeout`
//! 约束，读到 EOF 之前先关写半；不修改任何产品代码来迁就互通。
//!
//! 首段明文本就是上层写的地址（本层不解析），所以测试侧自己负责在重组字节上
//! 续读地址；地址未读满时 `TargetAddr::decode` 报错即继续取下一个 chunk。

#[path = "../../lengsuo-trojan/tests/support/mod.rs"]
mod support;

#[path = "xray_tcp/mod.rs"]
mod xray_tcp;
