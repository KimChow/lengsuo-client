//! L1×L2 接线：把 `link-core` 的 `Link<Session, Transport>` 接进 PC 端运行时。
//!
//! # 缺口（本模块补上的那个）
//!
//! `lengsuo-link-core::transport` 定义了 L1 [`Transport`] 与接线层 [`Link`]，
//! 但生产路径上只有测试用的 `Loopback`。PC 端的 L1 一直是本 crate 自己的
//! `udp::UdpEndpoint`，L2 也一直是 [`crate::assembly`] 自己调 `Keypair::seal`。
//! ⇒ PC 与移动端跑的是**两套 L2**，跨端迟早漂移。
//!
//! 本模块把 `UdpEndpoint` 适配成 [`Transport`]，于是 PC 端也能：
//!
//! ```text
//! Link::new(session, UdpTransport::new(endpoint))
//! ```
//!
//! 收发一律经过 `Link::send_frame` / `Link::recv_frame` ⇒ 明文只在
//! `Session::seal_frame` 一处变成密文，⛔ **没有明文旁路**。
//!
//! # 同步 ↔ 异步桥
//!
//! [`Transport`] 是**同步** trait，[`UdpEndpoint`] 是 tokio **异步**。
//! 桥的做法是**两个后台任务 + 两条有界队列**：
//!
//! - 异步的那一半留在任务里 `.await`；
//! - 同步的这一半只做 `try_send` / `try_recv`；
//! - 队列空 ⇒ `WouldBlock`（不是失败）。
//!
//! 为什么**不用** `block_on`（在运行时里会 panic、且钉死 reactor）、
//! 为什么**不用** `std::net::UdpSocket`（同步 `recv` 阻塞 reactor）、
//! 为什么**不新开** socket（[`UdpEndpoint`] 已处理 connected 语义与 MTU 预算），
//! 以及粘性故障槽的语义，见 [`transport`] 的模块文档。
//!
//! # 用法
//!
//! [`spawn_link`] 是唯一的生产入口：它造 [`UdpTransport`] 并返回
//! [`Link<Session, UdpTransport>`]。⚠️ 必须在 tokio 运行时内调用。

use lengsuo_link_core::session::Session;
use lengsuo_link_core::transport::Link;

use crate::udp::UdpEndpoint;

mod transport;

pub use transport::UdpTransport;

/// 生产接线入口：会话 + UDP 端点 ⇒ 一条可收发的 [`Link`]。
///
/// 内部启动两个后台任务（见 [`UdpTransport`]）；`Link` 被丢弃时它们随之退出。
///
/// ⚠️ 必须在 tokio 运行时内调用（内部 `tokio::spawn`）。
#[must_use]
pub fn spawn_link(session: Session, endpoint: UdpEndpoint) -> Link<UdpTransport> {
    Link::new(session, UdpTransport::new(endpoint))
}
