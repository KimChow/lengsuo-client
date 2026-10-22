//! UDP 传输层（L1）：socket 封装 + 收发循环。
//!
//! 本模块把「一个 UDP socket + 一个 peer 地址」变成「一个能收能发的端点 +
//! 一个有明确结束条件的收发循环」，让上层（隧道装配卡）能把
//! `lengsuo-link-core` 的密文帧丢进 UDP、把收到的 UDP 交给上层。
//!
//! # 分层位置
//!
//! **L1 传输**。搬运的是**已经封好的密文包**（`Frame::encode` 的输出），
//! **不做** AEAD 封/解（那在 `lengsuo-link-core` 的 L2/L3）。
//!
//! # 三件事
//!
//! 1. **socket 封装**（[`UdpEndpoint`]）：绑定 / 连接一个本地 UDP socket，
//!    记录对端地址，提供 `send_frame` / `recv_frame` / `send_raw` / `recv_raw`。
//! 2. **收发循环**（[`spawn_recv_loop`]）：异步收循环，事件走 channel，
//!    **有明确的结束条件**（取消 / 通道关闭 / socket 级错误）。
//! 3. **对端地址可更新**（[`UdpEndpoint::set_peer_endpoint`]）：为 endpoint
//!    漫游留口（协议侧归后续卡）。
//!
//! # 裸握手 vs L3 帧（**两种线上格式**）
//!
//! | 报文 | 线上格式 | 收路径 |
//! |---|---|---|
//! | L2 握手（initiation / response / cookie） | **裸** UDP 数据报（148 / 92 / 64B），⛔ 不套帧头 | [`UdpEndpoint::recv_raw`] + [`classify`] |
//! | L3 密文帧 | 20B 帧头 + 载荷 | [`UdpEndpoint::recv_frame`] |
//!
//! 收循环用 [`UdpEndpoint::recv_raw`] 收**裸数据报**，再按**首字节**分流
//! （[`datagram::classify`]）⇒ 裸握手以 [`UdpEvent::Handshake`] 交给上层，
//! L3 帧以 [`UdpEvent::Frame`] 交给上层。
//!
//! # 两级错误语义
//!
//! | 级别 | 触发 | 上层动作 | 类型 |
//! |---|---|---|---|
//! | **单包级** | 一个数据报解不开 | **只丢这一包**，循环继续 | [`UdpError::BadDatagram`] |
//! | **连接级** | socket 层出错（对端不可达等） | **上报**并结束循环 | [`UdpError::Socket`] |
//!
//! 判据用 [`UdpError::severity`]（机器可判定），见 [`ErrorSeverity`]。
//!
//! # keepalive
//!
//! 本卡**只提供发 keepalive 的能力**（[`spawn_keepalive`]），
//! **间隔与开关由上层配**（[`KeepaliveConfig::interval`]）——
//! 本 crate 里**没有**任何写死的节奏常量。

pub mod datagram;
pub mod error;
pub mod keepalive;
pub mod loop_;
pub mod socket;

pub use self::datagram::{classify, Datagram, DatagramError, HandshakeKind};
pub use self::error::{ErrorSeverity, UdpError};
pub use self::keepalive::{spawn_keepalive, KeepaliveConfig, KeepaliveHandle, KeepaliveOutcome};
pub use self::loop_::{
    spawn_recv_loop, Cancel, LoopHandle, LoopOutcome, UdpEvent, DEFAULT_RECV_QUEUE_CAPACITY,
};
pub use self::socket::{UdpEndpoint, MIN_RECV_BUFFER_LEN};
