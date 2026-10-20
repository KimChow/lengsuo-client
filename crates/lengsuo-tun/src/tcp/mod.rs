//! 用户态 TCP 栈：被动打开（监听）与主动打开（主动 connect）两个方向。
//!
//! 四层分工，与参考实现 `app/dispatcher/default.go` 的「解析 → 分发 → 链路」结构对齐：
//! - [`segment`]：TCP 段的字节级解析与构造（无 IO）。
//! - [`state`]：单连接状态机内核（无 IO，RFC 9293 被动打开路径）。
//! - [`active`]：单连接状态机内核（无 IO，RFC 9293 主动打开路径：SYN → SYN-ACK → ACK，
//!   含同时打开与 SYN 重传计时器）。
//! - [`listener`]：把真实设备喂进来的**整个 IP 报文**接到状态机上，并用
//!   [`segment::build`] 构造回包；会话表复用现网 [`crate::session::SessionTable`]。
//! - [`connector`]：主动方向的接入层：出接口查表、IP 报文构造、入向报文分发。
//! - [`stream`]：把已 `Deliver` 的载荷交给 `AsyncRead + AsyncWrite` 的上层读端，
//!   并把上层写入经 listener 封装成段发出。
//!
//! 明确不做：打开设备、路由安装、分片重组、拥塞控制。逐条差异见 `state.rs`、
//! `active.rs` 与 `listener.rs` 末尾的「偏离清单」。

pub mod active;
pub mod connector;
pub mod ip;
pub mod listener;
pub mod segment;
pub mod state;
pub mod stream;

pub use active::{
    ActiveConfig, ActiveConnection, ActiveError, ActiveOutcome, ActiveState, OutboundSegment,
};
pub use connector::{Connector, ConnectorResult, RouteEntry, RouteTable};
pub use listener::{Config, Error, Feed, ListenerStats, TcpListener};
pub use segment::{Flags, Segment};
pub use state::{Connection, DiscardReason, Outcome, SendSegment, State};
pub use stream::{StreamPair, TcpStream};
