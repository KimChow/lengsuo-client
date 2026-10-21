//! Mux 会话状态机（对照 Xray `common/mux/{session,client,server}.go`
//! 固定 commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。
//!
//! 本模块对齐的是**帧语义与会话管理**，不是参考的 goroutine/buf.Pipe 结构：
//!
//! - `SessionManager` → [`SessionTable`]：`(id → state)`，`Allocate` 自增 id 分配、
//!   `Add`/`Remove`/`Get`、`Close` 全清；
//! - 客户端 `ClientWorker` 的 `fetchOutput` 状态分派 →
//!   [`ClientSession::handle_frame`]（New/Keep/KeepAlive/End 各自语义）；
//! - 客户端 `fetchInput` 的首包 `writeFirstPayload` →
//!   [`StreamSender::send_new`]（`SendFlow` 空闲时发 New 帧，随后 Keep 帧）；
//! - 服务端 `ServerWorker.handleStatusNew/handleStatusKeep/handleStatusEnd` →
//!   [`ServerSession::handle_frame`]（本层不含 dispatcher，改由调用方注入
//!   「建立目标流」的回调 [`TargetDialer`]）。
//!
//! 本层只做**同步**状态机 + 字节流编解码：网络收发由调用方驱动（见
//! `tests/xray_mux.rs` 的夹具），符合本 crate「原语层不做网络」的定位。
//!
//! 拆分：会话表与策略在 [`table`]，流通道抽象在 [`sink`]，服务端状态机在
//! [`server`]，客户端状态机在 [`client`]，输入侧封装器与读端迭代器在
//! [`stream`]。

mod client;
mod server;
mod sink;
mod stream;
mod table;

pub use client::ClientSession;
pub use server::ServerSession;
pub use sink::{DiscardSink, StreamSink, TargetDialer};
pub use stream::{
    address_port_len, encode_frame_with_payload, read_address_port, FrameReader, StreamSender,
};
pub use table::{SessionState, SessionStrategy, SessionTable};
