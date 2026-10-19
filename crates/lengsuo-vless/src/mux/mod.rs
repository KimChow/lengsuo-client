//! 通用多会话 Mux（对照 Xray `common/mux/`，固定 commit
#![doc = "`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。"]
//!
//! 分两块：
//! - [`frame`]：帧编解码（`frame.go`），与 `lengsuo-vmess` 的 `muxframe` 同一语义；
//! - [`worker`]：会话表与两端状态机（`session.go`/`client.go`/`server.go`/`writer.go`），
//!   数据面由调用方驱动（见 [`worker`] 模块头）。
//!
//! VLESS 侧入口：客户端用 `command=Mux`、目标 `v1.mux.cool:9527` 建立承载连接
//! （参考 `proxy/vless/outbound` 的 `Target: net.TCPDestination(muxCoolAddress, muxCoolPort)`），
//! 服务端识别该目标后把整条连接交给 [`worker::MuxServer`]。

pub mod frame;
pub mod worker;

/// `muxCoolAddress`：承载连接的目标域名（参考 `client.go`）。
pub const MUX_COOL_ADDRESS: &str = "v1.mux.cool";
/// `muxCoolPort`：承载连接的目标端口（参考 `client.go`）。
pub const MUX_COOL_PORT: u16 = 9527;
