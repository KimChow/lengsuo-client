//! Mux 帧编解码（对照 Xray `common/mux/frame.go` 固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。
//!
//! 帧布局（`frame.go` 头注释逐字）：
//! ```text
//! 2 bytes - length      // metaLen，不含自身
//! 2 bytes - session id  // BE16
//! 1 bytes - status
//! 1 bytes - option
//! -------------------- 以上 4 字节计入 metaLen
//! 1 byte  - network     // 仅 status==New（或 Keep+UDP 目标）时出现
//! 2 bytes - port        // PortThenAddress：端口在前
//! n bytes - address
//! ```
//! 其后可选:`status==New` 时的 source/local 地址（`Inbound.Source` 语义，
//! 本层不写、读侧按 `read_source_and_local` 开关消费），以及 `OptionData`
//! 之后的 `BE16 数据长度 || 数据`（[`read_data`] / [`encode_data_into`]）。
//!
//! 关键语义（逐条对齐参考，不可「等价」改写）：
//! - **`metaLen` 上限 512**：`Unmarshal` 里 `if metaLen > 512 { invalid metalen }`；
//! - `SessionStatus`：New=1、Keep=2、End=3、KeepAlive=4；其余值 = unknown status；
//! - `Option`：OptionData=0x01、OptionError=0x02；
//! - `TargetNetwork`：TCP=1、UDP=2（与 VMess 请求头命令字节同值但**不同域**）；
//! - 地址解析**只在** `status==New` 或（`status==Keep` 且余量 >4 且首字节 UDP）时进行
//!   （`MUST check the flag first`）；
//! - `status==New` 且余量为 0 或首字节为 0 时判为 heartbeat/padding，直接返回成功；
//! - 未知 network / 未知 status / 地址解析失败均 fail-closed 返回错误。
//!
//! 与参考的字段差异：参考的 `FrameMetadata.Inbound`（reverse mux）本层不承载，
//! 读侧以 [`FrameMetadata::source`]/[`FrameMetadata::local`] 暴露原始地址对，
//! 由调用方决定是否使用（写侧恒不发，等价于 `Inbound == nil` 且 `b.UDP == nil`）。
//!
//! 拆分：状态/网络枚举与帧元数据在 [`meta`]，地址段编解码在 [`address`]，
//! 会话数据段读写在 [`data`]，帧错误类型在 [`error`]。

mod address;
mod data;
mod error;
mod meta;

pub use address::{decode_address_port, encode_address_port};
pub use data::{encode_data_into, read_data};
pub use error::FrameError;
pub use meta::{FrameMetadata, SessionStatus, TargetNetwork, MAX_META_LEN, SESSION_CHUNK_SIZE};

/// `OptionData`。
pub const OPTION_DATA: u8 = 0x01;
/// `OptionError`。
pub const OPTION_ERROR: u8 = 0x02;

/// `SessionStatusNew`。
pub const SESSION_STATUS_NEW: u8 = 0x01;
/// `SessionStatusKeep`。
pub const SESSION_STATUS_KEEP: u8 = 0x02;
/// `SessionStatusEnd`。
pub const SESSION_STATUS_END: u8 = 0x03;
/// `SessionStatusKeepAlive`。
pub const SESSION_STATUS_KEEP_ALIVE: u8 = 0x04;

/// `TargetNetworkTCP`。
pub const TARGET_NETWORK_TCP: u8 = 0x01;
/// `TargetNetworkUDP`。
pub const TARGET_NETWORK_UDP: u8 = 0x02;

#[cfg(test)]
mod tests;
