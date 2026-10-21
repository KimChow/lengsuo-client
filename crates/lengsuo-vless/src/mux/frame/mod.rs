//! Mux 帧编解码（对照 Xray `common/mux/frame.go`，固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）。
//!
//! 帧布局（`frame.go` 头注释逐字，端口在地址前）：
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
//! 其后是可选段：`status==New` 且 `read_source_and_local` 时的 source/local
//! 地址（参考 `Inbound.Source`/`Inbound.Local`），以及 `OptionData` 之后的
//! `BE16 数据长度 || 数据`（[`read_data`] / [`encode_data_into`]）。
//!
//! 关键语义（逐条对齐参考，不可「等价」改写）：
//! - **`metaLen` 上限 512**：`Unmarshal` 里 `if metaLen > 512 { invalid metalen }`；
//! - `SessionStatus`：New=1、Keep=2、End=3、KeepAlive=4；其余值 = unknown status；
//! - `Option`：OptionData=0x01、OptionError=0x02；
//! - `TargetNetwork`：TCP=1、UDP=2；
//! - 地址解析**只在** `status==New` 或（`status==Keep` 且余量 >4 且首字节 UDP）时进行
//!   （`MUST check the flag first`）；
//! - `status==New` 且余量为 0 或首字节为 0 时判为 heartbeat/padding，直接返回成功；
//! - 未知 network / 未知 status / 地址解析失败均 fail-closed 返回错误。
//!
//! 与参考的差异：参考 `FrameMetadata.WriteTo` 还会在 `b.UDP != nil` 时写 8 字节
//! `GlobalID`；本层不承载 GlobalID（XUDP 跨连接恢复不在本卡范围），读侧也不消费它。
//!
//! **目录结构**（拆分自原单文件 `frame.rs`，行为逐字节等价）：
//! - [`meta`]：会话状态 / 目标网络枚举 / [`FrameMetadata`] / [`FrameError`]；
//! - [`address`]：地址段 `PortThenAddress` 编解码；
//! - [`payload`]：数据段 `BE16 长度 || 数据` 的同步/异步读写与整帧写出。

mod address;
mod meta;
mod payload;

#[cfg(test)]
mod tests;

pub use address::{decode_address_port, encode_address_port};
pub use meta::{
    FrameError, FrameMetadata, SessionStatus, TargetNetwork, OPTION_DATA, OPTION_ERROR,
    SESSION_STATUS_END, SESSION_STATUS_KEEP, SESSION_STATUS_KEEP_ALIVE, SESSION_STATUS_NEW,
    TARGET_NETWORK_TCP, TARGET_NETWORK_UDP,
};
pub use payload::{
    decode_from_async, encode_data_into, read_data, read_data_async, write_frame_async,
};

/// `Unmarshal` 的 metaLen 上限（参考常量 512，硬编码）。
pub const MAX_META_LEN: usize = 512;
/// `buf.Size`：单帧数据载荷上限（参考 `PacketReader` 的 `size > buf.Size`）。
pub const DATA_LIMIT: usize = 8192;
/// 流式会话的分片大小（参考 `buf.SplitSize(mb, 8*1024)`）。
pub const STREAM_CHUNK_SIZE: usize = 8 * 1024;
