//! VLESS Vision 客户端流量层：对齐 `proxy.go` 的 `TrafficState` / `VisionWriter` /
//! `VisionReader` / `XtlsPadding` / `XtlsUnpadding` / `XtlsFilterTls` /
//! `IsCompleteRecord` / `ReshapeMultiBuffer`，以及 outbound `postRequest` 的
//! **首包直发决策**（有数据 → 立即随 VLESS 头一起发；无数据 → 插入 0 内容长
//! padding 块遮蔽头长度）。
//!
//! 本模块只做客户端一侧：上行写、下行读都落在 [`TrafficState`] 的
//! `Outbound` 状态组（客户端对端是 Xray 入站的 `Inbound` 状态组）。
//! 不含 REALITY、多会话 Mux / XUDP 跨连接，也不做 splice 内核直拷贝——
//! `EnableXtls` 判据虽按参考转写，但真机直拷贝切换是呼叫方的事。
//!
//! 与参考的一处**有意补强（报告偏离清单）**：参考客户端在上行 EOF 时不会显式补发
//! `COMMAND_PADDING_END`，依赖 `NumberOfPacketToFilter` 倒数（>7 块）或 TLS inner
//! 记录边界来结束 padding；本实现提供 [`VisionClient::encode_uplink_finish`]，若
//! 半关闭时仍处于 padding 状态，则补发一条 0 内容 `End` 块，使 Xray 入站尽早退出
//! padding 状态（协议层字节与参考 `XtlsPadding(…, COMMAND_PADDING_END, …)` 完全一致）。
//!
//! **目录结构**（拆分自原单文件 `client.rs`，行为逐字节等价）：
//! - [`state`]：流量状态模型 [`TrafficState`] / [`InboundState`] / [`OutboundState`]；
//! - [`filter`]：TLS 识别（`XtlsFilterTls`）与 padding 长度决策；
//! - [`vision_client`]：客户端主体 [`VisionClient`]（上行写 / 下行读）；
//! - [`tests`]：单元测试。
//!
//! 本模块不含 `unsafe`。

mod filter;
mod state;
mod vision_client;

#[cfg(test)]
mod tests;

pub use state::{InboundState, OutboundState, TrafficState};
pub use vision_client::VisionClient;

/// 参考 `IsCompleteRecord`（判断一个缓冲是否恰好含一条完整 TLS 记录）。
///
/// 拆分前由 `client.rs` 直接 `pub use super::framing::is_complete_record;` 导出；
/// 拆分后原导出路径丢失，此处**原样恢复**，保持外部可见路径不变。
pub use super::framing::is_complete_record;

/// 参考 `proxy.go` 事件字节。
pub const COMMAND_PADDING_CONTINUE: u8 = 0x00;
/// 参考 `proxy.go` 事件字节。
pub const COMMAND_PADDING_END: u8 = 0x01;
/// 参考 `proxy.go` 事件字节。
pub const COMMAND_PADDING_DIRECT: u8 = 0x02;

/// 参考 `common/buf.Size`。
pub const BUF_SIZE: usize = 8192;

/// 参考默认测试种子（`{900, 500, 900, 256}`）。
pub const DEFAULT_TEST_SEED: [u32; 4] = [900, 500, 900, 256];

/// 参考 `XtlsFilterTls`（单 buffer 形态：`payload` 非 nil 时才调用，且只降一档）。
pub(crate) use filter::xtls_filter_tls_single;

/// 参考 `XtlsPadding` 的 padding 长度决策（纯函数，rng 注入）。
pub(crate) use filter::padding_length;
