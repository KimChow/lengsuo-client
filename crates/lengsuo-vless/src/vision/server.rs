//! VLESS Vision **服务端侧**流量层：对齐 `proxy.go` 的 `VisionReader` /
//! `VisionWriter`（服务端：上行读 = `Inbound` 状态组，下行写 = `Inbound` 状态组；
//! [客户端侧](super::client)对称地走上行写 / 下行读 = `Outbound` 状态组）。
//!
//! 场景：官方 Xray 客户端（outbound vless `flow=xtls-rprx-vision`）→ 本仓服务端。
//! - 上行（服务端读）：解 `XtlsPadding` 块（命令 + 内容 + padding），首块含 16 字节
//!   UUID；命令 `Continue(0)` 继续、`End(1)` 结束 padding、`Direct(2)` 结束并切直拷贝。
//! - 下行（服务端写）：在 padding 期按参考规则给下行数据加 padding 块，`IsTLS` /
//!   `IsTLS12orAbove` 决定是否走 TLS 应用数据捷径与长 padding；首包为空时插入一条
//!   0 内容 `Continue` 长 padding 块。
//!
//! 与客户端侧共用 [`super::client`] 的状态模型、[`super::framing`] 的
//! `is_complete_record` / `reshape_payload`、[`super::rand_below`] 与
//! [`super::padding`] 的握手 padding 参数，故本模块只补「服务端方向」这一层。
//!
//! 对齐口径：本模块只实现**流量层**（padding / 解帧 / 直拷贝切换判据），不含
//! REALITY、通用多会话 Mux / XUDP 跨连接、也不做 splice 内核直拷贝——
//! `enable_xtls` 判据按参考转写，真机直拷贝切换留给呼叫方（与客户端侧一致）。
//!
//! **目录结构**（拆分自原单文件 `server.rs`，行为逐字节等价）：
//! - `session`：服务端会话状态机主体 [`VisionServer`]；
//! - `tests`：单元测试。
//!
//! 本模块不含 `unsafe`。

mod session;

#[cfg(test)]
mod tests;

pub use session::VisionServer;
