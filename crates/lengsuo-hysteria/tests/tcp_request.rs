//! Hysteria2 TCPRequest 帧测试。
//!
//! 只覆盖本 crate 的帧编解码原语：不证明 QUIC 连接、HTTP/3 伪装认证、
//! UDP 中继或与参考实现的双向互通已完成。
//! 地址与 padding 均为测试专用假值，不含真实凭据。

// 用例按主题拆到 `tests/tcp_request/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

use lengsuo_hysteria::tcp::{
    TcpRequest, FRAME_TYPE_TCP_REQUEST, MAX_ADDRESS_LENGTH, MAX_PADDING_LENGTH,
};
use lengsuo_hysteria::varint::MAX_VALUE;
use lengsuo_hysteria::Error;

include!("tcp_request/helpers.rs");
include!("tcp_request/basic.rs");
include!("tcp_request/truncation.rs");
include!("tcp_request/types.rs");
include!("tcp_request/address.rs");
include!("tcp_request/framing.rs");
include!("tcp_request/limits.rs");
