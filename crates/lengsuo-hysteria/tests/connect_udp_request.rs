//! CONNECT-UDP 请求消息测试。
//!
//! 只覆盖本 crate 的消息层编解码原语：不证明 HTTP/3 Extended CONNECT 协商、
//! QUIC 连接、认证 token、UDP 中继或与原生 apernet/hysteria 的双向互通已完成。
//! 地址与 padding 均为测试专用假值，不含真实凭据。

// 用例按主题拆到 `tests/connect_udp_request/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

use lengsuo_hysteria::connect_udp::{ConnectUdpRequest, REQUEST_TYPE_CONNECT_UDP};
use lengsuo_hysteria::tcp::{MAX_ADDRESS_LENGTH, MAX_PADDING_LENGTH};
use lengsuo_hysteria::varint::MAX_VALUE;
use lengsuo_hysteria::Error;
use std::time::Duration;

include!("connect_udp_request/helpers.rs");
include!("connect_udp_request/basic.rs");
include!("connect_udp_request/limits.rs");
include!("connect_udp_request/truncation.rs");
include!("connect_udp_request/types.rs");
include!("connect_udp_request/address.rs");
include!("connect_udp_request/framing.rs");
include!("connect_udp_request/encoding.rs");
