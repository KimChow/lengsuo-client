//! VLESS XEL / Mux 回环夹具：本仓服务端 ↔ node 出站。
//!
//! ⛔ **本文件只覆盖 Rust↔Rust 回环**：对端是**本仓**协议 crate 的服务端原语，
//! **不**声称与参考实现（Xray `d2758a023cd7…`）互通。参考侧（固定版本 Xray）在
//! **库层**已有真实对端证据（`crates/lengsuo-vless/tests/xray_vision.rs` 等）；
//! **node 侧**与参考对端的互通**尚未验证**（见本卡报告偏离清单）。
//!
//! 全部只绑回环、只用临时端口（`127.0.0.1:0` 交给内核分配）、只用假凭据。
//! 每个网络操作都有截止时间；日志不输出任何密钥材料。

#![allow(dead_code)]

use std::collections::HashMap;
use std::time::Duration;

use lengsuo_node::config::NodeConfig;
use lengsuo_tls::{PrivatePkcs8KeyDer, TlsServer};
use lengsuo_vless::header::Command;
use lengsuo_vless::mux::frame::{decode_from_async, read_data_async, SessionStatus, TargetNetwork};
use lengsuo_vless::mux::worker::{Action, MuxServer, SessionWriter};
use lengsuo_vless::stream::{receive_request, send_response};
use lengsuo_vless::xel::aead::XelCipher;
use lengsuo_vless::xel::XelKey;
use lengsuo_vless::xel_wire::{XelStream, XelWireConfig};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// 单步截止时间（建流 / 帧读写）。
pub const WAIT: Duration = Duration::from_secs(8);
/// 用例总截止时间。
pub const DEADLINE: Duration = Duration::from_secs(30);
/// 测试用 UUID（假凭据；服务端与 node 侧共用同一份）。
pub const UUID: &str = "11111111-1111-1111-1111-111111111111";
/// 服务端读 VLESS 头时用的凭据（与 UUID 文本的 16 字节一致）。
pub const KEY: [u8; 16] = [0x11; 16];
/// 回环载荷（含二进制字节）。
pub const PAYLOAD: &[u8] = b"node vless xel payload\0\xff\xfe binary";
/// 篡改用例的载荷长度（远大于一条 VLESS 头记录 ⇒ 偏移可安全落在载荷密文里）。
pub const BIG_PAYLOAD_LEN: usize = 4096;
/// 篡改用例的翻转偏移（**记录层**下行方向的第 N 个字节）。
///
/// 记录层下行字节流 = 响应头记录（`5` 字节记录头 + `2` 字节明文 + `16` 字节 tag =
/// `23` 字节）‖ 载荷记录（`5` 字节记录头 + 密文 + `16` 字节 tag）⇒ 载荷密文从
/// 第 `28` 字节开始。取 `128` ⇒ 稳稳落在载荷密文里，既不碰响应头记录，也不碰
/// 记录头（AAD）与末尾 tag。
pub const TAMPER_OFFSET: usize = 128;
/// 记录层与传输层之间的桥接管道容量（篡改用例用）。
const BRIDGE_CAPACITY: usize = 64 * 1024;

/// 客户端 XEL 上行密钥（假材料，运行时常量 ⇒ 不是真凭据）。
pub const XEL_UPLINK_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
/// 客户端 XEL 下行密钥（假材料）。
pub const XEL_DOWNLINK_HEX: &str =
    "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
/// 服务端故意用错的密钥（⇒ 客户端的 AEAD 认证必然失败）。
pub const XEL_WRONG_HEX: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
/// 服务端的上行密钥（= 客户端的**下行**密钥；方向相对客户端对调）。
pub const XEL_SERVER_UPLINK_HEX: &str = XEL_DOWNLINK_HEX;
/// 服务端的下行密钥（= 客户端的**上行**密钥）。
pub const XEL_SERVER_DOWNLINK_HEX: &str = XEL_UPLINK_HEX;

/// 双向流抽象（读 + 写）。
pub trait Duplex: AsyncRead + AsyncWrite + Unpin {}
impl<T> Duplex for T where T: AsyncRead + AsyncWrite + Unpin {}

/// 装箱后的双向流。
pub type BoxedDuplex = Box<dyn Duplex>;

include!("support/fixture.rs");
include!("support/mux.rs");
