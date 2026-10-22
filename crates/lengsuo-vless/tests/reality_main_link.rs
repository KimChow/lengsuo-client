//! REALITY 接入 VLESS **主连接链路** 的实跑取证。
//!
//! 与 `reality_xray_server.rs`（→ 参考服务端）不同，这里对端是**本仓**的
//! REALITY + TLS 1.3 服务端；两端都走 `lengsuo_vless::stream` 的**主链路**函数：
//!
//! ```text
//! 客户端：RealitySettings → RealityConfig::from_settings → RealityStream::connect
//!        → stream::send_request（VLESS 头）→ 载荷 → stream::receive_response
//! 服务端：accept_hello → TLS 1.3 → stream::receive_request → 回环 echo
//!        → stream::send_response → 载荷
//! ```
//!
//! 全部回环地址、临时端口、运行时生成的假凭据；每个网络操作都有截止时间。
//! 日志不输出任何密钥材料。
//!
//! **目录结构**（按职责拆分，避免单文件超 400 行软目标）：
//! - `reality_main_link/harness.rs` —— 本仓 REALITY 服务端与握手走查夹具；
//! - `reality_main_link/cases.rs` —— 主链路贯通 / 默认路径 / 非法配置三条用例。

mod support;

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use lengsuo_vless::header::{Command, Request};
use lengsuo_vless::reality::server::{accept_hello, RealityServerConfig};
use lengsuo_vless::reality::session::server_handshake;
use lengsuo_vless::reality::tls13::io::{
    HandshakeCollector, Inbound, Outbound, RecordReader, RecordWriter,
};
use lengsuo_vless::reality::tls13::server::ServerHandshake;
use lengsuo_vless::reality::x25519::{x25519, x25519_base};
use lengsuo_vless::reality_config::{ConfigError, RealityConfig, RealitySettings};
use lengsuo_vless::reality_link::RealityStream;
use lengsuo_vless::stream;
use ss_core::target::TargetAddr;
use support::{base64_url, free_ports, SeededRng, KEY, WAIT};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::{TcpListener, TcpStream},
    time::timeout,
};

/// 用例总截止时间。
const DEADLINE: Duration = Duration::from_secs(30);
/// 单次建流的截止时间。
const HANDSHAKE: Duration = Duration::from_secs(10);
const SERVER_NAME: &str = "www.example.com";
/// 服务端白名单里的短 ID（配置里的十六进制文本 → `[0x31..0x38]`）。
const SHORT_ID_HEX: &str = "3132333435363738";
const SHORT_ID: [u8; 8] = *b"12345678";
const PAYLOAD: &[u8] = b"reality main-link payload\0\xff\xfe binary";
// 用例按主题拆到 `tests/reality_main_link/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

include!("reality_main_link/harness.rs");
include!("reality_main_link/cases.rs");
