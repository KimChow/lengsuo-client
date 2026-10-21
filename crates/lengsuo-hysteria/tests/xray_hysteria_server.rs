//! 与参考 Xray 的**服务端方向**互通验收（本仓服务端 ← 官方 Xray 客户端）。
//! 全部 `#[ignore]`：须用 `--ignored` 实跑，禁止用自家 roundtrip 冒充。
//!
//! 形态：本仓 `HysteriaServer` 监听 QUIC（ALPN=h3、openssl 现场自签证书进
//! 临时目录）；官方 Xray 以**客户端**身份运行（socks 入站 + hysteria v2
//! outbound，`streamSettings.network=hysteria` + `security=tls`，`serverName`
//! 指向自签证书 SAN），Xray 的 freedom... 不，客户端 outbound 把 socks 流量
//! 打到本仓服务端，服务端直连目标 echo。
//!
//! - 用例 A：TCP echo，1B / 4KiB / 256KiB 逐字节（经 socks 客户端 → 本仓服务端）。
//! - 用例 B：UDP 往返（socks UDP associate）。
//! - 用例 C：错误 auth —— Xray 客户端会因 404 建连失败；断言本仓服务端
//!   对该连接不建立任何承载（由客户端日志/失败体现）。
//!
//! 注：用例 C 的「错误 auth → masquerade 404」断言在本仓服务端侧由
//! `tests/rust_roundtrip.rs::wrong_auth_rust_roundtrip` 直接锁定（同一条参考
//! 路径）；此处以 Xray 官方客户端复验，断言其**无法**完成建连。

// 用例按主题拆到 `tests/xray_hysteria_server/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream as StdTcpStream, UdpSocket as StdUdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use lengsuo_hysteria::quic::server::{HysteriaServer, ServerConfig};

mod support;

const AUTH: &str = "lengsuo-interop-password";
const SERVER_NAME: &str = "localhost";

include!("xray_hysteria_server/harness.rs");
include!("xray_hysteria_server/world.rs");
include!("xray_hysteria_server/scenarios.rs");
