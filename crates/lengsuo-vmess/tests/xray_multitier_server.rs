//! **多安全档**反向互通：Xray 客户端 → 本仓 VMess 入站（`#[ignore]`，需 `LENGSUO_XRAY`）。
//!
//! 运行方式：
//! ```text
//! LENGSUO_XRAY=~/ref/bin/xray cargo test -p lengsuo-vmess --test xray_multitier_server --locked -- --ignored --nocapture
//! ```
//!
//! 拓扑：
//! ```text
//! 测试进程 --SOCKS5--> Xray（SOCKS 入站 + VMess 出站，security=<档位>）
//!                --VMess--> 本仓入站夹具 --TCP--> 本地回显后端
//! ```
//!
//! 判据：回程与发送载荷**逐字节一致**（1B / 4KiB / 256KiB 三段，跨越参考
//! 8192 字节单帧边界）；入站处理线程不得 panic；全程有超时上限。
//!
//! 参考事实（固定 commit `d2758a02`）：
//! - 参考**出口**按账号安全档分派数据段：`proxy/vmess/outbound/outbound.go`
//!   的 `request.Security = account.Security`，再由
//!   `proxy/vmess/encoding/client.go` 的 `EncodeRequestBody` 落成具体套件。
//! - 参考出口的默认 option 是 `ChunkStream | ChunkMasking | GlobalPadding`
//!   （`outbound.go`：`shouldEnablePadding` 对 AES/ChaCha/AUTO 为真）；
//!   `none` 档则**不带** `GlobalPadding`（`shouldEnablePadding` 对 NONE 为假），
//!   但**带** `ChunkStream`（参考 NONE 分支需要它）。
//! - 请求头 / 响应头两段 AEAD **恒为 AES-128-GCM**，与档位无关。
//!
//! 本仓入站侧的档位处理（对齐参考 `proxy/vmess/encoding/server.go`）：
//! - 头里的 security 低 4 位决定数据段套件（`parseSecurityType`）；
//! - `none` 档 + `ChunkStream` + TCP ⇒ `ChunkStreamReader`（明文载荷、无 padding）；
//! - 其余档位 ⇒ `AuthenticationReader`（AEAD 载荷 + 三种长度段形态）。
//!
//! **文件结构**：本文件是测试目标入口（原 586 行超限文件）。按职责拆到
//! `tests/xray_multitier_server/` 下：
//! - `common.rs`：超时常量、参考二进制定位、时钟、回显后端、载荷构造、
//!   最小 socks5 CONNECT。
//! - `xray_client.rs`：Xray 客户端进程夹具（`XrayClient`，含档位/实验开关）。
//! - `inbound.rs`：本仓 VMess 入站夹具（`VmessInbound` + 单连接处理）。
//! - `every_tier.rs`：方向 B / B'（逐档位回显，含认证长度段变体）。
//! - `tier_mismatch.rs`：档位错配负例。
//!
//! 拆法用 `include!` **文本并入**同一模块（不是 `mod` 子模块）——这样用例名
//! **不带模块前缀**，与拆分前逐字一致（`mod` 方案会把名字变成 `every_tier::xxx`，
//! 属于改名）。代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。
//!
//! ⚠️ 本文件与 `tests/xray_vmess_server.rs` 的助手**同名**（`xray_bin` /
//! `now_unix` / `spawn_echo_backend` / `start_vmess_inbound` / `handle_connection` /
//! `socks5_connect`）。两者是**各自独立的测试目标**（独立编译单元），故各留
//! 副本、互不共享——刻意不提取到公共模块，避免跨文件耦合。

#[path = "support/mod.rs"]
mod support;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lengsuo_vmess::bodyframe::{BodyFrame, BodySuite, ChunkStreamFrame};
use lengsuo_vmess::server::{
    decode_request_header, encode_response_header, response_key_iv, HeaderSecurity, ResponseHeader,
};
use ss_core::target::TargetAddr;
use support::codec::{cmd_key_from_uuid, generate_uuid_bytes, uuid_string};
use support::tiercodec::Tier;

include!("xray_multitier_server/common.rs");
include!("xray_multitier_server/xray_client.rs");
include!("xray_multitier_server/inbound.rs");
include!("xray_multitier_server/every_tier.rs");
include!("xray_multitier_server/tier_mismatch.rs");
