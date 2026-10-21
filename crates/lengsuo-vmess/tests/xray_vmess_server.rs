//! Xray 客户端 → 本仓 VMess 入站 互通用例（`#[ignore]`）。
//!
//! 拓扑：测试进程 --socks5--> Xray（socks 入站 + vmess outbound, aes-128-gcm）
//! --vmess/AEAD--> 本仓入站夹具 --raw TCP--> 本地回显后端。
//!
//! Xray outbound 对 AES-128-GCM 默认发 option = ChunkStream(0x01) |
//! ChunkMasking(0x04) | GlobalPadding(0x08)（outbound.go:102-114 +
//! `shouldEnablePadding`），因此本夹具覆盖「掩码 + 全局 padding」的真实默认
//! 数据面（客户端方向 option=0 简化路径之外的矩阵）。
//!
//! 断言口径（对齐 `inbound.go` 的断连时机，见 `docs/vmess-status.md`）：
//! - A：1B/4KiB/256KiB 连续载荷全链路回显，逐字节相等；
//! - B：Xray 侧配错 UUID → 本仓 `invalid user` 拒绝：隧道在 10s 内关闭且
//!   不出现请求字节的回显；不得只把「没读到」当通过；
//! - C：直连入站喂畸形头（错 cmdKey / 截断 / 错长度 tag / 错载荷 tag）：
//!   连接被关、一个字节都不回、处理线程不 panic。不依赖 Xray 二进制。
//!
//! **文件结构**：本文件是测试目标入口（原 560 行超限文件）。按职责拆到
//! `tests/xray_vmess_server/` 下：
//! - `common.rs`：选项位常量、时钟、参考二进制定位、载荷构造、回显后端、
//!   最小 socks5 CONNECT。
//! - `xray_client.rs`：Xray 客户端进程夹具（`XrayClient`）。
//! - `inbound.rs`：本仓 VMess 入站夹具（`VmessInbound` + 单连接处理）。
//! - `echo_case.rs`：用例 A（全链路回显）。
//! - `wrong_uuid_case.rs`：用例 B（错误 UUID 拒绝）。
//! - `malformed_case.rs`：用例 C（畸形头矩阵）+ `assert_rejected` 助手。
//!
//! 拆法用 `include!` **文本并入**同一模块（不是 `mod` 子模块）——这样用例名
//! **不带模块前缀**，与拆分前逐字一致（`mod` 方案会把名字变成 `echo_case::xxx`，
//! 属于改名）。代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

#[path = "support/codec_mod.rs"]
mod support;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lengsuo_vmess::aead::seal_vmess_aead_header;
use lengsuo_vmess::chunkframe::{
    open_padded_chunk, read_padded_size, seal_padded_chunk, DataCipher, DataSizeParser,
};
use lengsuo_vmess::consts::SECURITY_AES_128_GCM;
use lengsuo_vmess::request::{HeaderPlanner, KeySource, RequestHeader};
use lengsuo_vmess::server::{
    decode_request_header, encode_response_header, response_key_iv, HeaderSecurity, ResponseHeader,
};
use lengsuo_vmess::{Command as ProxyCommand, SecurityOption};
use ss_core::target::TargetAddr;
use support::codec::{cmd_key_from_uuid, generate_uuid_bytes, uuid_string};

include!("xray_vmess_server/common.rs");
include!("xray_vmess_server/xray_client.rs");
include!("xray_vmess_server/inbound.rs");
include!("xray_vmess_server/echo_case.rs");
include!("xray_vmess_server/wrong_uuid_case.rs");
include!("xray_vmess_server/malformed_case.rs");
