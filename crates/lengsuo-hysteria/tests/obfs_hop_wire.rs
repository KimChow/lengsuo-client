//! Hysteria2 的 **Salamander 混淆** 与 **端口跳跃** 接入真实链路后的互通取证。
//!
//! 全部 `#[ignore]`：须用 `--ignored` 实跑（需要参考二进制 `LENGSUO_XRAY`）。
//!
//! 五个方向：① **可证伪基线**（参考服务端开掩码 ⇒ 本仓不混淆的客户端必须
//! 连不上）；② 本仓客户端 → 参考服务端；③ 参考客户端 → 本仓服务端；
//! ④ 口令不符必须失败（先立对照组）；⑤ 端口跳跃的 socket 层取证。
//!
//! 参考侧配置（`streamSettings.finalmask.udp[].settings.password`）来自
//! `infra/conf/transport_internet.go:1720/1889` 与
//! `transport/internet/finalmask/salamander/config.proto`（`password`）。
//!
//! # 参考侧的线上格式
//!
//! `finalmask.go` 走 **header 分支**（`salamander/config.go:18` 的 `HeaderConn()`）：
//! `headerManagerConn.WriteTo` 把载荷拷到 `writeBuf[8:]`（留 8 字节头部余量），
//! 交给 `salamanderConn.WriteTo` 做 `Obfuscate(p[8:], p)` —— **用头部余量装盐**。
//! 上线路字节 = `[8 字节盐][载荷 ^ BLAKE2b256(PSK||盐)]`，与本仓
//! `transport/wire.rs` 逐字节一致。

// 用例按主题拆到 `tests/obfs_hop_wire/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

use std::io::IoSliceMut;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use lengsuo_hysteria::obfs::{B2sumDeriver, Blake2b256, Obfuscator, SALT_LEN};
use lengsuo_hysteria::proxy;
use lengsuo_hysteria::quic::{
    ClientConfig, HysteriaClient, HysteriaServer, ObfsHopConfig, ServerConfig,
};
use lengsuo_hysteria::transport::{
    hop, HopSpec, MaskedUdpSocket, OsRng, PortList, TransportRng, WireMask,
};

mod support;

include!("obfs_hop_wire/harness.rs");
include!("obfs_hop_wire/client.rs");
include!("obfs_hop_wire/interop.rs");
include!("obfs_hop_wire/hop.rs");
include!("obfs_hop_wire/regress.rs");
