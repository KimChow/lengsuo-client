//! Rust 客户端 ↔ 真实 Xray VMess 入站的 `RequestCommand_UDP` 互通（ignored）。
//!
//! 运行方式（缺 `LENGSUO_XRAY` 时每个用例明确打印原因并 return，不静默通过）：
//! ```text
//! LENGSUO_XRAY=/path/to/xray cargo test -p lengsuo-vmess --test xray_udp --locked -- --ignored --nocapture
//! ```
//!
//! 报文语义（固定 commit d2758a02，逐条给出参考出处）：
//! - `proxy/vmess/inbound/inbound.go:281`：UDP 与 TCP 同走 `dispatcher.Dispatch`，
//!   目的地来自请求头 `Destination()`（`common/protocol/headers.go:55-60`，
//!   `RequestCommandUDP` → UDP 目的地）——请求头即关联语义，无额外握手。
//! - `proxy/vmess/encoding/server.go:264-330`：请求/响应体加解密与命令字节无关，
//!   但 `Command.TransferType()`（`common/protocol/headers.go:21-30`）把 UDP 映射为
//!   `TransferTypePacket` 传入 `crypto.AuthenticationReader/Writer`
//!   （`common/crypto/auth.go:206-226,325-351`）。
//! - `AuthenticationReader.readInternal`（auth.go:179-186）：明文 ≤ `buf.Size`(8192)
//!   的 chunk 解密后整体保留在一个 buf.Buffer 里 → vmess 入站
//!   `buf.Copy(bodyReader, link.Writer)`（inbound.go:291）按 buffer 转发。
//! - freedom 出站对 UDP 目的地用 `NewPacketWriter`（`proxy/freedom/freedom.go:176`），
//!   其 `WriteMultiBuffer`（freedom.go:354-411）把每个 buffer 按**一个 UDP 数据报**
//!   写出（`b.UDP == nil` 时经 `PacketConnWrapper.Write` 写往拨号目的地，
//!   `transport/internet/system_dialer.go:161-163`）→ 一个 VMess chunk = 一个数据报，
//!   载荷为原始数据，vmess 层无 SOCKS5 式 RSV/FRAG/ATYP 头。
//! - 回程：freedom `NewPacketReader`/`PacketReader`（freedom.go:246-302）每个
//!   数据报一个 buffer → `transferResponse`（inbound.go:187-223）在 Packet 模式下
//!   由 `AuthenticationWriter.writePacket` 每 buffer 封一 chunk（auth.go:325-343）
//!   → 回程同样一 chunk = 一数据报。
//! - 数据报上限 `buf.Size` = 8192（`common/buf/buffer.go:13`）。
//!
//! **多目标语义**：传统 `RequestCommand_UDP` 的关联目的地唯一（请求头只写一个
//! 地址）。参考要在一连接上多目标，走 mux-in-vmess（`v1.mux.cool`）：vmess
//! outbound 对 UDP+cone 改写为 `RequestCommandMux + v1.mux.cool:666` 并用
//! `xudp.NewPacketWriter` 封包（`proxy/vmess/outbound/outbound.go:88-92,149-157,172`；
//! Mux 请求头**不写地址**：`encoding/client.go:80-84`）。服务端 mux
//! `handleStatusNew` 派发（`common/mux/server.go:165-279`），UDP 会话
//! `transferType = TransferTypePacket`（server.go:277-280），数据帧由
//! `mux.PacketReader` 按「2B 长度 + 原始载荷」逐包读出（reader.go:29-53），
//! Keep 帧处理在 `common/mux/server.go:300-321`；响应帧格式见
//! `common/mux/frame.go` 注释块与 `writer.go:71-90`。
//! （cone 由本卡测试配置显式开启；默认未开时参考客户端不会自动切 mux。）
//!
//! **偏离说明**：本仓 `request::Command` 无 Mux 变体（`request.rs:42-70`，
//! `Command::from_byte(3) == None`），`HeaderPlanner::plan` 对命令 3 直接拒绝
//! （request.rs:199-206）。因此用例 B 的 mux 请求头明文在测试内按参考
//! `client.go:63-89` 手工构造（38 字节定长段 + FNV），经
//! `aead::seal_vmess_aead_header` 封装；这是测试侧代码，不改 `src/`。
//!
//! `src/udp.rs` 的 SOCKS5 封装（RSV|FRAG|ATYP|ADDR|PORT|DATA）在 vmess 入站
//! 路径上参考并不解析：该格式属于 SOCKS 入站的 UDP associate
//! （`proxy/socks/server.go:211-239`、`proxy/socks/protocol.go:324-363`）。
//! 本文件不使用它；实跑结论与修 `src/udp.rs` 的建议见报告。
//!
//! **文件结构**：本文件是测试目标入口（原 531 行超限文件）。用例按主题拆到
//! `tests/xray_udp/` 下：
//! - `common.rs`：超时常量、参考二进制定位、UDP 回显后端、传统关联建连、
//!   数据段 cipher、单数据报往返助手。
//! - `classic_assoc.rs`：用例 A1/A2（IPv4 目标 / 域名目标）。
//! - `two_associations.rs`：用例 B（两条关联并行、不交叉投递）。
//! - `local_and_truncated.rs`：用例 C1（构造期超限）与 C2（截断流）。
//! - `wrong_uuid.rs`：用例 C3（错误 UUID）。
//! - `unbound_port.rs`：用例 C4（目标端口无监听，不挂死）。
//!
//! 拆法用 `include!` **文本并入**同一模块（不是 `mod` 子模块）——这样用例名
//! **不带模块前缀**，与拆分前逐字一致（`mod` 方案会把名字变成 `classic_assoc::xxx`，
//! 属于改名）。代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

#[path = "support/mod.rs"]
mod support;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use lengsuo_vmess::chunkframe::{self, DataCipher};
use lengsuo_vmess::consts::SECURITY_AES_128_GCM;
use lengsuo_vmess::request::{Command, KeySource};
use lengsuo_vmess::udp::MAX_UDP_PAYLOAD;
use ss_core::target::TargetAddr;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpStream, UdpSocket};

use support::codec;
use support::XrayFixture;

include!("xray_udp/common.rs");
include!("xray_udp/classic_assoc.rs");
include!("xray_udp/two_associations.rs");
include!("xray_udp/local_and_truncated.rs");
include!("xray_udp/wrong_uuid.rs");
include!("xray_udp/unbound_port.rs");
