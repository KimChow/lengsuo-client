//! VLESS XEL 记录层的 Rust↔Rust 跨进程互通（真实回环 TCP）。
//!
//! **为什么不是与 Xray 互通**：Xray v26.3.27（`d2758a0`）里 XEL 只能作为
//! `mlkem768x25519plus.*` 会话握手的一部分上线——`proxy/vless/encryption/xor.go`
//! 的 `NewXorConn` 只在 `ServerInstance`/`ClientInstance` 握手内部建立，密钥与 IV 都
//! 来自握手派生的 `UnitedKey`；`common.go` 的记录密钥同样由
//! `NewAEAD(握手 ctx, UnitedKey, useAES)` 派生。配置里没有"注入会话密钥"或
//! "只开记录层"的路径：`encryption`/`decryption` 取 `"xor"` 会被配置解析直接拒绝
//! （可执行留证见 `tests/xray_xel_blocker.rs`）。因此本文件两端都用本 crate 实现，
//! 验证记录层在跨进程字节流上的语义；**与 Xray 的 XEL 互通状态为未互通**，
//! 阻塞点与解锁条件记录在 `docs/vless-status.md`。
//!
//! 拓扑：父进程 = client 角色；对端 = 同一个测试二进制用 `--exact --ignored`
//! 再启动一次的子进程（server 角色），用例名与端口经 `LENGSUO_XEL_CASE` /
//! `LENGSUO_XEL_PORT` 交接；子进程输出写入系统临时目录日志，失败时回读并 panic。
//! 密钥全部是测试假密钥，且不写入日志。
//!
//! 每个读操作都由 `tokio::time::timeout` 约束；接收端只有在对端已关闭写半之后
//! 才把流读到 EOF。`aead-xor` / `xor-only` 用 XOR 掩蔽器覆盖整条双向流，
//! 分块切分点刻意不规则（1/3/4/5/997/2048 字节），迫使跨进程流在任意切分下
//! 都保持分帧与密钥流连续。
//!
//! **目录结构**（按职责拆分，避免单文件超 400 行软目标）：
//! - `xel_interop/harness.rs` —— 假密钥、用例判定与线上字节构造；
//! - `xel_interop/process.rs` —— 跨进程收发与对端子进程；
//! - `xel_interop/aead.rs` —— AEAD 记录层互通用例；
//! - `xel_interop/xor.rs` —— XOR 掩蔽 / 纯分帧互通用例；
//! - `xel_interop/rejects.rs` —— 失效流必须 fail-closed 的用例。

use lengsuo_vless::xel::{
    aead::XelCipher,
    frame::{RecordFramer, RecordHeader},
    record::{RecordReader, RecordWriter},
    xor::XorMask,
    Error, XelKey,
};
use std::{
    net::Ipv4Addr,
    process::{Child, Command, ExitStatus, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Instant},
};
// 用例按主题拆到 `tests/xel_interop/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

include!("xel_interop/harness.rs");
include!("xel_interop/process.rs");
include!("xel_interop/aead.rs");
include!("xel_interop/xor.rs");
include!("xel_interop/rejects.rs");
