//! XEL 记录层出站原语（`lengsuo_vless::xel_wire`）的具名用例。
//!
//! 本文件验证的是**接线正确、没改语义**，三条主线：
//!
//! 1. **正常往返**：既有原语 → 新 API → 还原 ⇒ 载荷逐字节一致。
//! 2. **错误输入 fail-closed**：非法参数/截断输入 ⇒ 显式报错，不静默产出垃圾。
//! 3. **与既有实现的等价性**：新 API 的输出与既有原语的输出**逐字节相同**。
//!
//! 关键证据是第 3 条：新 API 只是**编排**（分块、方向分离、掩蔽层顺序），
//! 加密/分帧全部委托给 `crate::xel` 的既有原语。等价性用例直接拿
//! `crate::xel::record::RecordWriter` / `RecordReader` / `crate::xel::xor::XorMask`
//! 的输出与新 API 的输出对拍——任何「复制了第二份实现」的行为都会让对拍失败。
//!
//! **不声称与 Xray 进程级互通**：Xray v26.3.27（`d2758a0`）的 XEL 只能作为
//! `mlkem768x25519plus.*` 握手的一部分上线，记录层密钥由握手派生，配置里没有
//! 「注入会话密钥 / 只开记录层」的入口。既有 `tests/xel_golden.rs` 已用参考端
//! 实跑产出的黄金字节证明**记录层本身**与参考逐字节一致；本文件在此之上证明
//! **新 API 与既有原语**逐字节一致。两者串起来即：本 API 未改变记录层语义。
//!
//! **组合形态（AEAD ⊕ XOR 同时开启）的金标对齐**见子模块
//! [`reference_golden`]：既有金标只分别锁定两层，没有锁定「两层同时开启」时
//! 参考产出的线上字节——而那正是生产配置（参考 `XorMode == 2`）的形态。
//!
//! **目录结构**（按职责拆分，避免单文件超 400 行软目标）：
//! - `xel_wire/roundtrip.rs` —— 正常往返 + 与既有原语的逐字节等价；
//! - `xel_wire/framing.rs` —— 分块边界 + 错误输入 fail-closed；
//! - `xel_wire/stream.rs` —— 出站原语 `XelStream` 的真实回环 TCP 端到端。

/// 组合形态（AEAD 记录层 ⊕ XOR 头部掩蔽）的参考金标字节对拍。
#[path = "xel_wire/reference_golden.rs"]
mod reference_golden;

/// 参考二进制侧的互通边界取证（`#[ignore]`，须显式 `--ignored` 实跑）。
#[path = "xel_wire/reference_binary.rs"]
mod reference_binary;

use std::time::Duration;

use lengsuo_vless::xel::{
    aead::XelCipher,
    record::{RecordReader, RecordWriter},
    xor::XorMask,
    Error as XelError, XelKey,
};
use lengsuo_vless::xel_wire::{
    Error as WireError, XelReceiver, XelSender, XelStream, XelWireConfig, XorLayer,
    MAX_PLAINTEXT_PER_RECORD, XOR_IV_LEN,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

/// 上行 AEAD 记录密钥（假密钥）。
fn uplink_key() -> XelKey {
    XelKey::new(&[0xA1; 32]).unwrap()
}

/// 下行 AEAD 记录密钥（假密钥）。
fn downlink_key() -> XelKey {
    XelKey::new(&[0xB2; 32]).unwrap()
}

/// 错钥（假密钥，用于 fail-closed 用例）。
fn wrong_key() -> XelKey {
    XelKey::new(&[0x99; 32]).unwrap()
}

/// XOR 掩蔽层的上下行 IV。
const IV_UP: [u8; XOR_IV_LEN] = [0x11; XOR_IV_LEN];
const IV_DOWN: [u8; XOR_IV_LEN] = [0x22; XOR_IV_LEN];

/// 载荷序列：覆盖空、单字节、跨记录边界与多记录。
fn payloads() -> Vec<Vec<u8>> {
    vec![
        b"first xel wire payload".to_vec(),
        vec![0x00],
        vec![0xEE; 400],
        b"tail record \xff\x00\x80".to_vec(),
    ]
}

/// 构造一对方向（发送端 / 接收端）。
///
/// **同进程回环**：发送端用 `uplink_key`，接收端必须用**同一把** `uplink_key`
/// 解密（对端发来的就是上行方向的记录）。XOR 掩蔽层同理：接收端的 `recv_key`/
/// `recv_iv` 必须与发送端的 `send_key`/`send_iv` **完全一致**（参考 `xor.go` 的
/// `NewXorConn(conn, ctr, peerCTR, ...)`：对端的发送流就是本端的接收流，
/// 掩蔽与去掩蔽必须用同一条密钥流）。
fn pair(cipher: XelCipher, xor: bool) -> (XelSender, XelReceiver) {
    let xor_layer = if xor {
        Some(XorLayer::new(uplink_key(), &IV_UP, uplink_key(), &IV_UP).expect("IV 长度合法"))
    } else {
        None
    };
    let config = XelWireConfig {
        cipher,
        uplink_key: uplink_key(),
        downlink_key: uplink_key(),
        xor: xor_layer,
    };
    config.split().expect("配置合法")
}
// 用例按主题拆到 `tests/xel_wire/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。

include!("xel_wire/roundtrip.rs");
include!("xel_wire/framing.rs");
include!("xel_wire/stream.rs");
