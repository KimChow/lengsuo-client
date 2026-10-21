//! L2 会话往返用例：握手 → 收发 → 世代号递增 → 重连重建 responder。
//!
//! 覆盖任务书 §七 的 1–5 条：
//! 1. 握手成功：双方在同一进程内完成一次握手，得到一致的会话状态。
//! 2. 收发往返：封一帧明文 ⇒ 对方解回**逐字节相同**的明文。
//! 3. 世代号递增：第一次握手 ⇒ 世代号 = 初始值；重连（第二次握手）⇒ 世代号 +1。
//! 4. 重连可重建 responder：同一对密钥**连续握手两次都成功**。
//! 5. 角色固定：发起方与响应方的角色在会话对象上显式可见。
//!
//! 全部是**测试专用假密钥**（0x11 / 0x22 模式字节），不代表任何真实凭据。
//! 对端公钥用**仓外独立实现**（Python `cryptography` 的 X25519）算出后写死
//! 在本文件里——不依赖本仓的 X25519 代码自证。
//!
//! ⚠️ 本文件**不**证明与任何真实 WireGuard 端互通：只证明本卡会话状态机的
//! 握手编排、密钥落地、世代号与重连语义自洽。

use std::time::{Duration, Instant};

use lengsuo_link_core::frame::FrameType;
use lengsuo_link_core::session::{
    Generation, Session, SessionConfig, SessionError, SessionRole, SessionState,
};

// 用例按主题拆到 `tests/session_roundtrip/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致（`mod`
// 方案会把名字变成 `roundtrip::xxx` 等，属于改名）。代价是分文件之间不能重复
// `use`，故所有 `use` 都留在本入口文件。
include!("session_roundtrip/common.rs");
include!("session_roundtrip/roundtrip.rs");
include!("session_roundtrip/generation.rs");
