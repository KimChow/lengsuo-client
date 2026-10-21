//! L2 会话 fail-closed 与失效用例。
//!
//! 覆盖任务书 §七 的 6–8 条：
//! 6. **认证失败 ⇒ 失效**：用错误密钥解封 ⇒ 错误可区分（`AuthFailed` 类），
//!    **不回退明文**，且会话被标记为**已失效**。
//! 7. **失效后拒绝收发**：会话失效后再调封/解 ⇒ 明确错误，**不静默成功**。
//! 8. **错误密钥字节不外泄**：会话对象的 `Debug` / 错误文本**不含**密钥字节。
//!
//! 全部是**测试专用假密钥**（0x11 / 0x22 / 0x5A / 0x99 模式字节），不代表任何
//! 真实凭据。对端公钥由仓外独立实现（Python `cryptography` 的 X25519）算出后
//! 写死 ⇒ 不依赖本仓的 X25519 代码自证。
//!
//! ⚠️ 本文件**不**证明与任何真实 WireGuard 端互通。

use std::time::Instant;

use lengsuo_link_core::frame::{FrameType, FRAME_HEADER_LEN};
use lengsuo_link_core::session::{Session, SessionConfig, SessionError, SessionRole, SessionState};

// 用例按主题拆到 `tests/session_failclosed/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致（`mod`
// 方案会把名字变成 `failclosed::xxx` 等，属于改名）。代价是分文件之间不能重复
// `use`，故所有 `use` 都留在本入口文件。
include!("session_failclosed/common.rs");
include!("session_failclosed/fail_closed.rs");
include!("session_failclosed/no_leak.rs");
