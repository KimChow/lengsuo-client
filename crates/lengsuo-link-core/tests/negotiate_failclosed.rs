//! L4 通道协商 fail-closed 与错误码稳定性用例。
//!
//! 覆盖任务书 §七 的 5–7 条：
//! 5. **协商不上不许默认直连**：协商失败 ⇒ 明确错误码，**不**产生「默认 p2p」的结果。
//! 6. **错误码稳定**：同一个失败场景 ⇒ 错误码（数字或标签）**完全一致**
//!    （用断言锁死，⛔ 不断言 Rust `Debug` 文本）。
//! 7. **载荷超限拒绝**：协商消息明文超 `MAX_PLAIN_LEN` ⇒ 明确错误，**不截断**。
//!
//! 全部是**测试专用假密钥**（0x11 / 0x22 模式字节），不代表任何真实凭据。
//!
//! ⚠️ 本文件**不**证明与任何真实对端互通。

use std::time::Instant;

use lengsuo_link_core::frame::{FrameType, MAX_PLAIN_LEN};
use lengsuo_link_core::negotiate::{
    decode_control, Capability, CapabilitySet, ChannelMode, ErrorCode, MessageKind, ModeSet,
    NegotiateError, NegotiateState, NegotiationExtension, NegotiationMessage, Negotiator,
    NegotiatorRole, NEGOTIATE_HEADER_LEN,
};
use lengsuo_link_core::session::Generation;

// 用例按主题拆到 `tests/negotiate_failclosed/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致（`mod`
// 方案会把名字变成 `capability::xxx` 等，属于改名）。代价是分文件之间不能重复
// `use`，故所有 `use` 都留在本入口文件。
include!("negotiate_failclosed/common.rs");
include!("negotiate_failclosed/capabilities.rs");
include!("negotiate_failclosed/error_codes.rs");
