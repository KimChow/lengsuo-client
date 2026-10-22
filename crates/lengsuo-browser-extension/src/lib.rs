//! 凭据体系的 Native Messaging host 侧**协议层**（纯函数、无 IO、可单测）。
//!
//! 字节布局的唯一真相是凭据线协议契约 §5.2（消息帧）与 §5.3（消息类型表）；
//! 本 crate 每个模块对应契约的一节，测试逐字节断言。
//!
//! | 模块 | 契约节 | 内容 |
//! |---|---|---|
//! | [`frame`] | §5.2 | 消息帧编解码（`len` / `type` / `reserved` / `payload`） |
//! | [`message`] | §5.3 | 消息类型表（11 种）+ `type = 10` 回退语义 |
//! | [`error`] | §5.2 | 类型化错误（每类失败一个具名变体） |
//!
//! # 纯函数层
//!
//! ⛔ 本 crate **不做 IO**：不碰 socket、不读写 stdin/stdout、不写注册表、
//! 不读环境变量、不访问网络。传输与登记属于后续的接线层。
//!
//! # 跨仓一致性
//!
//! 跨仓（扩展仓 / 客户端仓 / 服务端仓）之间没有代码依赖，只靠
//! **契约文档 + 固定向量文件**对齐。字节级的锚点是
//! `tests/vectors/credential-wire-v1.json`：
//! 它把帧布局、字节序、长度上限、11 种消息类型的编号、以及各类非法帧
//! 全部钉成字面量，任何一端改动字节定义都会立刻对不上。
//!
//! # 许可
//!
//! 纯手写实现，只依赖 `thiserror`（MIT/Apache-2.0）
//! ⇒ **可商用闭源**。⛔ 不含任何 GPL-3.0 实现的代码。

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod frame;
pub mod message;

pub use error::FrameError;
pub use frame::{decode, decode_exact, Frame, FRAME_HEADER_LEN, MAX_PAYLOAD_LEN, RESERVED_LEN};
pub use message::{MessageType, HOST_NAME, NATIVE_RESPONSE_FALLBACK_TYPE};
