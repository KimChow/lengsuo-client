//! 凭据体系的 Native Messaging host 侧**协议层**（纯函数、无 IO、可单测）。
//!
//! 字节布局的唯一真相是凭据线协议契约 §5.2（消息帧）与 §5.3（消息类型表）；
//! 本 crate 每个模块对应契约的一节，测试逐字节断言。
//!
//! | 模块 | 契约节 | 内容 |
//! |---|---|---|
//! | [`base64`] | RFC 4648 | 标准 base64（无 padding 编码、宽容解码）—— **信封层** |
//! | [`base64url`] | RFC 4648 §5 | base64url（无 padding）—— **载荷层**（§5.3.1） |
//! | [`envelope`] | §5.2.1 | JSON 信封 `{"frame_b64":"…"}` ⇄ 业务帧字节 |
//! | [`frame`] | §5.2 | 消息帧编解码（`len` / `type` / `reserved` / `payload`） |
//! | [`json`] | §5.3.1 | 最小 JSON（保序、整数-only、代理对、fail-closed） |
//! | [`message`] | §5.3 | 消息类型表（11 种）+ `type = 10` 回退语义 |
//! | [`payload`] | §5.3.1 | 请求 / 响应载荷字段表 + `clientDataJSON` 模板 |
//! | [`error`] | §5.2 | 类型化错误（每类失败一个具名变体） |
//!
//! ⚠️ **两层 base64 不要混用**：§5.2.1 信封层是**标准 base64**（`+`/`/`），
//! §5.3.1 载荷层是 **base64url**（`-`/`_`，无 padding），两者模块与错误类型
//! 都不同（[`base64`] / [`base64url`]）。
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

pub mod base64;
pub mod base64url;
pub mod envelope;
pub mod error;
pub mod frame;
pub mod json;
pub mod message;
pub mod payload;

pub use base64::{decode as base64_decode, encode as base64_encode, Base64Error};
pub use base64url::{decode as base64url_decode, encode as base64url_encode, Base64UrlError};
pub use envelope::{decode_frame_b64, encode_frame_b64, EnvelopeError, MAX_ENVELOPE_LEN};
pub use error::FrameError;
pub use frame::{decode, decode_exact, Frame, FRAME_HEADER_LEN, MAX_PAYLOAD_LEN, RESERVED_LEN};
pub use json::{parse as json_parse, JsonError, MAX_JSON_BYTES, MAX_JSON_DEPTH};
pub use message::{MessageType, HOST_NAME, NATIVE_RESPONSE_FALLBACK_TYPE};
pub use payload::{
    client_data_json, decode_request, encode_response, verify_nonce_echo, ClientDataKind,
    CredentialItem, CredentialKind, Decision, PayloadError, Request, Response, UserInfo,
};
