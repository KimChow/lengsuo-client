//! VMess 服务端（入站方向）原语：请求头解码 + 响应头封装。
//!
//! 语义来源（只读参考，Go 侧同类，固定 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）：
//! - `proxy/vmess/encoding/server.go`：`DecodeRequestHeader`（AuthID 校验 + 头
//!   AEAD 解密 + 字段解析 + FNV 校验）与响应头封装路径。
//! - `proxy/vmess/inbound/inbound.go`：认证失败时的 drain 量与断连时机（决定
//!   互通测试的断言口径，见 `docs/vmess-status.md`）。
//! - `proxy/vmess/encoding/encoding.go`：地址段 `addrParser` 的读取端
//!   （PortThenAddress）。
//!
//! 边界：本模块只做「单连接请求头解码 / 响应头封装」原语与驱动它们的同步/
//! 异步函数；**不做**监听器、多账号管理、路由与策略——那是上层的事。
//! 重放过滤（session history）以回调注入，语义对齐参考 `server.go` 的
//! `SessionHistory.addIfNotExits`：键是 `(user, requestBodyKey, requestBodyIV)`
//! 三元组（3 分钟过期由调用方实现），**不是** AuthID。

pub mod decode;
pub mod respond;

pub use decode::{
    decode_request_header, DecodedRequest, HeaderDecodeError, HeaderSecurity, InboundCommand,
    SessionFilter,
};
pub use respond::{
    encode_response_header, response_key_iv, ResponseHeader, RESPONSE_HEADER_WIRE_LEN,
};
