//! Hysteria2 的 HTTP/3 认证（对齐 Xray `transport/internet/hysteria/dialer.go`
//! `client.dial` 的 RoundTrip 部分与 `config.go` 常量）。
//!
//! 认证在 QUIC 握手完成后、任何业务流之前进行，走一条双向请求流上的
//! `POST https://hysteria/auth`：
//!
//! ```text
//! 请求头:  Hysteria-Auth: <密码>            （机密，错误信息/日志不回显）
//!          Hysteria-CC-RX: <BrutalDown 十进制>
//!          Hysteria-Padding: <[256,2048) 随机字母数字>
//! 响应:    状态码 233 = 认证通过
//!          Hysteria-UDP: <bool，是否开放 UDP datagram>
//!          Hysteria-CC-RX: <服务端 BrutalDown>
//!          Hysteria-Padding: <随机填充>
//! ```
//!
//! 非 233（如 masquerade 的 404）一律 [`AuthError::Rejected`]；任何失败都会
//! 以错误码 0x101（HTTP/3 GeneralProtocolError，参考 `closeErrCodeProtocolError`）
//! 关闭 QUIC 连接。HTTP/3 帧（RFC 9114）与 QPACK 头部块（RFC 9204，含动态表、
//! RIC 回绕与 Huffman 解码，能解 quic-go/qpack 的任意合规输出）由本 crate 手写，
//! 原因见 `qpack` 模块文档（依赖冻结拿不到 `http` crate）。
//!
//! ## datagram 发送缓冲（Bytes 桥）
//!
//! 依赖冻结拿不到 `bytes` crate，而 `quinn::Connection::send_datagram` 只接受
//! `bytes::Bytes`。两条互补路径，均无需命名该 crate：
//!
//! 1. **直接构造**（[`send_datagram_direct`]）：`Bytes: From<Vec<u8>>`，用一个
//!    返回类型由调用点推断的泛型函数（`make_datagram_buffer`）即可从 `&[u8]`
//!    造出 `Bytes`——类型经 `send_datagram` 的入参唯一确定。这是服务端与
//!    客户端的常规发送路径（每调用一次分配）。
//! 2. **复用接收缓冲**（[`SeedFiller`] / [`seed_filler_from_chunk`]）：
//!    `read_chunk` 有时返回独占引用计数的 `Bytes`，`try_into_mut` → 写入 →
//!    `freeze` 可复用该缓冲，省一次分配。属于可选优化，池空时回退路径 1。
//!
//! 认证期间读到的响应 chunk 会顺手生成一次性「种子发送器」
//! （[`H3ControlStreams::take_seeds`]）交给 `quic::client` 的 UDP 层做首包发送。
//!
//! ## 子模块
//!
//! | 子模块 | 职责 |
//! |---|---|
//! | [`constants`] | 线上头名、状态码、关闭码、HTTP/3 帧/流类型 |
//! | [`error`] | [`AuthError`]（错误文本不回显密码） |
//! | [`outcome`] | [`AuthOutcome`] 与 [`H3ControlStreams`] |
//! | [`datagram`] | datagram 发送的 Bytes 桥（[`SeedFiller`]） |
//! | [`random`] | 随机源与 padding 串生成 |
//! | [`flow`] | 认证流程（建流 → 写 HEADERS → 读响应 → 解码 → 校验） |

mod constants;
mod datagram;
mod error;
mod flow;
mod outcome;
mod random;

pub use constants::*;
pub use datagram::{seed_filler_from_chunk, send_datagram_direct, SeedFiller};
pub use error::AuthError;
pub use flow::authenticate;
pub use outcome::{AuthOutcome, H3ControlStreams};
pub use random::{random_padding, random_u64};

// 供服务端模块（`h3_server`）复用的类型别名（与客户端侧同一份语义）。
pub(crate) use crate::padding::Range as ServerPaddingRange;
pub(crate) use crate::qpack::HeaderField as ServerHeaderField;
