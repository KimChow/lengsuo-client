//! VMess 请求头明文构造（对齐 `proxy/vmess/encoding/client.go` 的
//! `EncodeRequestHeader` 明文段 + `common/protocol` 的地址写法）。
//!
//! 明文布局（封装前的 buffer.Bytes()，封装见 [`crate::aead`]）：
//! ```text
//! Version(1)=1 | requestBodyIV(16) | requestBodyKey(16) | responseHeader(1)
//! | Option(1) | security(1)=paddingLen<<4|sec | 0x00(1) | Command(1)
//! | 地址(PortThenAddress, 见 [`crate::address`]) | padding(0..16 随机) | FNV1a(前面全部)(4)
//! ```
//! - Command == Mux(3) 时**不含地址**（参考 `addrParser.WriteAddressPort` 被跳过）。
//! - paddingLen 由 `dice.Roll(16)` 生成（0..15），写进 security 高 4 位；
//!   padding 字节为随机。
//! - FNV1a 32 位校验覆盖从 Version 到 padding 结束的全部字节。
//! - 地址段是 VMess 自身的 **Port(BE16) | AddrType(1|2|3) | ADDR**，不是 ss-core
//!   `TargetAddr::encode_into`/`encode_checked` 的 SOCKS5 `ATYP | ADDR | Port`；
//!   误用后者是本层此前的协议偏离（已由固定字节向量锁定修正）。
//!
//! 范围与限制：Security 只支持 none / AES-128-GCM / ChaCha20-Poly1305 与
//! autocipher 哨兵（由调用方解析）；legacy（SecurityType_Legacy）与 Mux 命令
//! 不实现（返回 [`crate::Error::Unsupported`]，fail-closed 不静默降级）。
//!
//! 拆分：枚举与密钥来源在 [`model`]，请求头字段集与规划器在 [`planner`]，
//! FNV-1a 与 `CipherSpec` 在 [`checksum`]。

mod checksum;
mod model;
mod planner;

pub use checksum::{fnv1a32, CipherSpec};
pub use model::{Command, KeySource, SecurityOption};
pub use planner::{HeaderPlanner, RequestHeader};

use crate::consts::{HEADER_IV_LEN, HEADER_KEY_LEN, VMESS_VERSION};

/// 请求头版本字节。
pub const KEY_LEN: usize = HEADER_KEY_LEN;
/// 请求头对称密钥长度。
pub const NONCE_LEN: usize = HEADER_IV_LEN;
/// 请求头 IV 长度。
pub const VMESS_VERSION_BYTE: u8 = VMESS_VERSION;
/// Mux 命令字节（本层不实现）。
pub const CMD_MUX: u8 = 3;

#[cfg(test)]
mod tests;
