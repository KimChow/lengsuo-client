//! VMess AEAD 头部封装与认证响应（对齐 `proxy/vmess/aead/encrypt.go` 与
//! 旧客户端 `encoding/client.go` 的响应头路径）。
//!
//! 请求头（`SealVMessAEADHeader`）线格式：
//! ```text
//! AuthID(16) || AEAD_GCM(BE16(payload_len)) (18) || connection_nonce(8) || AEAD_GCM(payload)
//! ```
//! 两段 AEAD 都是 AES-128-GCM，AAD = AuthID 16 字节；密钥/nonce 由 KDF 链派生，
//! path 里含 AuthID 与 connectionNonce 的原始字节（Go string 可携带二进制）：
//! - 长度段：KDF16(key, "VMess Header AEAD Key_Length", authID, nonce) / KDF(key, "…Nonce_Length", …)[:12]
//! - 载荷段：KDF16(key, "VMess Header AEAD Key", authID, nonce) / KDF(key, "…Nonce", …)[:12]
//!
//! 认证响应（服务端 → 客户端，20 字节 = 4B 密文 + 16B tag）在当前 Xray 主线
//! `DecodeResponseHeader` 中已改为独立 KDF 盐 + AES-128-GCM：长度段与载荷段
//! 分别用 `KDF16(responseBodyKey, "AEAD Resp Header Len Key")` 等；无 AAD、
//! nonce 为 KDF 截 12 字节。本模块同时提供主线响应头两段解密所需的全部派生。
//!
//! **头部 AEAD 不按安全档分派。** 参考 `proxy/vmess/aead/encrypt.go` 的
//! `SealVMessAEADHeader` / `OpenVMessAEADHeader` 两侧都写死 `crypto.NewAesGcm`：
//! 安全档（`SecurityType`）只作用于**数据段**（body），由
//! [`crate::bodyframe`] 负责。因此本模块的两段头部 AEAD 恒为 AES-128-GCM，
//! 逐字节与参考一致。`seal_vmess_aead_header_with` /
//! `open_vmess_aead_header_with` 接受显式档位参数，但 ChaCha 档会
//! **fail-closed**（[`crate::Error::Unsupported`]），不会静默按 AES 处理。
//!
//! fail-closed：任何解密失败都是 [`crate::Error::AuthFailed`]，调用方必须弃用连接。
//!
//! 拆分：请求头封装/解封在 [`header`]，服务端分段/流式解头在 [`open`]，
//! 响应头两段在 [`response`]，KDF 与 AES-128-GCM 基元在 [`internal`]。

mod header;
mod internal;
mod open;
mod response;

pub use header::{
    open_vmess_aead_header, open_vmess_aead_header_with, parse_auth_id_from_header,
    seal_header_with, seal_vmess_aead_header, seal_vmess_aead_header_with, HeaderSuite,
};
pub use open::{
    open_request_header_length, open_request_header_payload, open_vmess_aead_header_stream,
    OpenHeaderError,
};
pub use response::{
    open_response_header_length, open_response_header_payload, response_header_length_key_iv,
    response_header_payload_key_iv, seal_response_header_length, seal_response_header_payload,
};

use crate::consts::{AUTH_RESPONSE_ID_SALT, CONNECTION_NONCE_LEN};

/// 连接侧随机 nonce 长度（`SealVMessAEADHeader` 的 connectionNonce）。
pub const HEADER_NONCE_LEN: usize = CONNECTION_NONCE_LEN;
/// 兼容别名：响应认证明文长度（主线响应头已不用它，保留给自建解码器测试）。
pub const RESPONSE_AUTH_LEN: usize = 4;

/// 认证响应（旧客户端 `responseHeader` 路径）的派生盐。
/// 主线 `DecodeResponseHeader` 使用 `KDF_SALT_AEAD_RESP_HEADER_*`。
pub const RESPONSE_AUTH_SALT: &[u8] = AUTH_RESPONSE_ID_SALT;

#[cfg(test)]
mod tests;
