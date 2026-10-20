//! REALITY 服务端握手状态的辅助类型与工具函数。
//!
//! 从 [`super`] 拆出以符合 400 行软目标；公开 API 不变。

use super::super::ed25519;
use super::super::messages::handshake_type;
use super::super::messages::SIG_ED25519;
use super::super::schedule::TrafficKey;

/// 从 ClientHello 握手消息里取出 `legacy_session_id`。
///
/// 布局（RFC 8446 §4.1.2）：
/// `type(1) + length(3) + legacy_version(2) + random(32) + session_id_len(1)
/// + session_id(n)`。
///
/// 参考 `handshake_server_tls13.go:270` 把这个值原样回显到 ServerHello。
/// 解析失败时返回空向量（服务端回显空 session_id 仍是合法的 TLS 1.3 行为）。
pub(super) fn client_session_id(client_hello_raw: &[u8]) -> Vec<u8> {
    // 4（消息头）+ 2（legacy_version）+ 32（random）= 38 是长度字节的位置。
    const LEN_OFFSET: usize = 4 + 2 + 32;
    if client_hello_raw.len() <= LEN_OFFSET {
        return Vec::new();
    }
    let len = usize::from(client_hello_raw[LEN_OFFSET]);
    let start = LEN_OFFSET + 1;
    match client_hello_raw.get(start..start + len) {
        Some(bytes) => bytes.to_vec(),
        None => Vec::new(),
    }
}

/// 应用数据阶段的双向记录层密钥。
pub struct ServerSessionKeys {
    /// 客户端 → 服务端。
    pub client: TrafficKey,
    /// 服务端 → 客户端。
    pub server: TrafficKey,
}

/// TLS 1.3 `CertificateVerify` 的被签消息（RFC 8446 §4.4.3）。
///
/// 对齐参考 `auth.go:82` 的 `signedMessage`。
pub fn server_signed_message(transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + 33 + 32);
    out.extend_from_slice(&[0x20u8; 64]);
    out.extend_from_slice(b"TLS 1.3, server CertificateVerify\x00");
    out.extend_from_slice(transcript_hash);
    out
}

/// `Finished` 消息类型常量（供调用方判断）。
pub const FINISHED_TYPE: u8 = handshake_type::FINISHED;

/// Ed25519 签名算法常量（供调用方判断）。
pub const ED25519_SIGNATURE_ALGORITHM: u16 = SIG_ED25519;

/// 常量时间比较的薄封装（`subtle` 的 `ConstantTimeEq` 只实现了定长数组）。
pub(super) trait ConstantTimeSliceEq {
    /// 与等长切片做常量时间比较，返回 1（相等）或 0（不等）。
    fn ct_eq_slice(&self, other: &[u8]) -> u8;
}

impl ConstantTimeSliceEq for [u8; 32] {
    fn ct_eq_slice(&self, other: &[u8]) -> u8 {
        if other.len() != self.len() {
            return 0;
        }
        let mut diff = 0u8;
        for (a, b) in self.iter().zip(other.iter()) {
            diff |= a ^ b;
        }
        // diff == 0 → 1
        u8::from(diff == 0)
    }
}

/// 生成 Ed25519 签名（供调用方复用服务端签名路径）。
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    ed25519::SigningKey::from_seed(seed).sign(message)
}
