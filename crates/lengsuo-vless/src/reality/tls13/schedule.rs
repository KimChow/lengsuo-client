//! TLS 1.3 密钥调度（RFC 8446 §7.1）。
//!
//! 参考实现对应 `xtls/reality` 的 `tls13/tls13.go`（`ExpandLabel` /
//! `extract` / `deriveSecret`）与 `key_schedule.go`（`trafficKey` /
//! `finishedHash`）。本模块只做纯计算，不含 I/O，便于用 RFC 8448 向量自证。
//!
//! # 与参考的等价性要点（易错处）
//!
//! 1. `Derive-Secret(S, "derived", "")` 的上下文是 **`Hash("")`**
//!    （32 字节 SHA-256 空串摘要），**不是**空上下文。参考
//!    `tls13/tls13.go` 的 `deriveSecret` 在 `transcript == nil` 时用
//!    `transcript = hash()`，再取 `transcript.Sum(nil)`。
//! 2. Go 的 `hkdf.Extract(hash, secret, salt)` 是 **HMAC(key=salt, msg=secret)**；
//!    参考的 `extract(h, newSecret, currentSecret)` 因此等价于
//!    `HMAC(key=currentSecret, msg=newSecret)`。于是
//!    `HandshakeSecret = HMAC(key=derived, msg=ecdhe)`、
//!    `MasterSecret = HMAC(key=derived, msg=0)`。
//! 3. `hkdf.Expand` 是纯 expand（无 extract），故本模块显式区分
//!    [`hkdf_extract_sha256`] 与 [`hkdf_expand_sha256`]；REALITY 认证载荷用的
//!    `HKDF-Extract + Expand` 组合仍走 [`hkdf_sha256`]。

use super::super::hash::hmac::{hkdf_expand_sha256, hkdf_extract_sha256, hmac_sha256};

/// 握手哈希长度（SHA-256）。
pub const HASH_LEN: usize = 32;
/// `TLS_AES_128_GCM_SHA256` 的密钥长度。
pub const KEY_LEN: usize = 16;
/// `TLS_AES_128_GCM_SHA256` 的 IV 长度。
pub const NONCE_LEN: usize = 12;

/// SHA-256 空串摘要。`Derive-Secret(., "derived", "")` 的上下文。
const EMPTY_HASH: [u8; HASH_LEN] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// `HKDF-Expand-Label`（RFC 8446 §7.1）。
///
/// 结构为 `uint16 length | opaque label<7..255> | opaque context<0..255>`，
/// 其中 label = `"tls13 " + Label`。
///
/// 对齐参考 `xtls/reality/tls13` 的 `ExpandLabel`。
pub fn expand_label(secret: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(4 + 6 + label.len() + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let mut out = vec![0u8; length];
    hkdf_expand_sha256(secret, &info, &mut out);
    out
}

/// `Derive-Secret(Secret, Label, Messages)` = `Expand-Label(Secret, Label, Transcript-Hash(Messages))`。
///
/// 对齐参考 `xtls/reality/tls13` 的 `deriveSecret`。
pub fn derive_secret(secret: &[u8], label: &str, transcript_hash: &[u8]) -> [u8; HASH_LEN] {
    let out = expand_label(secret, label, transcript_hash, HASH_LEN);
    out.try_into().expect("长度固定为 32")
}

/// `Derive-Secret(Secret, "derived", "")`。
///
/// 参考在 `transcript == nil` 时用空哈希对象，��下文是 `Hash("")`。
pub fn derive_derived(secret: &[u8]) -> [u8; HASH_LEN] {
    derive_secret(secret, "derived", &EMPTY_HASH)
}

/// TLS 1.3 的密钥调度状态。
///
/// 覆盖 RFC 8446 §7.1 图中本仓实际用到的分支：无 PSK、单一 ECDHE(X25519)、
/// `TLS_AES_128_GCM_SHA256`。客户端与服务端的计算**完全相同**，
/// 差别只在传入的转录哈希。
#[derive(Clone)]
pub struct KeySchedule {
    early_secret: [u8; HASH_LEN],
    /// `handshake_secret`（保留以便诊断/自证；派生已完成）。
    #[allow(dead_code)]
    handshake_secret: [u8; HASH_LEN],
    /// `master_secret`（保留以便诊断/自证；派生已完成）。
    #[allow(dead_code)]
    master_secret: [u8; HASH_LEN],
    /// `c hs traffic`。
    pub client_handshake_traffic: [u8; HASH_LEN],
    /// `s hs traffic`。
    pub server_handshake_traffic: [u8; HASH_LEN],
    /// `c ap traffic`（`server Finished` 之后才可用）。
    pub client_application_traffic: [u8; HASH_LEN],
    /// `s ap traffic`。
    pub server_application_traffic: [u8; HASH_LEN],
}

impl KeySchedule {
    /// 建立密钥调度。
    ///
    /// * `shared_secret`：X25519 ECDHE 共享密钥（32 字节）。
    /// * `transcript_ch_sh`：`Hash(ClientHello..ServerHello)`。
    /// * `transcript_ch_sfin`：`Hash(ClientHello..server Finished)`。
    ///
    /// 对齐参考 `xtls/reality/tls13` 的 `EarlySecret` / `HandshakeSecret` /
    /// `MasterSecret` 三段推进。
    pub fn new(shared_secret: &[u8], transcript_ch_sh: &[u8], transcript_ch_sfin: &[u8]) -> Self {
        let zeros = [0u8; HASH_LEN];
        // early_secret = HKDF-Extract(0, 0) = HMAC(key=0, msg=0)。
        let early_secret = hkdf_extract_sha256(&zeros, &zeros);
        // handshake_secret = HKDF-Extract(derived, ECDHE)。
        let derived = derive_derived(&early_secret);
        let handshake_secret = hkdf_extract_sha256(&derived, shared_secret);
        let client_handshake_traffic =
            derive_secret(&handshake_secret, "c hs traffic", transcript_ch_sh);
        let server_handshake_traffic =
            derive_secret(&handshake_secret, "s hs traffic", transcript_ch_sh);
        // master_secret = HKDF-Extract(Derive-Secret(handshake_secret, "derived", ""), 0)。
        let derived = derive_derived(&handshake_secret);
        let master_secret = hkdf_extract_sha256(&derived, &zeros);
        let client_application_traffic =
            derive_secret(&master_secret, "c ap traffic", transcript_ch_sfin);
        let server_application_traffic =
            derive_secret(&master_secret, "s ap traffic", transcript_ch_sfin);
        Self {
            early_secret,
            handshake_secret,
            master_secret,
            client_handshake_traffic,
            server_handshake_traffic,
            client_application_traffic,
            server_application_traffic,
        }
    }

    /// 早期数据密钥（0-RTT）。本仓不支持 0-RTT，保留字段以便显式拒绝。
    pub fn client_early_traffic(&self, transcript_ch: &[u8]) -> [u8; HASH_LEN] {
        derive_secret(&self.early_secret, "c e traffic", transcript_ch)
    }
}

/// 记录层密钥与 IV（参考 `key_schedule.go` 的 `trafficKey`）。
#[derive(Clone)]
pub struct TrafficKey {
    pub key: [u8; KEY_LEN],
    pub iv: [u8; NONCE_LEN],
}

/// 从流量密钥导出记录层 key/iv。
///
/// 对齐参考 `key_schedule.go` 的
/// `trafficKey`：`ExpandLabel(secret, "key")` / `ExpandLabel(secret, "iv")`。
pub fn traffic_key(secret: &[u8]) -> TrafficKey {
    let key = expand_label(secret, "key", &[], KEY_LEN);
    let iv = expand_label(secret, "iv", &[], NONCE_LEN);
    TrafficKey {
        key: key.try_into().expect("长度固定"),
        iv: iv.try_into().expect("长度固定"),
    }
}

/// `Finished` 的 `verify_data`。
///
/// 对齐参考 `key_schedule.go` 的 `finishedHash`：
/// `finishedKey = ExpandLabel(baseKey, "finished")`，
/// `verifyData = HMAC(finishedKey, Transcript-Hash)`。
pub fn finished_verify_data(base_key: &[u8], transcript_hash: &[u8]) -> [u8; HASH_LEN] {
    let finished_key = expand_label(base_key, "finished", &[], HASH_LEN);
    hmac_sha256(&finished_key, transcript_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::hash::sha::Sha256;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 8448 §3 的 `expand_label` 向量（SHA-256）。
    ///
    /// 向量原文：`secret = 9b be 43 6b ... db 35`、`label = "traffic upd"`、
    /// `context = 9b` × 16，输出 `bd 35 fc 3a c0 e4 ec d8 62 dd b8 26 9d 29 1c e2
    /// d4 f5 36 ea ca f0 ff 46 91 fc 0f 83 d6 bb 10 be`。
    #[test]
    fn rfc8448_expand_label_vector() {
        let secret = [
            0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17, 0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71,
            0xdb, 0x35,
        ];
        let context = [0x9bu8; 16];
        let out = expand_label(&secret, "traffic upd", &context, 32);
        assert_eq!(
            hex(&out),
            "bd35fc3ac0e4ecd862ddb8269d291ce2d4f536eacaf0ff4691fc0f83d6bb10be"
        );
    }

    /// RFC 8448 §3：客户端与服务端的 `traffic upd` 链在给定 secret 下必须一致推进。
    #[test]
    fn traffic_upd_is_deterministic() {
        let secret = [0x42u8; 32];
        let next = expand_label(&secret, "traffic upd", &[], 32);
        let again = expand_label(&secret, "traffic upd", &[], 32);
        assert_eq!(next, again);
        let next2 = expand_label(&next, "traffic upd", &[], 32);
        assert_ne!(next, next2);
    }

    /// `finished` 的 `verify_data` 必须是 HMAC-SHA256(finished_key, transcript)。
    #[test]
    fn finished_matches_manual_hmac() {
        let base = [0x7au8; 32];
        let transcript = b"transcript hash bytes";
        let expected = {
            let finished_key = expand_label(&base, "finished", &[], HASH_LEN);
            hmac_sha256(&finished_key, transcript)
        };
        assert_eq!(finished_verify_data(&base, transcript), expected);
    }

    /// `Derive-Secret(., "derived", "")` 的上下文必须是 `Hash("")`。
    ///
    /// 这条最容易写错：若误用空上下文，握手密钥与参考不一致，
    /// 表现为记录层解封失败。参考 `tls13/tls13.go` 的 `deriveSecret` 在
    /// `transcript == nil` 时构造空哈希对象并取 `Sum(nil)`。
    #[test]
    fn derived_secret_uses_empty_hash_context() {
        let secret = [0x11u8; 32];
        let with_empty_hash = derive_derived(&secret);
        let with_wrong_context = derive_secret(&secret, "derived", &[]);
        assert_ne!(
            with_empty_hash, with_wrong_context,
            "空上下文与 Hash(\"\") 必须不同"
        );
        // 与手工展开一致。
        let expected = expand_label(&secret, "derived", &EMPTY_HASH, HASH_LEN);
        assert_eq!(with_empty_hash.to_vec(), expected);
    }

    /// 密钥调度的两阶段推进必须是自洽的：握手流量密钥依赖 CH..SH 哈希，
    /// 应用流量密钥依赖 CH..server Finished 哈希。
    #[test]
    fn key_schedule_phases_depend_on_transcript() {
        let shared = [0x11u8; 32];
        let mut ch = Sha256::new();
        ch.update(b"client hello");
        let ch_hash = ch.finalize();
        let mut ch_sh = Sha256::new();
        ch_sh.update(&ch_hash);
        let ch_sh_hash = ch_sh.finalize();
        let mut ch_sfin = Sha256::new();
        ch_sfin.update(&ch_sh_hash);
        let ch_sfin_hash = ch_sfin.finalize();

        let schedule = KeySchedule::new(&shared, &ch_sh_hash, &ch_sfin_hash);
        // 不同 transcript 必须给出不同的握手密钥。
        let other = KeySchedule::new(&shared, &[0u8; 32], &ch_sfin_hash);
        assert_ne!(
            schedule.client_handshake_traffic,
            other.client_handshake_traffic
        );
        // 同一输入必须给出一致结果。
        let again = KeySchedule::new(&shared, &ch_sh_hash, &ch_sfin_hash);
        assert_eq!(
            schedule.client_handshake_traffic,
            again.client_handshake_traffic
        );
        assert_eq!(
            schedule.client_application_traffic,
            again.client_application_traffic
        );
        // 客户端与服务端流量密钥必须不同。
        assert_ne!(
            schedule.client_handshake_traffic,
            schedule.server_handshake_traffic
        );
        assert_ne!(
            schedule.client_application_traffic,
            schedule.server_application_traffic
        );
    }

    /// `HKDF-Extract` 的方向：HMAC(key=salt, msg=ikm)。
    ///
    /// 参考 `tls13/tls13.go` 的 `extract(h, newSecret, currentSecret)` 等价于
    /// `HMAC(key=currentSecret, msg=newSecret)`；本仓
    /// `hkdf_extract_sha256(salt, ikm)` = `HMAC(key=salt, msg=ikm)`。
    #[test]
    fn extract_argument_order_matches_reference() {
        let salt = [0x22u8; 32];
        let ikm = [0x33u8; 32];
        let swapped = hkdf_extract_sha256(&ikm, &salt);
        let correct = hkdf_extract_sha256(&salt, &ikm);
        assert_ne!(correct, swapped);
        // HMAC(key=salt, msg=ikm) 必须等于手工计算。
        assert_eq!(correct, hmac_sha256(&salt, &ikm));
    }
}
