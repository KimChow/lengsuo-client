//! `transport` 的封装/解封测试：全部使用假密钥与假载荷，不代表任何真实凭据。
//! 只证明本 crate 内部 seal ⇄ `wire::parse` ⇄ open 的自洽与 fail-closed 语义，
//! **不证明与任何真实 WireGuard 对端互通**（握手与密钥协商未实现）。
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use lengsuo_wireguard::replay::Error as ReplayError;
use lengsuo_wireguard::transport::{
    key_len, Decrypted, Error, Receiver, Sender, TransportKey, DEFAULT_MAX_COUNTER, MAX_PACKET_LEN,
    MAX_PAYLOAD_LEN,
};
use lengsuo_wireguard::wire::{parse, Message, TRANSPORT_MIN_LEN};

/// 假会话密钥（固定模式字节，仅测试用）。
const KEY_A: [u8; 32] = [0xA1; 32];
/// 另一把假密钥，用于“错误密钥”测试。
const KEY_B: [u8; 32] = [0xB2; 32];
const RECEIVER_ID: u32 = 0xDE_AD_BE_EF;
/// 非 0xFF 的递增字节串，便于逐字节定位错位。
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|offset| (offset % 233) as u8).collect()
}

fn key_a() -> TransportKey {
    TransportKey::new(&KEY_A).expect("32 字节假密钥")
}

fn sender() -> Sender {
    Sender::new(key_a(), RECEIVER_ID, 0)
}

fn receiver() -> Receiver {
    Receiver::new(key_a(), RECEIVER_ID, DEFAULT_MAX_COUNTER)
}

/// 独立算一遍参考 nonce 布局（4 零 + LE64 计数器）的密文，用于钉住格式。
fn reference_ciphertext(counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    ChaCha20Poly1305::new_from_slice(&KEY_A)
        .expect("假密钥长度已校验")
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("假数据封装不应失败")
}

/// 密钥字节的两种常见泄漏形态：数组 Debug 与 hex。
fn leak_forms(key: &[u8]) -> Vec<String> {
    vec![
        format!("{key:?}"),
        key.iter().map(|byte| format!("{byte:02x}")).collect(),
        key.iter().map(|byte| format!("{byte:02X}")).collect(),
    ]
}
fn receiver_seal_one() -> Vec<u8> {
    sender().seal(&payload(8)).expect("seal")
}

// 用例按主题拆到 `tests/transport/` 下，用 `include!` **文本并入**同一模块
// （不是 `mod` 子模块）——这样用例名**不带模块前缀**，与拆分前逐字一致。
// 代价是分文件之间不能重复 `use`，故所有 `use` 都留在本入口文件。
include!("transport/roundtrip.rs");
include!("transport/rejections.rs");
include!("transport/secrecy.rs");
