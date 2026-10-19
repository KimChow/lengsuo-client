//! Noise 基元与常量——对齐 wireguard-go `device/noise-helpers.go`、
//! `device/noise-protocol.go`、`device/noise-types.go`。
//!
//! 只含与握手相关的密码学基元：HMAC-BLAKE2s-256（block 64）、KDF1/KDF2/KDF3、
//! mixHash/mixKey、AEAD seal/open、MAC1/MAC2 的 keyed BLAKE2s-128、TAI64N
//! 时间戳。发起方与响应方状态机都复用本模块，禁止重复实现或自创“等价”方案。

use blake2::digest::consts::{U16, U32};
use blake2::digest::Mac as _;
use blake2::{Blake2s, Blake2sMac};
type Blake2s32 = Blake2s<U32>;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;

use crate::transport::Error;

/// `NoiseConstruction`。
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// `WGIdentifier`。
pub const WG_IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
/// `WGLabelMAC1`。
pub const LABEL_MAC1: &[u8] = b"mac1----";
/// `WGLabelCookie`。
pub const LABEL_COOKIE: &[u8] = b"cookie--";
/// initiation 报文长度（type1 + sender4 + ephemeral32 + static48 + timestamp28 + mac1 16 + mac2 16）。
pub const INITIATION_LEN: usize = 148;
/// response 报文长度（type1 + sender4 + receiver4 + ephemeral32 + empty48 + mac1 16 + mac2 16）。
pub const RESPONSE_LEN: usize = 92;
/// cookie reply 报文长度（type4 + receiver4 + nonce24 + cookie32）。
pub const COOKIE_REPLY_LEN: usize = 64;
/// PSK 长度。
pub const PSK_LEN: usize = 32;
/// MAC1/MAC2 长度（BLAKE2s-128）。
pub const MAC_LEN: usize = 16;
/// AEAD nonce 长度（握手内固定全零）。
pub const ZERO_NONCE_LEN: usize = 12;
/// XChaCha20-Poly1305 nonce 长度（cookie reply 用，参考 `NonceSizeX`）。
pub const X_NONCE_LEN: usize = 24;
/// `CookieRefreshTime`：cookie 有效期。
pub const COOKIE_REFRESH_TIME: std::time::Duration = std::time::Duration::from_secs(120);
/// `HandshakeInitationRate`：两次 initiation 剥壳的时间下限（防洪水）。
pub const HANDSHAKE_INITIATION_RATE: std::time::Duration = std::time::Duration::from_millis(20);

/// `HMAC1`：单输入 HMAC-BLAKE2s-256。
fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut hasher = Blake2s32::default();
        <Blake2s32 as blake2::Digest>::update(&mut hasher, key);
        let hashed = <Blake2s32 as blake2::Digest>::finalize(hasher);
        // BLAKE2s-256 摘要只有 32 字节：拷进前 32 字节，余下保持零填充。
        key_block[..32].copy_from_slice(hashed.as_slice());
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = key_block.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = key_block.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Blake2s32::default();
    <Blake2s32 as blake2::Digest>::update(&mut inner, &ipad);
    <Blake2s32 as blake2::Digest>::update(&mut inner, data);
    let inner_hash = <Blake2s32 as blake2::Digest>::finalize(inner);
    let mut outer = Blake2s32::default();
    <Blake2s32 as blake2::Digest>::update(&mut outer, &opad);
    <Blake2s32 as blake2::Digest>::update(&mut outer, inner_hash);
    <Blake2s32 as blake2::Digest>::finalize(outer).into()
}

/// `HMAC2`。
fn hmac2_blake2s(key: &[u8], in0: &[u8], in1: &[u8]) -> [u8; 32] {
    let mut joined = in0.to_vec();
    joined.extend_from_slice(in1);
    hmac_blake2s(key, &joined)
}

/// `KDF1`：`HMAC1(key, input)`，再 `HMAC1(上一步, 0x01)`。
fn kdf1(key: &[u8], input: &[u8]) -> [u8; 32] {
    let t0 = hmac_blake2s(key, input);
    hmac_blake2s(&t0, &[0x1])
}

/// `KDF2`：返回 (t0, t1)。
pub(crate) fn kdf2(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let prk = hmac_blake2s(key, input);
    let t0 = hmac_blake2s(&prk, &[0x1]);
    let t1 = hmac2_blake2s(&prk, &t0, &[0x2]);
    (t0, t1)
}

/// `KDF3`：返回 (t0, t1, t2)。
pub(crate) fn kdf3(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let prk = hmac_blake2s(key, input);
    let t0 = hmac_blake2s(&prk, &[0x1]);
    let t1 = hmac2_blake2s(&prk, &t0, &[0x2]);
    let t2 = hmac2_blake2s(&prk, &t1, &[0x3]);
    (t0, t1, t2)
}

/// 供测试/跨模块使用的 KDF 公开导出（对齐既有 API）。
pub fn kdf1_pub(key: [u8; 32], input: &[u8]) -> [u8; 32] {
    kdf1(&key, input)
}
pub fn kdf2_pub(key: [u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    kdf2(&key, input)
}
pub fn kdf3_pub(key: [u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    kdf3(&key, input)
}

/// `mixHash`：BLAKE2s-256(h || data)。
pub(crate) fn mix_hash(h: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s32::default();
    <Blake2s32 as blake2::Digest>::update(&mut hasher, h);
    <Blake2s32 as blake2::Digest>::update(&mut hasher, data);
    <Blake2s32 as blake2::Digest>::finalize(hasher).into()
}

/// `mixKey`：`KDF1(chainKey, data)`——参考 `mixKey` 直接调 `KDF1`，不是 KDF2 丢弃第二输出。
pub fn mix_key(chain_key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    kdf1(chain_key, data)
}

/// 供测试/跨模块使用的 mixHash 导出。
pub fn mix_hash_pub(h: [u8; 32], data: &[u8]) -> [u8; 32] {
    mix_hash(&h, data)
}

/// `InitialChainKey = BLAKE2s-256(Construction)`。
#[must_use]
pub fn initial_chain_key() -> [u8; 32] {
    let mut hasher = Blake2s32::default();
    <Blake2s32 as blake2::Digest>::update(&mut hasher, CONSTRUCTION);
    <Blake2s32 as blake2::Digest>::finalize(hasher).into()
}

/// `InitialHash = mixHash(InitialChainKey, WGIdentifier)`。
#[must_use]
pub fn initial_hash() -> [u8; 32] {
    mix_hash(&initial_chain_key(), WG_IDENTIFIER)
}

/// `NewCipherFromKey`（AuthID/Timestamp 复用的 AES 侧不在此处；本握手只用
/// ChaCha20Poly1305 单例）。
fn aead(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new_from_slice(key).expect("ChaCha20Poly1305 固定 32B 密钥")
}

/// seal helper：zero nonce、指定 AAD。
pub(crate) fn seal(key: &[u8; 32], plain: &[u8], aad: &[u8]) -> Vec<u8> {
    aead(key)
        .encrypt(&[0u8; ZERO_NONCE_LEN].into(), Payload { msg: plain, aad })
        .expect("ChaCha20 加密仅在长度异常时失败；握手输入长度受控")
}

/// open helper：失败 = 认证失败。
pub(crate) fn open(key: &[u8; 32], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    aead(key)
        .decrypt(&[0u8; ZERO_NONCE_LEN].into(), Payload { msg: ct, aad })
        .map_err(|_| Error::AuthFailed)
}

pub fn open_aead(key: &[u8; 32], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    open(key, ct, aad)
}
pub fn seal_aead(key: &[u8; 32], plain: &[u8], aad: &[u8]) -> Vec<u8> {
    seal(key, plain, aad)
}

/// `BLAKE2s-256(label || public_key)`：MAC1/MAC2 密钥派生（参考 `CookieChecker.Init`
/// 与 `CookieGenerator.Init`）。
fn labeled_key(label: &[u8], public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2s32::default();
    <Blake2s32 as blake2::Digest>::update(&mut hasher, label);
    <Blake2s32 as blake2::Digest>::update(&mut hasher, public_key);
    <Blake2s32 as blake2::Digest>::finalize(hasher).into()
}

/// keyed BLAKE2s-128 MAC：cookie/消息散列都经它（参考 `blake2s.New128(key)`）。
pub fn keyed_blake2s_128(key: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = <Blake2sMac<U16> as blake2::digest::KeyInit>::new_from_slice(key)
        .expect("BLAKE2s-128 接受 0..=32B key");
    <Blake2sMac<U16> as blake2::digest::Mac>::update(&mut mac, data);
    mac.finalize().into_bytes().into()
}

/// MAC1：keyed BLAKE2s-128，key = BLAKE2s-256(LabelMAC1 || remote_static)，
/// 消息 = 报文去掉 mac1/mac2 尾部（参考 `CheckMAC1`/`AddMacs`）。
#[must_use]
pub fn mac1(remote_static: &[u8; 32], message_without_macs: &[u8]) -> [u8; MAC_LEN] {
    let mac_key = labeled_key(LABEL_MAC1, remote_static);
    keyed_blake2s_128(&mac_key, message_without_macs)
}

/// MAC2 的 cookie 派生：`BLAKE2s-128(secret, src)`（参考 `CheckMAC2`/`CreateReply`）。
#[must_use]
pub fn derive_cookie(secret: &[u8; 32], src: &[u8]) -> [u8; MAC_LEN] {
    keyed_blake2s_128(secret, src)
}

/// MAC1 密钥：`BLAKE2s-256("mac1----" || public_key)`。
#[must_use]
pub fn mac1_key(public_key: &[u8; 32]) -> [u8; 32] {
    labeled_key(LABEL_MAC1, public_key)
}

/// cookie 加密密钥：`BLAKE2s-256("cookie--" || public_key)`。
#[must_use]
pub fn cookie_encryption_key(public_key: &[u8; 32]) -> [u8; 32] {
    labeled_key(LABEL_COOKIE, public_key)
}

/// 常量时间字节比较（MAC 校验不得短路）。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// TAI64N 时间戳：`@` + 16 字符大写十六进制（8B TAI64 打包秒 + 4B 纳秒），
/// 对齐 `tai64n.Now()` 的线格式（12 字节载荷，big endian）。
#[must_use]
pub fn tai64n_now() -> [u8; 12] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // 参考 tai64n.go：12 字节 = BE64(0x400000000000000a + unix 秒) || BE32(纳秒 &^ 0xFFFFFF)。
    let seconds = 0x4000_0000_0000_000a_u64 + now.as_secs();
    let whitened = now.subsec_nanos() & !0x00ff_ffff;
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&seconds.to_be_bytes());
    out[8..].copy_from_slice(&whitened.to_be_bytes());
    out
}

/// `tai64n.Timestamp.After`：逐字节字典序比较（参考 `bytes.Compare`）。
#[must_use]
pub fn tai64n_after(a: &[u8; 12], b: &[u8; 12]) -> bool {
    a > b
}
