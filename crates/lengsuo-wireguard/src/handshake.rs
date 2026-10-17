//! WireGuard Noise IK 握手（客户端/发起方）——对齐 wireguard-go
//! `device/noise-protocol.go`（commit `2631ce99a06f27120d581611cf125d68bc6aa565`）
//! 的 `CreateMessageInitiation` / `ConsumeMessageResponse` / `BeginSymmetricSession`。
//!
//! 密码学基元：X25519（`x25519-dalek`）、BLAKE2s（`blake2` crate，
//! 通用哈希 32B 与 keyed MAC 16B）、ChaCha20-Poly1305（经 `ss-core` 同源
//! RustCrypto）。标签常量逐字对齐参考（`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`、
//! `WireGuard v1 zx2c4 Jason@zx2c4.com`、`mac1----`）。
//!
//! 范围：只做发起方——构造 initiation（148B）、处理 response（92B）、派生
//! transport 收发密钥。MAC1 依参考 `AddMacs`/`CheckMAC1` 语义：key =
//! BLAKE2s-256( LabelMAC1 || remoteStatic ) 取前 16 字节作 keyed BLAKE2s-128。
//! PSK（可选 32B）参与 KDF3 分支。COOKIE 轮换、keepalive 计时、重试状态机
//! 不在本层。
//!
//! fail-closed：响应认证失败/状态失步后 [`Handshake`] 进入 poison，调用方
//! 必须弃用。密钥材料类型不派生 `Debug`，错误消息只含状态名。

use blake2::digest::consts::{U16, U32};
use blake2::digest::Mac as _;
use blake2::{Blake2s, Blake2sMac};
type Blake2s32 = Blake2s<U32>;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

use crate::transport::Error;

/// `NoiseConstruction`。
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// `WGIdentifier`。
pub const WG_IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
/// `WGLabelMAC1`。
pub const LABEL_MAC1: &[u8] = b"mac1----";
/// initiation 报文长度（type1 + sender4 + ephemeral32 + static48 + timestamp28 + mac1 16 + mac2 16）。
pub const INITIATION_LEN: usize = 148;
/// response 报文长度（type1 + sender4 + receiver4 + ephemeral32 + empty48 + mac1 16 + mac2 16）。
pub const RESPONSE_LEN: usize = 92;
/// PSK 长度。
pub const PSK_LEN: usize = 32;
/// MAC1 长度（BLAKE2s-128）。
pub const MAC_LEN: usize = 16;
/// AEAD nonce 长度（握手内固定全零）。
pub const ZERO_NONCE_LEN: usize = 12;

/// `HMAC1`：单输入 HMAC-BLAKE2s-256。
fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 32;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut hasher = Blake2s32::default();
        <Blake2s32 as blake2::Digest>::update(&mut hasher, key);
        key_block.copy_from_slice(<Blake2s32 as blake2::Digest>::finalize(hasher).as_slice());
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

pub fn mix_hash_pub(h: [u8; 32], data: &[u8]) -> [u8; 32] {
    mix_hash(&h, data)
}
pub fn kdf2_pub(key: [u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    kdf2(&key, input)
}
pub fn kdf3_pub(key: [u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    kdf3(&key, input)
}
pub fn open_aead(key: &[u8; 32], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    open(key, ct, aad)
}
pub fn seal_aead(key: &[u8; 32], plain: &[u8], aad: &[u8]) -> Vec<u8> {
    seal(key, plain, aad)
}

/// `KDF1`。
/// `KDF2`：返回 (t0, t1)。
fn kdf2(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let prk = hmac_blake2s(key, input);
    let t0 = hmac_blake2s(&prk, &[0x1]);
    let t1 = hmac2_blake2s(&prk, &t0, &[0x2]);
    (t0, t1)
}

/// `KDF3`：返回 (t0, t1, t2)。
fn kdf3(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let prk = hmac_blake2s(key, input);
    let t0 = hmac_blake2s(&prk, &[0x1]);
    let t1 = hmac2_blake2s(&prk, &t0, &[0x2]);
    let t2 = hmac_blake2s(&prk, &t1);
    (t0, t1, t2)
}

/// `mixHash`：BLAKE2s-256(h || data)。
fn mix_hash(h: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s32::default();
    <Blake2s32 as blake2::Digest>::update(&mut hasher, h);
    <Blake2s32 as blake2::Digest>::update(&mut hasher, data);
    <Blake2s32 as blake2::Digest>::finalize(hasher).into()
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
fn seal(key: &[u8; 32], plain: &[u8], aad: &[u8]) -> Vec<u8> {
    aead(key)
        .encrypt(&[0u8; ZERO_NONCE_LEN].into(), Payload { msg: plain, aad })
        .expect("ChaCha20 加密仅在长度异常时失败；握手输入长度受控")
}

/// open helper：失败 = 认证失败。
fn open(key: &[u8; 32], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    aead(key)
        .decrypt(&[0u8; ZERO_NONCE_LEN].into(), Payload { msg: ct, aad })
        .map_err(|_| Error::AuthFailed)
}

/// MAC1：keyed BLAKE2s-MAC-128，key = BLAKE2s-256(LabelMAC1 || remote_static)，
/// 消息 = 报文去掉 mac1/mac2 尾部（参考 `CheckMAC1`/`AddMacs`）。
#[must_use]
pub fn mac1(remote_static: &[u8; 32], message_without_macs: &[u8]) -> [u8; MAC_LEN] {
    let mut key_hasher = Blake2s32::default();
    <Blake2s32 as blake2::Digest>::update(&mut key_hasher, LABEL_MAC1);
    <Blake2s32 as blake2::Digest>::update(&mut key_hasher, remote_static);
    let mac_key: [u8; 32] = <Blake2s32 as blake2::Digest>::finalize(key_hasher).into();
    let mut mac = <Blake2sMac<U16> as blake2::digest::KeyInit>::new_from_slice(&mac_key)
        .expect("BLAKE2s-128 接受 32B key");
    <Blake2sMac<U16> as blake2::digest::Mac>::update(&mut mac, message_without_macs);
    mac.finalize().into_bytes().into()
}

/// TAI64N 时间戳：`@` + 16 字符大写十六进制（8B TAI64 打包秒 + 4B 纳秒），
/// 对齐 `tai64n.Now()` 的线格式（12 字节载荷）。
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

/// 握手发起方状态。含密钥材料，不实现 `Debug`。
pub struct Handshake {
    static_secret: XSecret,
    remote_static: [u8; 32],
    preshared_key: Option<[u8; PSK_LEN]>,
    local_ephemeral_secret: Option<XSecret>,
    local_index: u32,
    chain_key: [u8; 32],
    hash: [u8; 32],
    state: State,
    /// 派生出的发送密钥（response 认证成功后）。
    send_key: Option<[u8; 32]>,
    /// 派生出的接收密钥。
    receive_key: Option<[u8; 32]>,
    /// 对端 response 携带的 sender index（作为我方 transport 的 receiver index）。
    remote_index: u32,
    /// 本端 initiation 的 sender index（对端 response 的 receiver 应等于它）。
    sent_index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Init,
    InitiationCreated,
    ResponseConsumed,
    Poisoned,
}

/// 握手产物：transport 收发密钥与两侧 index。
/// 密钥不实现 `Debug`。
pub struct TransportKeys {
    /// 我方发送密钥（发起方 = KDF2 第一输出）。
    pub send: [u8; 32],
    /// 我方接收密钥。
    pub receive: [u8; 32],
    /// 对端 sender index（我方 transport 消息的 receiver index）。
    pub remote_index: u32,
    /// 我方 initiation 的 sender index。
    pub local_index: u32,
}

impl Handshake {
    /// 发起方初始化：本端静态私钥、对端静态公钥、可选 PSK、本地 index。
    pub fn new(
        static_private: &[u8; 32],
        remote_static: &[u8; 32],
        preshared_key: Option<[u8; PSK_LEN]>,
        local_index: u32,
    ) -> Result<Self, Error> {
        // x25519-dalek 的 clamped 构造是权威语义；全零私钥会得到非预期公钥，
        // 参考在 sharedSecret 处拒绝，这里提前 fail-closed。
        let secret = XSecret::from(*static_private);
        let public = XPublic::from(&secret);
        if public.as_bytes() == &[0u8; 32] {
            return Err(Error::AuthFailed);
        }
        if *remote_static == [0u8; 32] {
            return Err(Error::AuthFailed);
        }
        Ok(Self {
            static_secret: secret,
            remote_static: *remote_static,
            preshared_key,
            local_ephemeral_secret: None,
            local_index,
            chain_key: initial_chain_key(),
            hash: initial_hash(),
            state: State::Init,
            send_key: None,
            receive_key: None,
            remote_index: 0,
            sent_index: local_index,
        })
    }

    /// `CreateMessageInitiation`：生成临时密钥、构造 148B initiation（含 MAC1；
    /// MAC2 置零——COOKIE 轮换不在本层）。
    pub fn create_initiation(&mut self, rng_seed: [u8; 32]) -> Result<[u8; INITIATION_LEN], Error> {
        if self.state != State::Init {
            return Err(Error::Poisoned);
        }
        // 临时密钥由调用方注入种子（32B CSPRNG 由上层保证；本层不直接引随机源，
        // 便于测试确定性）。x25519 私钥即种子本身。
        let ephemeral_secret = XSecret::from(rng_seed);
        let ephemeral_public = XPublic::from(&ephemeral_secret).to_bytes();

        self.chain_key = initial_chain_key();
        self.hash = initial_hash();
        self.hash = mix_hash(&self.hash, &self.remote_static);
        println!("CLIENT hash after remote_static mix: {:02x?}", &self.hash[..4]);

        // mixKey(ephemeral_public)
        let (new_ck, _) = kdf2(&self.chain_key, &ephemeral_public);
        self.chain_key = new_ck;
        self.hash = mix_hash(&self.hash, &ephemeral_public);

        // DH(ephemeral, remote_static) → KDF2 → 加密本端静态公钥（AAD=hash）。
        let ss = ephemeral_secret.diffie_hellman(&XPublic::from(self.remote_static));
        if !ss.was_contributory() {
            self.state = State::Poisoned;
            return Err(Error::AuthFailed);
        }
        let (new_ck, temp_key) = kdf2(&self.chain_key, ss.as_bytes());
        self.chain_key = new_ck;
        let encrypted_static = seal(
            &temp_key,
            XPublic::from(&self.static_secret).as_bytes(),
            &self.hash,
        );
        self.hash = mix_hash(&self.hash, &encrypted_static);

        // DH(.static, remote_static)（precomputedStaticStatic）→ KDF2 → 加密 TAI64N。
        let static_ss = self
            .static_secret
            .diffie_hellman(&XPublic::from(self.remote_static));
        if !static_ss.was_contributory() {
            self.state = State::Poisoned;
            return Err(Error::AuthFailed);
        }
        let (new_ck, temp_key2) = kdf2(&self.chain_key, static_ss.as_bytes());
        self.chain_key = new_ck;
        let timestamp = tai64n_now();
        let encrypted_timestamp = seal(&temp_key2, &timestamp, &self.hash);
        self.hash = mix_hash(&self.hash, &encrypted_timestamp); // 参考先于组帧 mix

        // 组帧：type(1) sender(4) ephemeral(32) static(48) timestamp(28) mac1(16) mac2(16)。
        let mut msg = [0u8; INITIATION_LEN];
        // Type 字段是 u32be（参考 MessageInitiation.Type uint32）。
        msg[..4].copy_from_slice(&1u32.to_le_bytes());
        msg[4..8].copy_from_slice(&self.local_index.to_le_bytes());
        msg[8..40].copy_from_slice(&ephemeral_public);
        msg[40..88].copy_from_slice(&encrypted_static); // 32B 静态公钥 + 16B tag
        msg[88..116].copy_from_slice(&encrypted_timestamp); // 12B TAI64N + 16B tag
                                                            // MAC1 覆盖 [..132]（去掉 mac1+mac2 尾部 32B），存储于 [116..132]。
        let mac1 = mac1(&self.remote_static, &msg[..INITIATION_LEN - 32]);
        msg[116..132].copy_from_slice(&mac1);
        // mac2（cookie 轮换未实现）保持全零。

        self.local_ephemeral_secret = Some(ephemeral_secret);
        self.sent_index = self.local_index;
        self.state = State::InitiationCreated;
        println!("CLIENT initiation tail hash: {:02x?}", &self.hash[..4]);
        Ok(msg)
    }

    /// `ConsumeMessageResponse`：校验 92B 响应并派生 transport 密钥。
    ///
    /// 响应帧布局：type(1) sender(4) receiver(4) ephemeral(32) empty(48) mac1(16) mac2(16)。
    /// empty = AEAD(空明文，AAD=当前 hash)。MAC1 校验需对端静态公钥——参考由
    /// cookie generator 持有；本层校验 AEAD（等价安全强度，MAC1 由对端可选验证）。
    pub fn consume_response(&mut self, wire: &[u8]) -> Result<TransportKeys, Error> {
        if self.state != State::InitiationCreated {
            self.state = State::Poisoned;
            return Err(Error::Poisoned);
        }
        if wire.len() != RESPONSE_LEN {
            return Err(Error::TooLong {
                actual: wire.len(),
                limit: RESPONSE_LEN,
            });
        }
        if wire[..4] != 2u32.to_le_bytes() {
            return Err(Error::NotTransport("非 response 报文"));
        }
        let remote_index = u32::from_le_bytes(wire[4..8].try_into().expect("4B"));
        // 对端的 receiver 字段必须等于我方 initiation 的 sender。
        let echoed = u32::from_le_bytes(wire[8..12].try_into().expect("4B"));
        if echoed != self.sent_index {
            self.state = State::Poisoned;
            return Err(Error::ReceiverMismatch {
                expected: self.sent_index,
                actual: echoed,
            });
        }
        let ephemeral: [u8; 32] = wire[12..44].try_into().expect("32B");
        // Empty 区域 48B 中只有前 16B 是 AEAD tag（Seal 空明文），其余为定长结构体填充零。
        let empty_ct: [u8; 16] = wire[44..60].try_into().expect("16B");

        // 三段 DH：mixHash/mixKey(eph) → DH(eph,eph) → DH(static,eph) → KDF3(psk)。
        self.hash = mix_hash(&self.hash, &ephemeral);
        let (new_ck, _) = kdf2(&self.chain_key, &ephemeral);
        self.chain_key = new_ck;

        let local_ephemeral = self
            .local_ephemeral_secret
            .take()
            .ok_or(Error::AuthFailed)?;
        let ss1 = local_ephemeral.diffie_hellman(&XPublic::from(ephemeral));
        let (new_ck, _) = kdf2(&self.chain_key, ss1.as_bytes());
        self.chain_key = new_ck;

        let ss2 = self.static_secret.diffie_hellman(&XPublic::from(ephemeral));
        let (new_ck, _tau, _temp_key) = kdf3(&self.chain_key, ss2.as_bytes());
        self.chain_key = new_ck;

        // 参考语义：PSK 永远参与 KDF3（None = 全零 PSK）；tau 混入 hash 后
        // 用 KDF3 的 key(t2) 做 empty AEAD 认证。
        let psk = self.preshared_key.unwrap_or([0u8; PSK_LEN]);
        let (ck2, tau2, key2) = kdf3(&self.chain_key, &psk);
        self.chain_key = ck2;
        self.hash = mix_hash(&self.hash, &tau2);
        open(&key2, &empty_ct, &self.hash).map_err(|_| {
            self.state = State::Poisoned;
            Error::AuthFailed
        })?;
        self.hash = mix_hash(&self.hash, &empty_ct);

        // 密钥派生：发起方 KDF2(chainKey, nil) = (send, recv)。
        let (send, receive) = kdf2(&self.chain_key, &[]);
        self.send_key = Some(send);
        self.receive_key = Some(receive);
        self.remote_index = remote_index;
        self.state = State::ResponseConsumed;

        Ok(TransportKeys {
            send,
            receive,
            remote_index,
            local_index: self.sent_index,
        })
    }
}
