//! WireGuard Noise IK 响应方状态机——对齐 wireguard-go
//! `device/noise-protocol.go` 的 `ConsumeMessageInitiation` / `CreateMessageResponse` /
//! `BeginSymmetricSession`（commit `2631ce99a06f27120d581611cf125d68bc6aa565`）。
//!
//! 字段顺序、KDF1/KDF2/KDF3 调用序与线上端序逐字对齐参考；`mixKey` 直接调
//! `KDF1`（见 [`mix_key`]）。MAC1/MAC2 校验与 cookie reply 由 [`CookieChecker`]/
//! [`CookieGenerator`] 承担，与参考一致地把 MAC 检查放在剥壳之前（`receive.go`
//! 的 `RoutineHandshake`），不在 `ConsumeMessageInitiation` 内。方向性密钥顺序：
//! 响应方 `KDF2(chainKey, nil) = (recv, send)`，与发起方的 `(send, recv)` 相反。

use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

use super::cookie::{CookieChecker, CookieGenerator};
use super::noise::{
    initial_chain_key, initial_hash, kdf2, kdf3, mix_hash, mix_key, open, seal, tai64n_after,
    COOKIE_REPLY_LEN, HANDSHAKE_INITIATION_RATE, INITIATION_LEN, PSK_LEN, RESPONSE_LEN,
    X_NONCE_LEN,
};

/// 响应方握手失败原因。所有分支 fail-closed，密钥与时间戳内容不进错误文本。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResponderError {
    /// 报文长度与类型要求不一致（响应方只收 148B initiation）。
    #[error("握手初始化长度 {actual} 字节，要求 {expected} 字节")]
    Length { actual: usize, expected: usize },
    /// 报文类型不是 1。
    #[error("非握手初始化报文")]
    NotInitiation,
    /// AEAD 认证失败（静态段或时间戳段）。
    #[error("AEAD 认证失败")]
    AuthFailed,
    /// 无效公钥 / 共享密钥为全零。
    #[error("无效公钥或共享密钥为全零")]
    InvalidKey,
    /// 解密出的对端静态公钥与配置的对端不一致。
    #[error("未知对端")]
    UnknownPeer,
    /// 时间戳不晚于已记录时间戳：握手重放。
    #[error("握手重放")]
    Replay,
    /// 两次剥壳间隔短于 `HandshakeInitationRate`：握手洪水。
    #[error("握手洪水")]
    Flood,
    /// 状态机失步。
    #[error("握手状态失步：{0}")]
    State(&'static str),
    /// MAC 校验失败（由 [`CookieChecker`] 上报，便于上层同一错误面）。
    #[error("MAC 校验失败")]
    Mac,
}

/// 响应方状态机的状态（对齐 `handshakeState` 全部取值；响应方只用到
/// `Zeroed`/`InitiationConsumed`/`ResponseCreated`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderState {
    Zeroed,
    InitiationCreated,
    InitiationConsumed,
    ResponseCreated,
    ResponseConsumed,
}

/// 响应方对称会话产物：transport 收发密钥与两侧 index。
pub struct ResponderKeys {
    /// 响应方发送密钥（`KDF2` 第二输出 t1，发起方用它解封）。
    pub send: [u8; 32],
    /// 响应方接收密钥（`KDF2` 第一输出 t0，发起方发送用）。
    pub receive: [u8; 32],
    /// 本端（响应方）index：响应方 transport 报文的 receiver。
    pub local_index: u32,
    /// 对端（发起方）index：响应方 transport 报文的 receiver。
    pub remote_index: u32,
}

/// 响应方状态机。字段顺序对齐参考 `Handshake` 结构（略去多线程 mutex）。
///
/// `static_secret`/`cookie_checker`/`cookie_generator` 是参考里
/// `device.staticIdentity`/`device.cookieChecker`/`peer.cookieGenerator` 的单 peer 化。
pub struct Responder {
    state: ResponderState,
    hash: [u8; 32],
    chain_key: [u8; 32],
    preshared_key: [u8; 32],
    local_ephemeral: Option<XSecret>,
    local_index: u32,
    remote_index: u32,
    remote_static: [u8; 32],
    remote_ephemeral: [u8; 32],
    precomputed_static_static: [u8; 32],
    last_timestamp: Option<[u8; 12]>,
    last_initiation_consumption: Option<std::time::Instant>,
    last_sent_handshake: Option<std::time::Instant>,
    static_secret: XSecret,
    cookie_checker: CookieChecker,
    cookie_generator: CookieGenerator,
}

impl Responder {
    /// 响应方初始化：本端静态私钥、对端静态公钥、可选 PSK、本端 index。
    pub fn new(
        static_private: &[u8; 32],
        remote_static: &[u8; 32],
        preshared_key: Option<[u8; PSK_LEN]>,
        local_index: u32,
    ) -> Result<Self, ResponderError> {
        let static_secret = XSecret::from(*static_private);
        let own_public = XPublic::from(&static_secret).to_bytes();
        if own_public == [0u8; 32] {
            return Err(ResponderError::InvalidKey);
        }
        if *remote_static == [0u8; 32] {
            return Err(ResponderError::InvalidKey);
        }
        // precomputedStaticStatic = DH(本端静态私钥, 对端静态公钥)；全零在
        // consume_initiation 里拒绝（对齐参考 `isZero(precomputedStaticStatic)`）。
        let precomputed_static_static = *static_secret
            .diffie_hellman(&XPublic::from(*remote_static))
            .as_bytes();
        Ok(Self {
            state: ResponderState::Zeroed,
            hash: initial_hash(),
            chain_key: initial_chain_key(),
            preshared_key: preshared_key.unwrap_or([0u8; PSK_LEN]),
            local_ephemeral: None,
            local_index,
            remote_index: 0,
            remote_static: *remote_static,
            remote_ephemeral: [0u8; 32],
            precomputed_static_static,
            last_timestamp: None,
            last_initiation_consumption: None,
            last_sent_handshake: None,
            static_secret,
            cookie_checker: CookieChecker::init(&own_public),
            cookie_generator: CookieGenerator::init(remote_static),
        })
    }

    /// 本端 index（response 的 Sender / transport receiver）。
    #[must_use]
    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    /// 对端 index（initiation 的 Sender / 出站 transport receiver）。
    #[must_use]
    pub fn remote_index(&self) -> u32 {
        self.remote_index
    }

    /// 最近一次剥壳成功的 TAI64N 时间戳；`None` 表示尚无记录。
    #[must_use]
    pub fn last_timestamp(&self) -> Option<[u8; 12]> {
        self.last_timestamp
    }

    /// `receive.go` 在入站把 MAC1 检查放在剥壳前；此处逐一对齐 `CheckMAC1`。
    #[must_use]
    pub fn check_mac1(&self, msg: &[u8]) -> bool {
        self.cookie_checker.check_mac1(msg)
    }

    /// `receive.go` 过载时再校验 MAC2；此处逐一对齐 `CheckMAC2`。
    #[must_use]
    pub fn check_mac2(&self, msg: &[u8], src: &[u8]) -> bool {
        self.cookie_checker.check_mac2(msg, src)
    }

    /// `SendHandshakeCookie`：MAC2 无效时签发 64B cookie reply。
    pub fn create_cookie_reply(
        &mut self,
        msg: &[u8],
        src: &[u8],
        secret_seed: [u8; 32],
        nonce: [u8; X_NONCE_LEN],
    ) -> [u8; COOKIE_REPLY_LEN] {
        let recv = u32::from_le_bytes(msg[4..8].try_into().expect("4B"));
        self.cookie_checker
            .create_reply(msg, recv, src, secret_seed, nonce)
    }

    /// `send.go` 的 `SendHandshakeResponse` 在出站前记录时间。
    pub fn mark_handshake_sent(&mut self) {
        self.last_sent_handshake = Some(std::time::Instant::now());
    }

    /// `ConsumeMessageInitiation`：剥壳 148B initiation（解密静态/时间戳、回放与
    /// 洪水检测），成功即置 `InitiationConsumed`。不校验 MAC——与参考一致。
    pub fn consume_initiation(&mut self, wire: &[u8]) -> Result<(), ResponderError> {
        if wire.len() != INITIATION_LEN {
            return Err(ResponderError::Length {
                actual: wire.len(),
                expected: INITIATION_LEN,
            });
        }
        if wire[..4] != 1u32.to_le_bytes() {
            return Err(ResponderError::NotInitiation);
        }
        let sender = u32::from_le_bytes(wire[4..8].try_into().expect("4B"));
        let ephemeral: [u8; 32] = wire[8..40].try_into().expect("32B");
        let static_ct: [u8; 48] = wire[40..88].try_into().expect("48B");
        let timestamp_ct: [u8; 28] = wire[88..116].try_into().expect("28B");

        // 参考用栈上临时 hash/chainKey，直到全部校验通过才写回状态。
        let own_public = XPublic::from(&self.static_secret).to_bytes();
        let mut hash = mix_hash(&initial_hash(), &own_public);
        hash = mix_hash(&hash, &ephemeral);
        let mut chain_key = mix_key(&initial_chain_key(), &ephemeral);

        // 解密静态公钥段。
        let ss = self.static_secret.diffie_hellman(&XPublic::from(ephemeral));
        if !ss.was_contributory() {
            return Err(ResponderError::AuthFailed);
        }
        let (new_ck, key) = kdf2(&chain_key, ss.as_bytes());
        chain_key = new_ck;
        let peer_pk = open(&key, &static_ct, &hash).map_err(|_| ResponderError::AuthFailed)?;
        let peer_pk: [u8; 32] = peer_pk[..32].try_into().expect("静态段明文固定 32B");
        hash = mix_hash(&hash, &static_ct);

        // 查找对端并向后对齐身份。
        if peer_pk != self.remote_static {
            return Err(ResponderError::UnknownPeer);
        }
        if self.precomputed_static_static == [0u8; 32] {
            return Err(ResponderError::InvalidKey);
        }

        // 解密时间戳段。
        let (new_ck, key) = kdf2(&chain_key, &self.precomputed_static_static);
        chain_key = new_ck;
        let ts = open(&key, &timestamp_ct, &hash).map_err(|_| ResponderError::AuthFailed)?;
        hash = mix_hash(&hash, &timestamp_ct);

        let timestamp: [u8; 12] = ts[..12].try_into().expect("时间戳明文固定 12B");

        // 防重放：时间戳必须严格晚于已记录值。
        let replay = self
            .last_timestamp
            .is_some_and(|last| !tai64n_after(&timestamp, &last));
        if replay {
            return Err(ResponderError::Replay);
        }
        // 防洪水：两次剥壳间隔不得短于 `HandshakeInitationRate`。
        let flood = self
            .last_initiation_consumption
            .is_some_and(|last| last.elapsed() <= HANDSHAKE_INITIATION_RATE);
        if flood {
            return Err(ResponderError::Flood);
        }

        // 全部通过后写回状态（参考锁内更新段）。
        self.hash = hash;
        self.chain_key = chain_key;
        self.remote_index = sender;
        self.remote_ephemeral = ephemeral;
        if self
            .last_timestamp
            .is_none_or(|last| tai64n_after(&timestamp, &last))
        {
            self.last_timestamp = Some(timestamp);
        }
        let now = std::time::Instant::now();
        if self
            .last_initiation_consumption
            .is_none_or(|last| now > last)
        {
            self.last_initiation_consumption = Some(now);
        }
        self.state = ResponderState::InitiationConsumed;
        Ok(())
    }

    /// `CreateMessageResponse`：构造 92B response（MAC 段留零，由
    /// [`Self::add_macs`] 加 MAC——对应参考 `SendHandshakeResponse` 后续 `AddMacs`）。
    pub fn create_response(
        &mut self,
        ephemeral_seed: [u8; 32],
        local_index: u32,
    ) -> Result<[u8; RESPONSE_LEN], ResponderError> {
        if self.state != ResponderState::InitiationConsumed {
            return Err(ResponderError::State("先剥壳 initiation 才能构造 response"));
        }
        // 参考在 index table 里删除旧 index 并分配新 index；单 peer 化后由调用方给定。
        self.local_index = local_index;

        let mut msg = [0u8; RESPONSE_LEN];
        msg[..4].copy_from_slice(&2u32.to_le_bytes());
        msg[4..8].copy_from_slice(&self.local_index.to_le_bytes());
        msg[8..12].copy_from_slice(&self.remote_index.to_le_bytes());

        // 创建临时密钥。
        let ephemeral_secret = XSecret::from(ephemeral_seed);
        let ephemeral_public = XPublic::from(&ephemeral_secret).to_bytes();
        msg[12..44].copy_from_slice(&ephemeral_public);
        self.hash = mix_hash(&self.hash, &ephemeral_public);
        self.chain_key = mix_key(&self.chain_key, &ephemeral_public);

        // 两次 DH：eph×远端eph、eph×远端static。
        let ss = ephemeral_secret.diffie_hellman(&XPublic::from(self.remote_ephemeral));
        if !ss.was_contributory() {
            return Err(ResponderError::InvalidKey);
        }
        self.chain_key = mix_key(&self.chain_key, ss.as_bytes());
        let ss = ephemeral_secret.diffie_hellman(&XPublic::from(self.remote_static));
        if !ss.was_contributory() {
            return Err(ResponderError::InvalidKey);
        }
        self.chain_key = mix_key(&self.chain_key, ss.as_bytes());
        self.local_ephemeral = Some(ephemeral_secret);

        // 混入 PSK。
        let (chain_key, tau, key) = kdf3(&self.chain_key, &self.preshared_key);
        self.chain_key = chain_key;
        self.hash = mix_hash(&self.hash, &tau);

        let empty_ct = seal(&key, &[], &self.hash);
        msg[44..60].copy_from_slice(&empty_ct[..16]);
        self.hash = mix_hash(&self.hash, &empty_ct);

        self.state = ResponderState::ResponseCreated;
        Ok(msg)
    }

    /// `peer.cookieGenerator.AddMacs`：给构造好的 response 加 MAC1（cookie 未就绪
    /// 时 MAC2 保持零）。
    pub fn add_macs(&mut self, msg: &mut [u8]) {
        self.cookie_generator.add_macs(msg);
    }

    /// `BeginSymmetricSession`（响应方分支）：`KDF2(chainKey, nil) = (recv, send)`。
    /// 消费 `self`，泄密材料随 `self` 一起被丢弃，只带出派生密钥。
    pub fn begin_symmetric_session(self) -> Result<ResponderKeys, ResponderError> {
        let (receive, send) = match self.state {
            ResponderState::ResponseCreated => kdf2(&self.chain_key, &[]),
            ResponderState::ResponseConsumed => {
                // 发起方分支（本响应方不会到达）；保留方向性语义以备完整设备运行时。
                let (send, receive) = kdf2(&self.chain_key, &[]);
                (receive, send)
            }
            _ => {
                return Err(ResponderError::State(
                    "非法状态派生 keypair：只能从 ResponseCreated/ResponseConsumed 派生",
                ))
            }
        };
        Ok(ResponderKeys {
            send,
            receive,
            local_index: self.local_index,
            remote_index: self.remote_index,
        })
    }
}
