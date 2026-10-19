//! WireGuard Noise IK 握手（客户端/发起方）——对齐 wireguard-go
//! `device/noise-protocol.go`（commit `2631ce99a06f27120d581611cf125d68bc6aa565`）
//! 的 `CreateMessageInitiation` / `ConsumeMessageResponse` / `BeginSymmetricSession`。
//!
//! 范围：只做发起方——构造 initiation（148B）、处理 response（92B）、派生
//! transport 收发密钥。MAC1 依参考 `AddMacs`/`CheckMAC1` 语义。
//! PSK（可选 32B）参与 KDF3 分支。COOKIE 轮换、keepalive 计时、重试状态机
//! 不在本层。
//!
//! fail-closed：响应认证失败/状态失同步后 [`Handshake`] 进入 poison，调用方
//! 必须弃用。密钥材料类型不派生 `Debug`，错误消息只含状态名。

use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

use super::noise::*;
use crate::transport::Error;

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
        self.hash = mix_hash_pub(self.hash, &self.remote_static);

        // mixKey(ephemeral_public)
        self.chain_key = mix_key(&self.chain_key, &ephemeral_public);
        self.hash = mix_hash_pub(self.hash, &ephemeral_public);

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
        self.hash = mix_hash_pub(self.hash, &encrypted_static);

        // DH(static, remote_static)（precomputedStaticStatic）→ KDF2 → 加密 TAI64N。
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
        self.hash = mix_hash_pub(self.hash, &encrypted_timestamp); // 参考先于组帧 mix

        // 组帧：type(1) sender(4) ephemeral(32) static(48) timestamp(28) mac1(16) mac2(16)。
        let mut msg = [0u8; INITIATION_LEN];
        // 线上字段一律 little endian（参考 `MessageInitiation.marshal` 用
        // `binary.LittleEndian`；类型字段占 4 字节，低字节为类型、高三字节保留零）。
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
        Ok(msg)
    }

    /// `ConsumeMessageResponse`：校验 92B 响应并派生 transport 密钥。
    ///
    /// 响应帧布局：type(4) sender(4) receiver(4) ephemeral(32) empty(16) mac1(16) mac2(16)。
    /// empty = AEAD(空明文，AAD=当前 hash)。MAC1 校验需对端静态公钥——参考由
    /// cookie checker 持有；本层校验 AEAD 前先验证 MAC1。
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
        // 线上字段 little endian（参考 `MessageResponse.unmarshal`）。
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

        // MAC1 校验（参考 receive.go 对 initiation/response 都先过 CheckMAC1）：
        // key = BLAKE2s-256("mac1----" || 本端静态公钥)——即"报文接收方自己的公钥"。
        let own_public = XPublic::from(&self.static_secret).to_bytes();
        if !ct_eq(
            &mac1(&own_public, &wire[..RESPONSE_LEN - 32]),
            &wire[60..76],
        ) {
            self.state = State::Poisoned;
            return Err(Error::AuthFailed);
        }

        // 完成三次 DH：mixHash/mixKey(eph) → DH(eph,eph) → DH(static,eph) → KDF3(psk)。
        self.hash = mix_hash_pub(self.hash, &ephemeral);
        self.chain_key = mix_key(&self.chain_key, &ephemeral);

        let local_ephemeral = self
            .local_ephemeral_secret
            .take()
            .ok_or(Error::AuthFailed)?;
        let ss1 = local_ephemeral.diffie_hellman(&XPublic::from(ephemeral));
        self.chain_key = mix_key(&self.chain_key, ss1.as_bytes());

        let ss2 = self.static_secret.diffie_hellman(&XPublic::from(ephemeral));
        self.chain_key = mix_key(&self.chain_key, ss2.as_bytes());

        // 参考语义：PSK 永远参与 KDF3（None = 全零 PSK）；tau 混入 hash 后
        // 用 KDF3 的 key(t2) 做 empty AEAD 认证。
        let psk = self.preshared_key.unwrap_or([0u8; PSK_LEN]);
        let (ck2, tau2, key2) = kdf3(&self.chain_key, &psk);
        self.chain_key = ck2;
        self.hash = mix_hash_pub(self.hash, &tau2);
        open(&key2, &empty_ct, &self.hash).map_err(|_| {
            self.state = State::Poisoned;
            Error::AuthFailed
        })?;
        self.hash = mix_hash_pub(self.hash, &empty_ct);

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
