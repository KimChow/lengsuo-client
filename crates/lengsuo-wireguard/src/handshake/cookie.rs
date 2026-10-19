//! Cookie/MAC1/MAC2——对齐 wireguard-go `device/cookie.go`。
//!
//! [`CookieChecker`] 对应设备级 `cookieChecker`（用本端静态公钥派生密钥）：
//! 校验入站握手的 MAC1、MAC2，并在 MAC2 无效或过载时签发 type 3 cookie reply。
//! [`CookieGenerator`] 对应 per-peer `cookieGenerator`（用对端静态公钥派生密钥）：
//! 为出站握手加 MAC1，并在消费了 cookie reply 后给后续握手加有效 MAC2。
//!
//! 随机源都由调用方注入种子（`secret_seed`/`nonce`），杜绝测试与生产的隐式
//! 随机差异——与参考 `rand.Read` 语义一致地“刷新即替换”。

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;

use super::noise::{
    cookie_encryption_key, ct_eq, derive_cookie, keyed_blake2s_128, mac1_key, COOKIE_REFRESH_TIME,
    COOKIE_REPLY_LEN, MAC_LEN, X_NONCE_LEN,
};

/// 入站握手（initiation/response）的 MAC 校验与 cookie reply 签发。
pub struct CookieChecker {
    /// `mac1.key`：`BLAKE2s-256("mac1----" || 本端公钥)`。
    mac1_key: [u8; 32],
    /// `mac2.secret`：签发 cookie 的 32B 密钥（每次刷新重新生成）。
    mac2_secret: [u8; 32],
    /// `mac2.secretSet`：secret 的生成时间；`None` 表示从未生成（必然过期）。
    mac2_secret_set: Option<std::time::Instant>,
    /// `mac2.encryptionKey`：`BLAKE2s-256("cookie--" || 本端公钥)`。
    mac2_encryption_key: [u8; 32],
}

impl CookieChecker {
    /// `Init(pk)`：pk 是本端静态公钥。
    #[must_use]
    pub fn init(own_public: &[u8; 32]) -> Self {
        Self {
            mac1_key: mac1_key(own_public),
            mac2_secret: [0u8; 32],
            mac2_secret_set: None,
            mac2_encryption_key: cookie_encryption_key(own_public),
        }
    }

    /// `CheckMAC1(msg)`：校验报文末尾倒数第二段 16B 的 MAC1。
    #[must_use]
    pub fn check_mac1(&self, msg: &[u8]) -> bool {
        let smac2 = msg.len() - MAC_LEN;
        let smac1 = smac2 - MAC_LEN;
        let expected = keyed_blake2s_128(&self.mac1_key, &msg[..smac1]);
        ct_eq(&expected, &msg[smac1..smac2])
    }

    /// `CheckMAC2(msg, src)`：cookie 过期即拒绝；否则按 `BLAKE2s-128(secret, src)`
    /// 派生 cookie 后校验报文最后一段 16B。
    #[must_use]
    pub fn check_mac2(&self, msg: &[u8], src: &[u8]) -> bool {
        if self.secret_stale() {
            return false;
        }
        let cookie = derive_cookie(&self.mac2_secret, src);
        let smac2 = msg.len() - MAC_LEN;
        let expected = keyed_blake2s_128(&cookie, &msg[..smac2]);
        ct_eq(&expected, &msg[smac2..])
    }

    /// `CreateReply(msg, recv, src)`：签发 64B cookie reply。
    ///
    /// `secret_seed` 与 `nonce` 对应参考里的 `rand.Read` 随机源，由调用方注入。
    pub fn create_reply(
        &mut self,
        msg: &[u8],
        recv: u32,
        src: &[u8],
        secret_seed: [u8; 32],
        nonce: [u8; X_NONCE_LEN],
    ) -> [u8; COOKIE_REPLY_LEN] {
        // 只在新 secret 需要刷新时才替换（参考 CreateReply 的过期判断）。
        if self.secret_stale() {
            self.mac2_secret = secret_seed;
            self.mac2_secret_set = Some(std::time::Instant::now());
        }
        let cookie = derive_cookie(&self.mac2_secret, src);

        let smac2 = msg.len() - MAC_LEN;
        let smac1 = smac2 - MAC_LEN;
        let cipher = XChaCha20Poly1305::new_from_slice(&self.mac2_encryption_key)
            .expect("cookie 加密密钥固定 32B");
        // AAD = 触发本 cookie reply 的那条报文的 MAC1（参考 `msg[smac1:smac2]`）。
        let ad = &msg[smac1..smac2];
        let encrypted = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &cookie,
                    aad: ad,
                },
            )
            .expect("cookie reply 加密仅长度异常才失败；输入长度受控");

        let mut reply = [0u8; COOKIE_REPLY_LEN];
        reply[..4].copy_from_slice(&3u32.to_le_bytes());
        reply[4..8].copy_from_slice(&recv.to_le_bytes());
        reply[8..8 + X_NONCE_LEN].copy_from_slice(&nonce);
        reply[8 + X_NONCE_LEN..].copy_from_slice(&encrypted);
        reply
    }

    fn secret_stale(&self) -> bool {
        self.mac2_secret_set
            .is_none_or(|set| set.elapsed() > COOKIE_REFRESH_TIME)
    }
}

/// 出站握手（initiation/response）的加 MAC 与 cookie reply 消费。
pub struct CookieGenerator {
    /// `mac1.key`：`BLAKE2s-256("mac1----" || 对端公钥)`。
    mac1_key: [u8; 32],
    /// `mac2.cookie`：消费 cookie reply 后保存的 16B cookie。
    mac2_cookie: [u8; MAC_LEN],
    /// `mac2.cookieSet`：cookie 写入时间；`None` 表示尚无 cookie。
    mac2_cookie_set: Option<std::time::Instant>,
    /// `mac2.hasLastMAC1`。
    mac2_has_last_mac1: bool,
    /// `mac2.lastMAC1`：最近一次 AddMacs 写下的 MAC1，作为 cookie reply 的 AAD。
    mac2_last_mac1: [u8; MAC_LEN],
    /// `mac2.encryptionKey`：`BLAKE2s-256("cookie--" || 对端公钥)`。
    mac2_encryption_key: [u8; 32],
}

impl CookieGenerator {
    /// `Init(pk)`：pk 是对端静态公钥。
    #[must_use]
    pub fn init(peer_public: &[u8; 32]) -> Self {
        Self {
            mac1_key: mac1_key(peer_public),
            mac2_cookie: [0u8; MAC_LEN],
            mac2_cookie_set: None,
            mac2_has_last_mac1: false,
            mac2_last_mac1: [0u8; MAC_LEN],
            mac2_encryption_key: cookie_encryption_key(peer_public),
        }
    }

    /// `ConsumeReply(msg)`：解密并保存 cookie reply 携带的 cookie。
    #[must_use]
    pub fn consume_reply(&mut self, msg: &[u8]) -> bool {
        if !self.mac2_has_last_mac1 || msg.len() != COOKIE_REPLY_LEN {
            return false;
        }
        let nonce: [u8; X_NONCE_LEN] = msg[8..8 + X_NONCE_LEN].try_into().expect("24B");
        let encrypted = &msg[8 + X_NONCE_LEN..];
        let cipher = XChaCha20Poly1305::new_from_slice(&self.mac2_encryption_key)
            .expect("cookie 解密密钥固定 32B");
        let Ok(cookie) = cipher.decrypt(
            (&nonce).into(),
            Payload {
                msg: encrypted,
                aad: &self.mac2_last_mac1,
            },
        ) else {
            return false;
        };
        self.mac2_cookie.copy_from_slice(&cookie);
        self.mac2_cookie_set = Some(std::time::Instant::now());
        true
    }

    /// `AddMacs(msg)`：就地写入 MAC1，并在 cookie 有效时写入 MAC2。
    pub fn add_macs(&mut self, msg: &mut [u8]) {
        let smac2 = msg.len() - MAC_LEN;
        let smac1 = smac2 - MAC_LEN;
        let mac1 = keyed_blake2s_128(&self.mac1_key, &msg[..smac1]);
        msg[smac1..smac2].copy_from_slice(&mac1);
        self.mac2_last_mac1 = mac1;
        self.mac2_has_last_mac1 = true;

        // cookie 过期则 MAC2 保持原值（即零——参考 AddMacs 直接返回）。
        let fresh = self
            .mac2_cookie_set
            .is_some_and(|set| set.elapsed() <= COOKIE_REFRESH_TIME);
        if fresh {
            let mac2 = keyed_blake2s_128(&self.mac2_cookie, &msg[..smac2]);
            msg[smac2..].copy_from_slice(&mac2);
        }
    }
}
