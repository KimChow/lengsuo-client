//! WireGuard Noise IK 握手——对齐 wireguard-go（commit
//! `2631ce99a06f27120d581611cf125d68bc6aa565`）的 `device/noise-protocol.go`、
//! `device/noise-helpers.go`、`device/cookie.go`。
//!
//! - [`noise`]：HMAC-BLAKE2s-256/KDF1-KDF3/mixHash/mixKey、AEAD、MAC、TAI64N。
//! - [`initiator`]：发起方 `CreateMessageInitiation`/`ConsumeMessageResponse`。
//! - [`responder`]：响应方 `ConsumeMessageInitiation`/`CreateMessageResponse`/
//!   `BeginSymmetricSession`。
//! - [`cookie`]：`CookieChecker`（MAC1/MAC2 校验 + cookie reply 签发）与
//!   `CookieGenerator`（加 MAC + cookie reply 消费）。
//!
//! COOKIE 重试状态机、keepalive 计时、密钥轮换与完整设备运行时不在本层。

mod cookie;
mod initiator;
mod noise;
mod responder;

pub use cookie::{CookieChecker, CookieGenerator};
pub use initiator::{Handshake, TransportKeys};
pub use noise::{
    ct_eq, derive_cookie, initial_chain_key, initial_hash, kdf1_pub, kdf2_pub, kdf3_pub, keyed_blake2s_128,
    mac1, mix_hash_pub, mix_key, open_aead, seal_aead, tai64n_after, tai64n_now, CONSTRUCTION,
    COOKIE_REPLY_LEN, COOKIE_REFRESH_TIME, HANDSHAKE_INITIATION_RATE, INITIATION_LEN, LABEL_COOKIE,
    LABEL_MAC1, MAC_LEN, PSK_LEN, RESPONSE_LEN, WG_IDENTIFIER, X_NONCE_LEN, ZERO_NONCE_LEN,
};
pub use responder::{Responder, ResponderError, ResponderKeys, ResponderState};