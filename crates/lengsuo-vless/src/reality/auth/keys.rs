//! REALITY 客户端的握手密钥材料（临时 X25519 密钥对 + `auth_key` 派生）。
//!
//! 从 [`super`] 拆出以符合 400 行软目标；公开 API 不变。
//!
//! 参考 `transport/internet/reality/reality.go:147-168`（`UClient` 内联块）：
//! `ecdh.X25519().NewPublicKey(peer)` → `ecdh.ECDH(peerPub)` →
//! `hkdf.New(sha256.New, AuthKey, hello.Random[:20], []byte("REALITY"))`。

use aes_gcm::aead::rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::{derive_auth_key, AuthError, RANDOM_LEN, X25519_LEN};
use crate::reality::x25519::{x25519, x25519_base};

/// 客户端侧的 REALITY 握手密钥材料。
///
/// `Debug` **不输出任何密钥字节**（硬约束：日志/Debug 不得泄漏密钥）。
/// 临时公钥本就明文上行，可以在 Debug 里出现。
pub struct RealityClientKeys {
    ephemeral_public: [u8; X25519_LEN],
    /// ECDH 共享密钥（即参考里 `AuthKey` 的 HKDF 输入）。
    shared: [u8; X25519_LEN],
}

impl Drop for RealityClientKeys {
    fn drop(&mut self) {
        // 硬约束：密钥材料用后清零。
        self.shared.zeroize();
    }
}

impl core::fmt::Debug for RealityClientKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RealityClientKeys")
            .field("ephemeral_public", &hex(&self.ephemeral_public))
            .field("shared", &"<redacted>")
            .finish()
    }
}

impl RealityClientKeys {
    /// 生成临时 X25519 密钥对并与服务端公钥协商共享密钥。
    ///
    /// `rng` 注入随机源：真实运行用 `aes_gcm::aead::OsRng`，测试用确定性 RNG。
    /// 参考用 Go 标准库 `ecdh.X25519()`；本卡无该依赖，改用本 crate 内置的
    /// [`crate::reality::x25519`]（见报告「偏离清单」）。协议字节完全一致：
    /// 同为 RFC 7748 X25519。
    pub fn generate<R: RngCore + CryptoRng>(
        server_public: &[u8; X25519_LEN],
        rng: &mut R,
    ) -> Result<Self, AuthError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let ephemeral_public = x25519_base(&seed);
        // 对齐参考：全零/低阶点共享密钥必须失败（`X25519` 返回 error、
        // `AuthKey == nil`），不得当作合法共享密钥继续。
        let shared = x25519(&seed, server_public).map_err(|_| AuthError::InvalidPublicKey)?;
        seed.zeroize();
        Ok(Self {
            ephemeral_public,
            shared,
        })
    }

    /// 临时公钥（写入 ClientHello 的 key_share）。
    pub fn ephemeral_public(&self) -> [u8; X25519_LEN] {
        self.ephemeral_public
    }

    /// 与 32 字节 `client_random` 一起派生 `auth_key`。
    ///
    /// 对齐参考：`AuthKey = X25519(priv, server_pub)` 随后
    /// `HKDF(ikm = AuthKey, salt = random[:20], info = "REALITY")`。
    ///
    /// **`auth_key` 不落地保存**：调用方拿到后自行控制生命周期
    /// （`seal_auth_payload` 用完即可丢弃）。
    pub fn derive_auth_key(&self, random: &[u8; RANDOM_LEN]) -> Result<[u8; 32], AuthError> {
        derive_auth_key(&self.shared, random)
    }
}

/// 十六进制小写编码（仅用于 Debug 输出公钥）。
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
