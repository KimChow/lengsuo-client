//! 口令 → 主密钥 → 方向会话的共享派生原语（UDP 与 TCP 复用，不各自复制一份）。
//!
//! 派生链与参考基线一致（Xray v26.3.27 / `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`，
//! `proxy/shadowsocks/config.go` 的 `getCipher`/`createAuthenticator`）：
//!
//! ```text
//! master_key = evp_bytes_to_key(password, KeyBytes)      // ss_core::kdf
//! subkey     = HKDF-SHA1(master_key, salt, "ss-subkey")   // ss_core::kdf
//! nonce      = 每个方向一套独立的递增序列                 // ss_core::crypto
//! ```
//!
//! `salt_len()` 直接取套件的 IV/salt 长度定义（AES-128-GCM 16，其余 32），因此
//! 长度约束只有一套来源。`MasterKey` 与 `SessionAead` 都**故意不实现 `Debug`**，
//! 密码、主密钥、salt 派生出的 subkey 都不会进入日志或调试输出。

use ss_core::crypto::{CipherSuite, SessionAead};
use ss_core::kdf::{evp_bytes_to_key, hkdf_sha1_subkey};

/// 派生参数不合法的原因。UDP 与 TCP 两个入口共用本类型（经 `lib.rs` 再导出）。
/// 各变体只带长度，不含口令、主密钥或 subkey，因此 `Display`/`Debug` 可安全输出。
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// 空口令没有可派生的主密钥；参考实现的密码配置同样拒绝空值。
    #[error("空口令无法派生主密钥（套件需要 {key_len} 字节）")]
    EmptyPassword { key_len: usize },
    /// 套件的 salt 或 nonce 长度为零，与本模块的线上格式假设不符。
    #[error("套件参数与本模块的线上格式不符：密钥 {key_len}，salt {salt_len}")]
    SuiteParams { key_len: usize, salt_len: usize },
    /// 派生结果长度与套件密钥长度不符（派生与套件不同步）。
    #[error("派生密钥长度不符：期望 {want}，实际 {got}")]
    DerivedLength { want: usize, got: usize },
    /// 给出的 salt 长度与套件不符。
    #[error("salt 长度不符：期望 {want}，实际 {got}")]
    SaltLength { want: usize, got: usize },
}

/// 取系统随机数失败（salt 必须由密码学随机源给出）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EntropyError;

/// 口令派生出的主密钥；只在派生期间持有口令明文。
///
/// **故意不实现 `Debug`/`Display`**：主密钥与派生出的 subkey 不得进入日志或
/// 调试输出。`key` 私有，只有 `raw` 在 `cfg(test)` 下暴露字节。
pub(crate) struct MasterKey {
    suite: CipherSuite,
    key: Vec<u8>,
}

impl MasterKey {
    /// 由套件与口令派生主密钥。空口令、salt/nonce/密钥长度与套件定义不符都在
    /// 返回 `Err` 时失败，不留半构造状态。
    pub(crate) fn new(suite: CipherSuite, password: &[u8]) -> Result<Self, KeyError> {
        if password.is_empty() {
            return Err(KeyError::EmptyPassword {
                key_len: suite.key_len(),
            });
        }
        // 四类 AEAD 套件的 salt 与 nonce 长度必须非零，否则线上帧格式不成立。
        if suite.salt_len() == 0 || suite.nonce_len() == 0 {
            return Err(KeyError::SuiteParams {
                key_len: suite.key_len(),
                salt_len: suite.salt_len(),
            });
        }
        let key = evp_bytes_to_key(password, suite.key_len());
        let want = suite.key_len();
        // evp_bytes_to_key 总是截断到请求长度；长度不符说明派生与套件不同步。
        if key.len() != want {
            return Err(KeyError::DerivedLength {
                want,
                got: key.len(),
            });
        }
        Ok(Self { suite, key })
    }

    #[must_use]
    pub(crate) fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// 本套件的会话 salt 长度（= IV 长度）。
    #[must_use]
    pub(crate) fn salt_len(&self) -> usize {
        self.suite.salt_len()
    }

    /// 派生出的主密钥字节，仅供 crate 内 `cfg(test)` 断言使用。
    #[cfg(test)]
    pub(crate) fn raw(&self) -> &[u8] {
        &self.key
    }

    /// 用系统随机源取一个新 salt（长度取套件定义）。
    pub(crate) fn new_salt(&self) -> Result<Vec<u8>, EntropyError> {
        let mut salt = vec![0u8; self.suite.salt_len()];
        getrandom::getrandom(&mut salt).map_err(|_| EntropyError)?;
        Ok(salt)
    }

    /// 由 salt 派生本方向 subkey 并建立会话 AEAD 上下文（nonce 序列自此独立递增）。
    pub(crate) fn session(&self, salt: &[u8]) -> Result<SessionAead, KeyError> {
        let want = self.suite.salt_len();
        if salt.len() != want {
            return Err(KeyError::SaltLength {
                want,
                got: salt.len(),
            });
        }
        let subkey = hkdf_sha1_subkey(&self.key, salt, self.suite.key_len());
        Ok(SessionAead::new(self.suite, subkey))
    }
}
