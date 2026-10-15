//! 传统 Shadowsocks AEAD 的 UDP 数据报编解码（不是完整 UDP 中继服务）。
//!
//! 线上格式与参考基线一致（Xray v26.3.27，完整 commit
//! `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`；`proxy/shadowsocks/protocol.go`
//! 的 `EncodeUDPPacket` / `DecodeUDPPacket`，`proxy/shadowsocks/config.go` 的
//! `AEADCipher.EncodePacket` / `DecodePacket`）：
//!
//! ```text
//! salt (AES-128-GCM=16 字节，其余三类=32 字节)
//!   || AEAD_Seal(subkey = HKDF-SHA1(master_key, salt, "ss-subkey"),
//!                nonce  = 全 0（每包新建计数器，首次取用即全 0）,
//!                plain  = SOCKS 目标地址 || UDP 载荷)
//! ```
//!
//! 尾部 16 字节是 AEAD tag，无 additional data。主密钥由
//! `ss_core::kdf::evp_bytes_to_key` 从口令派生；`seal` 每包用 `getrandom` 取新
//! salt 并新建 `SessionAead`，因此以系统随机源降低不同包的 (subkey, nonce) 碰撞风险。
//! `open` 的顺序固定为长度检查 → 拆 salt → 派生 → 认证 → 解析地址：认证不通过
//! 就绝不解析任何地址字节，一律 fail-closed，也没有明文回退路径。
//!
//! 入站防重放（同 salt 唯一性）与密钥轮换尚未实现，也不在此处缓存任何 salt；
//! 见 `docs/shadowsocks-status.md`。

use ss_core::crypto::{CipherSuite, SessionAead, TAG_LEN};
use ss_core::kdf::{evp_bytes_to_key, hkdf_sha1_subkey};
use ss_core::target::TargetAddr;

/// 单个 UDP 数据报的总长度上限（IPv4 最大报文扣除最小 IP/UDP 头）。
/// `seal` 与 `open` 都拒绝超过该值的包，避免把巨型数据报交给网络层。
pub const MAX_PACKET_LEN: usize = 65_507;

/// 编解码失败原因。认证失败与格式失败分开报告，调用方两者都必须 fail-closed。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("数据报过短：salt + tag 至少需要 {need} 字节，实际 {got}")]
    TooShort { need: usize, got: usize },

    #[error("数据报过长：{got} 字节超过 UDP 上限 {limit}")]
    TooLong { limit: usize, got: usize },

    #[error("密钥或 salt 长度与套件不符：期望 {want} 字节，实际 {got}")]
    KeyLength { want: usize, got: usize },

    #[error("随机 salt 获取失败")]
    Entropy,

    #[error("封装失败：{0}")]
    Seal(ss_core::Error),

    #[error("AEAD 认证失败（错误口令、篡改或 salt 不匹配）")]
    Authentication,

    #[error("解密后的目标地址非法：{0}")]
    Address(#[from] ss_core::Error),
}

/// 传统 Shadowsocks AEAD 的单包 UDP 编解码器。
///
/// 持有口令派生出的主密钥，因此**故意不实现 `Debug`**（也不实现 `Display`），
/// 避免密码、主密钥或 subkey 进入日志与调试输出。
pub struct UdpCodec {
    suite: CipherSuite,
    master_key: Vec<u8>,
}

impl UdpCodec {
    /// 由套件与口令构造。口令只在派生期间使用，结构体不保留其明文。
    ///
    /// 空口令、salt/nonce/密钥长度与套件定义不符都在返回 `Err` 时失败，
    /// 不会留下半构造的状态。
    pub fn new(suite: CipherSuite, password: &[u8]) -> Result<Self, Error> {
        if password.is_empty() {
            return Err(Error::KeyLength {
                want: suite.key_len(),
                got: 0,
            });
        }
        // 四类 AEAD 套件的 salt 与密钥长度必须非零且互相对应；不满足说明
        // 调用方给出的套件与本模块假设不一致，宁可不构造。
        if suite.salt_len() == 0 || suite.nonce_len() == 0 {
            return Err(Error::KeyLength {
                want: suite.key_len(),
                got: suite.salt_len(),
            });
        }
        let master_key = evp_bytes_to_key(password, suite.key_len());
        // evp_bytes_to_key 总是截断到请求长度；长度不符说明派生与套件不同步。
        if master_key.len() != suite.key_len() {
            return Err(Error::KeyLength {
                want: suite.key_len(),
                got: master_key.len(),
            });
        }
        Ok(Self { suite, master_key })
    }

    /// 本编解码器使用的 AEAD 套件。
    #[must_use]
    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// salt 长度（= 套件 IV/salt 字节数），调用方预分配与截断判断可用。
    #[must_use]
    pub fn salt_len(&self) -> usize {
        self.suite.salt_len()
    }

    /// 加密一个 UDP 数据报，返回 `salt || ct || tag`。
    ///
    /// salt 由 `getrandom` 每次重新生成（长度取套件的 `salt_len()`），
    /// `target` 与 `packet` 一起作为被认证的明文。非法目标（域名过长或含
    /// NUL）与超限长度在产生任何字节前失败。
    pub fn seal(&self, target: &TargetAddr, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let mut salt = vec![0u8; self.suite.salt_len()];
        getrandom::getrandom(&mut salt).map_err(|_| Error::Entropy)?;
        self.seal_with_salt(&salt, target, packet)
    }

    /// 解密并验证一个 UDP 数据报，返回（目标地址，原始载荷）。
    pub fn open(&self, packet: &[u8]) -> Result<(TargetAddr, Vec<u8>), Error> {
        let salt_len = self.suite.salt_len();
        let min_len = salt_len + TAG_LEN;
        if packet.len() < min_len {
            return Err(Error::TooShort {
                need: min_len,
                got: packet.len(),
            });
        }
        if packet.len() > MAX_PACKET_LEN {
            return Err(Error::TooLong {
                limit: MAX_PACKET_LEN,
                got: packet.len(),
            });
        }
        let (salt, ct) = packet.split_at(salt_len);
        let plaintext = self
            .aead_with_salt(salt)
            .open(ct)
            .map_err(|err| match err {
                ss_core::Error::AuthFailed => Error::Authentication,
                other => Error::Seal(other),
            })?;
        // 认证通过之后才信任明文里的地址字节。
        let (target, consumed) = TargetAddr::decode(&plaintext)?;
        Ok((target, plaintext[consumed..].to_vec()))
    }

    /// 用给定 salt 密封。唯一的公开入口是 `seal`（salt 只来自 `getrandom`）；
    /// 本函数模块私有，供固定 salt 的确定性单元测试逐字节比对向量（`vectors.rs`），
    /// 外部无法指定 salt。
    fn seal_with_salt(
        &self,
        salt: &[u8],
        target: &TargetAddr,
        packet: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if salt.len() != self.suite.salt_len() {
            return Err(Error::KeyLength {
                want: self.suite.salt_len(),
                got: salt.len(),
            });
        }
        let mut plaintext = Vec::new();
        // encode_checked：不可信域名先校验，空/过长/含 NUL 都不写出任何字节。
        target.encode_checked(&mut plaintext)?;
        let total = salt
            .len()
            .checked_add(plaintext.len())
            .and_then(|n| n.checked_add(packet.len()))
            .and_then(|n| n.checked_add(TAG_LEN))
            .ok_or(Error::TooLong {
                limit: MAX_PACKET_LEN,
                got: usize::MAX,
            })?;
        if total > MAX_PACKET_LEN {
            return Err(Error::TooLong {
                limit: MAX_PACKET_LEN,
                got: total,
            });
        }
        plaintext.extend_from_slice(packet);
        // 全新 SessionAead：计数器从全 0xFF 起，本包首个 nonce 即全 0。
        // 每包新建，因而生产入口不得复用发送 salt；接收重复 salt 仍须上层过滤。
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(salt);
        let sealed = self.aead_with_salt(salt).seal(&plaintext)?;
        if sealed.len() != plaintext.len() + TAG_LEN {
            return Err(Error::Seal(ss_core::Error::SealFailed));
        }
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// 由 salt 派生本包 subkey 并构造一次性 AEAD 上下文。
    fn aead_with_salt(&self, salt: &[u8]) -> SessionAead {
        let subkey = hkdf_sha1_subkey(&self.master_key, salt, self.suite.key_len());
        SessionAead::new(self.suite, subkey)
    }
}

#[cfg(test)]
mod vectors;
