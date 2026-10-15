//! AEAD 原语层（与 Xray common/crypto 的 AEADAuthenticator + GenerateAEADNonceWithSize 行为对齐）。
//!
//! 关键语义（不可偏离）：
//! - nonce 从全 0xFF 起始，每次取用**先递增后使用**（首次取用 = 全 0，第二次 = ...01）
//! - 同一会话内 size 块与 payload 块共用同一递增序列（每块消耗 2 个 nonce：先 size 后 payload）
//! - AEAD 无 additional data
//! - **nonce 取尽 fail-closed**：计数达上限返回 [`Error::NonceExhausted`]，不回绕复用、
//!   不 panic，且计数器与 `SessionAead` 永久保持取尽（详见 [`NonceCounter`] 文档）

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

use crate::{Error, Result};

pub const TAG_LEN: usize = 16;

/// Xray Shadowsocks 支持的 AEAD 套件（config.go getCipher 的 Rust 对应物）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20IetfPoly1305,
    XChaCha20IetfPoly1305,
}

impl CipherSuite {
    /// 解析套件名（SIP00x 命名，与 Xray CipherType 对应）。
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "aes-128-gcm" => Some(Self::Aes128Gcm),
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" => Some(Self::ChaCha20IetfPoly1305),
            "xchacha20-ietf-poly1305" => Some(Self::XChaCha20IetfPoly1305),
            _ => None,
        }
    }

    /// 主密钥长度（KeyBytes）。
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            _ => 32,
        }
    }

    /// 会话 salt/IV 长度（IVBytes，Xray 表：AES-128-GCM=16，其余=32）。
    pub fn salt_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            _ => 32,
        }
    }

    /// nonce 长度（XChaCha 为 24，其余 12）。
    pub fn nonce_len(self) -> usize {
        match self {
            Self::XChaCha20IetfPoly1305 => 24,
            _ => 12,
        }
    }

    fn seal_raw(self, key: &[u8], nonce: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        let ct = match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .encrypt(nonce.into(), pt),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .encrypt(nonce.into(), pt),
            Self::ChaCha20IetfPoly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .encrypt(nonce.into(), pt),
            Self::XChaCha20IetfPoly1305 => XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .encrypt(nonce.into(), pt),
        };
        ct.map_err(|_| Error::SealFailed)
    }

    fn open_raw(self, key: &[u8], nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        let pt = match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .decrypt(nonce.into(), ct),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .decrypt(nonce.into(), ct),
            Self::ChaCha20IetfPoly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .decrypt(nonce.into(), ct),
            Self::XChaCha20IetfPoly1305 => XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?
                .decrypt(nonce.into(), ct),
        };
        pt.map_err(|_| Error::AuthFailed)
    }
}

/// 小端递增计数器 nonce：全 0xFF 起始，先增后用（首次输出全 0）。
/// 复刻 Xray GenerateIncreasingNonce 的进位方向：byte[0] 先加，进位向高位。
///
/// ## 取尽语义（fail-closed，永久 poison）
///
/// 可取用总量是 `2^(8 * nonce_len)` 个 nonce：从全 `0xFF` 起第一步落到全 `0`
/// （第一个合法 nonce），一直走到全 `0xFF`（最后一个合法 nonce）；再下一步会
/// 回到全 `0`，即**重复首个 nonce**——这在 AEAD 语义下是灾难性的 (key, nonce)
/// 重用，因此本实现**不回绕复用、不 panic**，改为返回 [`Error::NonceExhausted`]
/// 并把计数器置为已取尽状态：此后每次取用继续报同一个错，不存在"再取一次就
/// 恢复"的路径（`SessionAead` 同理，见下）。取尽那一步**不产出任何 nonce**，
/// 内部值也保持在最后一个合法 nonce（全 `0xFF`），绝不留下全 `0` 的可重用形态。
///
/// 依据：Xray `common/crypto/auth.go` 的 `GenerateAEADNonceWithSize` /
/// `GenerateIncreasingNonce` 只是 `c[i]++; if c[i] != 0 { break }` 的自然长度
/// 溢出，取尽后**静默回绕**并复用 nonce（`AEADAuthenticator.Seal`/`Open` 无从
/// 感知，因为它只检查 `len(iv) != NonceSize()`，长度始终相等）。这是参考实现
/// 的真实缺陷，不是我们的对齐目标：本项目在 `ss-core` 这一层把它改成显式错误
/// （对应 parity 缺口清单 §2.2 第 2 项）。唯一一次例外的回绕是**首步**
/// （全 `0xFF` → 全 `0`），那是 Xray 语义下的第一个 nonce，必须放行。
///
/// 各套件的实际上限（`nonce_len` × 8 位计数空间；TCP 流式每块消耗 2 个 nonce：
/// 先 size 后 payload，见 `crate::chunk`）：
///
/// | 套件 | nonce_len | 可取 nonce 总数 | 约 | 同会话加密块上限 |
/// | --- | --- | --- | --- | --- |
/// | AES-128-GCM / AES-256-GCM / ChaCha20-IETF-Poly1305 | 12 | `2^96` | 7.9×10^28 | `2^95` |
/// | XChaCha20-IETF-Poly1305 | 24 | `2^192` | 6.3×10^57 | `2^191` |
///
/// 按 chunk 载荷上限 8192 B 折算，走满 `2^96` 约需 7.9×10^23 字节的单会话流量，
/// 远超单个 key epoch 的实际容量——正常路径永远碰不到；本错误存在是为了让异常
/// 长寿命会话显式失败，而不是静默重用。生产上真正先到的是密钥生命周期策略
/// （轮换 salt / key epoch），不是这个上限。UDP 每包新建 `SessionAead`（一次性
/// 零 nonce），不会走到取尽。
pub struct NonceCounter {
    counter: Vec<u8>,
    /// 尚未取用任何 nonce：此时全 `0xFF` → 全 `0` 的回绕是 Xray 语义下的第一个
    /// 合法 nonce，必须放行；之后的任何整串进位都视为取尽。
    pristine: bool,
    /// 已取尽标志：一旦置真，`next` 永久报错，绝不产出下一个 nonce。
    exhausted: bool,
}

impl NonceCounter {
    /// 新建计数器（全 `0xFF` 起始，首个取用产出全 `0`）。
    /// `nonce_len` 为 0 时视为立即取尽：不存在可用的 nonce 形态。
    pub fn new(nonce_len: usize) -> Self {
        Self {
            counter: vec![0xFF; nonce_len],
            pristine: nonce_len != 0,
            exhausted: nonce_len == 0,
        }
    }

    /// 长度 `nonce_len` 的计数器在一个 key epoch 内可取用的 nonce 总数
    /// （饱和于 `u128`）；`nonce_len = 0` 表示无 nonce 可用，返回 0。
    #[must_use]
    pub fn capacity(nonce_len: usize) -> u128 {
        if nonce_len == 0 {
            return 0;
        }
        let bits = nonce_len.saturating_mul(8);
        if bits >= 128 {
            u128::MAX
        } else {
            1u128 << bits
        }
    }

    /// 是否已取尽（已尽 ⇒ 后续取用一律报错，对象只能丢弃）。
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// 取下一个 nonce（先增后用）。取尽时返回 [`Error::NonceExhausted`]，
    /// 且状态永久保持取尽，不回绕、不 panic。
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<&[u8]> {
        if self.exhausted {
            return Err(Error::NonceExhausted);
        }
        // 只有整串 byte 全部进位（全 0xFF → 全 0）才会 carry_out：非首步时这正是
        // "即将复用首个 nonce" 的一步，必须拒绝而不是回绕。
        let mut carry_out = true;
        for bytes in self.counter.iter_mut() {
            let (value, overflowed) = bytes.overflowing_add(1);
            *bytes = value;
            if !overflowed {
                carry_out = false;
                break;
            }
        }
        if carry_out && !self.pristine {
            // 恢复最后一个合法 nonce 的形态，绝不留下全 0 的可重用值；状态永久取尽。
            self.counter.fill(0xFF);
            self.exhausted = true;
            return Err(Error::NonceExhausted);
        }
        self.pristine = false;
        Ok(&self.counter)
    }

    /// 测试专用：从给定计数值起建（首步回绕豁免已关闭），用于把计数器放到
    /// 接近取尽的位置。仅供本 crate 的边界测试使用，产品路径一律走 [`Self::new`]。
    #[cfg(test)]
    pub(crate) fn at_value(counter: &[u8]) -> Self {
        Self {
            counter: counter.to_vec(),
            pristine: false,
            exhausted: counter.is_empty(),
        }
    }
}

/// 一个会话方向的 AEAD 上下文（对应 Xray AEADAuthenticator + AEADChunkSizeParser 组合）。
///
/// nonce 取尽后本对象**永久不可复用**：`seal`/`open` 一律返回
/// [`Error::NonceExhausted`]（fail-closed，不回绕重用 nonce、不 panic、不静默
/// 退化），调用方必须断开该方向并轮换密钥 / 重建会话（重新协商 salt）。
/// 故意不实现 `Debug`：`subkey` 与 nonce 状态都不能进日志或调试输出。
pub struct SessionAead {
    suite: CipherSuite,
    subkey: Vec<u8>,
    nonce: NonceCounter,
}

impl SessionAead {
    /// 由 subkey 构造（subkey 由调用方经 kdf::hkdf_sha1_subkey 派生）。
    pub fn new(suite: CipherSuite, subkey: Vec<u8>) -> Self {
        debug_assert_eq!(subkey.len(), suite.key_len());
        Self {
            suite,
            subkey,
            nonce: NonceCounter::new(suite.nonce_len()),
        }
    }

    /// 加密任意明文块，消耗一个 nonce，返回 ct = pt || tag。
    ///
    /// nonce 取尽 ⇒ [`Error::NonceExhausted`]，且本对象后续每次调用都继续报同一错误。
    pub fn seal(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce.next()?.to_vec();
        self.suite.seal_raw(&self.subkey, &nonce, pt)
    }

    /// 解密任意密文块（pt||tag 形态），消耗一个 nonce。
    ///
    /// nonce 取尽 ⇒ [`Error::NonceExhausted`]（与 `seal` 同一永久取尽状态，
    /// 两个方向各自独立持有自己的 `SessionAead`）。
    pub fn open(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce.next()?.to_vec();
        self.suite.open_raw(&self.subkey, &nonce, ct)
    }

    /// 本方向的 nonce 计数器是否已取尽（取尽 ⇒ 本对象只能被丢弃）。
    #[must_use]
    pub fn nonce_exhausted(&self) -> bool {
        self.nonce.is_exhausted()
    }

    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }
}

/// 测试专用：把某方向的计数器直接放到给定值（首步豁免关闭），用于覆盖取尽边界。
///
/// 走满 `2^(8 * nonce_len)` 在测试里不可行（12 字节要 2^96 步），因此这里用真实
/// `nonce_len` 但接近全 `0xFF` 的种子值，几步之内即可命中取尽；线格式与产品路径
/// 完全一致。`counter` 长度必须等于套件的 `nonce_len()`。
#[cfg(test)]
pub(crate) fn session_at_nonce(suite: CipherSuite, subkey: Vec<u8>, counter: &[u8]) -> SessionAead {
    debug_assert_eq!(subkey.len(), suite.key_len());
    debug_assert_eq!(counter.len(), suite.nonce_len());
    SessionAead {
        suite,
        subkey,
        nonce: NonceCounter::at_value(counter),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_starts_at_zero_then_increments() {
        // Xray GenerateIncreasingNonce: c[i]++; if c[i]!=0 break —— FF+1=00 继续进位
        // 全 FF 起始 → 首次调用回绕为全 0，第二次为 [01,00×11]（little-endian 递增）
        let mut n = NonceCounter::new(12);
        assert_eq!(n.next().unwrap(), &[0u8; 12]);
        assert_eq!(n.next().unwrap(), &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut n2 = NonceCounter::new(1);
        assert_eq!(n2.next().unwrap(), &[0]);
        assert_eq!(n2.next().unwrap(), &[1]);
        // byte0 从 FF 走满一轮后进位到 byte1
        let mut n3 = NonceCounter::new(2);
        n3.next().unwrap(); // 全 0
        for _ in 0..255 {
            n3.next().unwrap(); // [1,0] ... [FF,0]
        }
        assert_eq!(n3.next().unwrap(), &[0, 1]); // byte0 FF→00 进位，byte1 00→01
        assert_eq!(n3.next().unwrap(), &[1, 1]);
    }

    #[test]
    fn capacity_matches_each_suites_nonce_space() {
        // 上限 = 2^(8*nonce_len)，与套件表一致；XChaCha 的 2^192 饱和于 u128。
        assert_eq!(NonceCounter::capacity(0), 0);
        assert_eq!(NonceCounter::capacity(1), 256);
        assert_eq!(NonceCounter::capacity(2), 65536);
        for suite in [
            CipherSuite::Aes128Gcm,
            CipherSuite::Aes256Gcm,
            CipherSuite::ChaCha20IetfPoly1305,
        ] {
            assert_eq!(NonceCounter::capacity(suite.nonce_len()), 1u128 << 96);
        }
        assert_eq!(
            NonceCounter::capacity(CipherSuite::XChaCha20IetfPoly1305.nonce_len()),
            u128::MAX
        );
    }

    #[test]
    fn one_byte_counter_uses_every_nonce_exactly_once_then_refuses() {
        // 穷举最小计数空间：capacity(1)=256 个 nonce 逐个取用且互不重复，
        // 第 257 步必须拒绝（此处正是 Xray 侧静默回绕复用全 0 的位置）。
        let mut counter = NonceCounter::new(1);
        let mut seen = [false; 256];
        for _ in 0..256 {
            let nonce = counter.next().expect("前 256 个 nonce 全部合法");
            assert_eq!(nonce.len(), 1);
            let value = nonce[0] as usize;
            assert!(
                !seen[value],
                "nonce {value:02x} 被重复取用：必须 fail-closed 而不是回绕"
            );
            seen[value] = true;
            assert!(!counter.is_exhausted());
        }
        assert!(seen.iter().all(|used| *used), "计数空间必须被完整覆盖");
        assert!(
            matches!(counter.next(), Err(Error::NonceExhausted)),
            "取尽后必须返回 NonceExhausted"
        );
        assert!(counter.is_exhausted());
    }

    #[test]
    fn last_legal_nonce_succeeds_next_step_is_rejected() {
        // 12 字节真实长度：放到倒数第二个位置，确认"恰好最后一个合法 nonce"成功。
        let mut counter = NonceCounter::at_value(&[
            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ]);
        assert_eq!(
            counter.next().unwrap(),
            &[0xFF; 12],
            "全 FF 是最后一个合法 nonce"
        );
        assert!(!counter.is_exhausted(), "尚未取尽时不得提前报错");
        assert!(
            matches!(counter.next(), Err(Error::NonceExhausted)),
            "再下一步就是复用首个 nonce，必须拒绝"
        );
        assert!(counter.is_exhausted());
    }

    #[test]
    fn exhausted_counter_stays_exhausted_and_never_resumes() {
        // 取尽是不可逆状态：反复取用继续报同一个错，永不恢复、不 panic，
        // 且内部值绝不落到"全 0"那种可与首个 nonce 重复的形态。
        let mut counter = NonceCounter::at_value(&[0xFD, 0xFF]);
        assert_eq!(counter.next().unwrap(), &[0xFE, 0xFF]);
        assert_eq!(counter.next().unwrap(), &[0xFF, 0xFF], "最后一个合法 nonce");
        for attempt in 0..8 {
            assert!(
                matches!(counter.next(), Err(Error::NonceExhausted)),
                "第 {attempt} 次重试仍必须拒绝"
            );
            assert!(counter.is_exhausted());
            assert_eq!(counter.counter, vec![0xFF, 0xFF], "拒绝步不得改动内部值");
        }
    }

    #[test]
    fn first_wrap_from_all_ff_is_the_zero_nonce_not_exhaustion() {
        // 唯一允许整串进位的一步是首步：全 FF → 全 0 是第一个合法 nonce，
        // 若把它误判为取尽会破坏与 Xray 的线格式互通（回归防护）。
        let mut counter = NonceCounter::new(2);
        assert_eq!(counter.next().unwrap(), &[0x00, 0x00]);
        assert!(!counter.is_exhausted());
        assert_eq!(counter.next().unwrap(), &[0x01, 0x00]);
    }

    #[test]
    fn zero_length_nonce_is_exhausted_from_the_start() {
        // nonce_len = 0 没有任何可用 nonce 形态：构造即取尽，取用一律报错。
        let mut counter = NonceCounter::new(0);
        assert!(counter.is_exhausted());
        assert!(
            matches!(counter.next(), Err(Error::NonceExhausted)),
            "零长度 nonce 不得返回空切片当作可用 nonce"
        );
        assert_eq!(NonceCounter::capacity(0), 0);
    }

    #[test]
    fn seal_reports_exhaustion_then_poisons_the_session() {
        // 恰好最后一个合法 nonce 的 seal 成功；再 seal 一次报 NonceExhausted，
        // 且对象永久 poison（继续报错，不会"跳过这一步"后恢复）。
        let subkey = vec![0xA5u8; 16];
        let mut seed = [0xFFu8; 12];
        seed[0] = 0xFE;
        let mut a = session_at_nonce(CipherSuite::Aes128Gcm, subkey, &seed);
        let last_ct = a.seal(b"last block").expect("最后一个合法 nonce 必须成功");
        assert!(!a.nonce_exhausted());
        assert!(matches!(
            a.seal(b"one block too many"),
            Err(Error::NonceExhausted)
        ));
        assert!(a.nonce_exhausted());
        for _ in 0..4 {
            assert!(matches!(a.seal(b"retry"), Err(Error::NonceExhausted)));
            assert!(matches!(a.open(&last_ct), Err(Error::NonceExhausted)));
        }
    }

    #[test]
    fn open_reports_exhaustion_on_the_same_poisoned_state() {
        // 读侧同样 fail-closed：取尽后 open 报 NonceExhausted，而不是被误判成
        // AuthFailed（认证失败与密钥耗尽必须可区分，上层据此决定断连原因）。
        let subkey = vec![0x5Au8; 32];
        let mut seed = [0xFFu8; 12];
        seed[0] = 0xFE;
        let mut a = session_at_nonce(CipherSuite::Aes256Gcm, subkey, &seed);
        assert!(matches!(a.open(&[0u8; 16]), Err(Error::AuthFailed)));
        assert!(matches!(a.open(&[0u8; 16]), Err(Error::NonceExhausted)));
        assert!(a.nonce_exhausted());
        assert!(matches!(a.seal(b"x"), Err(Error::NonceExhausted)));
    }

    #[test]
    fn exhaustion_error_message_holds_no_key_or_nonce_material() {
        // 错误文本必须是静态的：不含 subkey、nonce 字节、长度等任何可关联细节。
        let subkey = vec![0x42u8; 16];
        let mut seed = [0xFFu8; 12];
        seed[0] = 0xFE;
        let mut a = session_at_nonce(CipherSuite::Aes128Gcm, subkey.clone(), &seed);
        a.seal(b"x").unwrap();
        let rendered = a.seal(b"y").expect_err("必须报错").to_string();
        assert_eq!(
            rendered,
            "AEAD nonce space exhausted for this session key: refusing to reuse a nonce, rotate the key"
        );
        for byte in subkey.iter().chain(seed.iter()) {
            assert!(
                !rendered.contains(&format!("{byte:02x}")),
                "错误消息泄漏了字节 {byte:02x}"
            );
            assert!(!rendered.contains(&format!("{byte}")));
        }
        assert!(!rendered.contains('[') && !rendered.contains(']'));
        // Debug 形态同样不得带出密钥材料。
        let debugged = format!("{:?}", a.seal(b"z").err().unwrap());
        for byte in subkey.iter().chain(seed.iter()) {
            assert!(!debugged.contains(&format!("{byte:02x}")));
        }
    }

    #[test]
    fn suite_params_match_xray_table() {
        assert_eq!(CipherSuite::Aes128Gcm.key_len(), 16);
        assert_eq!(CipherSuite::Aes128Gcm.salt_len(), 16);
        assert_eq!(CipherSuite::Aes256Gcm.salt_len(), 32);
        assert_eq!(CipherSuite::ChaCha20IetfPoly1305.nonce_len(), 12);
        assert_eq!(CipherSuite::XChaCha20IetfPoly1305.nonce_len(), 24);
    }

    #[test]
    fn seal_open_roundtrip_all_suites() {
        for suite in [
            CipherSuite::Aes128Gcm,
            CipherSuite::Aes256Gcm,
            CipherSuite::ChaCha20IetfPoly1305,
            CipherSuite::XChaCha20IetfPoly1305,
        ] {
            let subkey = vec![7u8; suite.key_len()];
            let mut a = SessionAead::new(suite, subkey.clone());
            let mut b = SessionAead::new(suite, subkey);
            let pt = b"hello shadowsocks";
            let ct = a.seal(pt).unwrap();
            assert_eq!(ct.len(), pt.len() + 16);
            assert_eq!(b.open(&ct).unwrap(), pt);
        }
    }

    #[test]
    fn tampered_ct_fails_closed() {
        let subkey = vec![9u8; 16];
        let mut a = SessionAead::new(CipherSuite::Aes128Gcm, subkey.clone());
        let mut b = SessionAead::new(CipherSuite::Aes128Gcm, subkey);
        let mut ct = a.seal(b"data").unwrap();
        ct[0] ^= 0xFF;
        assert!(b.open(&ct).is_err());
    }
}
