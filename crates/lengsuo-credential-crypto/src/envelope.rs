//! 信封格式（Envelope v1）。
//!
//! 契约 §1：
//!
//! ```text
//! envelope = header(24B) || rp_id(rp_id_len) || aaguid(16) || wrapped_dek || priv_ciphertext
//!
//! header:
//!   [0..4)   magic          u32 大端 = 0x4C534347  ("LSCG")
//!   [4..8)   version        u32 大端 = 1
//!   [8..12)  wrapped_dek_len u32 大端 = 60
//!   [12..16) ciphertext_len u32 大端
//!   [16..20) aaguid_len     u32 大端 = 16
//!   [20..22) rp_id_len      u16 大端
//!   [22..24) flags          u16 大端（本次签名的标志位快照）
//! ```
//!
//! ⚠️ **字节序一律大端（网络序）**——跨仓最容易错的一处，测试用固定向量钉死。
//!
//! ⚠️ **`wrapped_dek` = `nonce(12) || tag(16) || ciphertext(32)` = 60 字节**
//! （契约 §1.2.1 明写「**不是 32**，也不是 28」：GCM 是流模式、无块填充
//! ⇒ 密文长度 == 明文长度 ⇒ 32 字节 DEK ⇒ 密文 32 字节 ⇒ 12+16+32 = 60）。
//! 契约 §1.1 的示意图里写「wrapped_dek 32 字节」，与 §1.2.1 的算式冲突；
//! **以 §1.2.1 为准**（它显式否定了 32 这个读法），详见交付报告。
//!
//! ⚠️ **`priv_ciphertext` 总长 = N + 28**（N = PKCS#8 DER 长度，**不是固定值**）
//! ⇒ 头里的 `ciphertext_len` 存的是**总长**（N+28），不是 N。
//!
//! ⚠️ **AAD = header 全部字节**（24 + rp_id_len）⇒ 改 header 会解封失败（防篡改）。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use zeroize::Zeroizing;

use crate::entropy::Entropy;
use crate::error::Error;

/// 信封魔数：`0x4C534347`（ASCII "LSCG"）。
pub const ENVELOPE_MAGIC: u32 = 0x4C53_4347;

/// 信封版本。
pub const ENVELOPE_VERSION: u32 = 1;

/// 固定头长度（不含 rp_id）。
pub const HEADER_LEN: usize = 24;

/// `wrapped_dek` 长度：`nonce(12) || tag(16) || ciphertext(32)`。
pub const WRAPPED_DEK_LEN: usize = 60;

/// GCM nonce 长度。
pub const NONCE_LEN: usize = 12;

/// GCM tag 长度（附在密文尾部）。
pub const TAG_LEN: usize = 16;

/// DEK 长度。
pub const DEK_LEN: usize = 32;

/// 主密钥长度。
pub const MASTER_KEY_LEN: usize = 32;

/// `priv_ciphertext` 的固定开销：`nonce(12) || tag(16)`。
pub const PRIV_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// aaguid 长度（恒为 16 字节全零）。
pub const AAGUID_LEN: usize = 16;

/// 密文固定长度段（aaguid）之后的偏移增量。
const AAGUID_OFFSET_FROM_RP: usize = AAGUID_LEN;

/// 一个已封好的信封。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// 固定头字节（24 字节）。
    pub header: [u8; HEADER_LEN],
    /// rp_id（UTF-8）。
    pub rp_id: String,
    /// aaguid（恒为 16 字节全零）。
    pub aaguid: [u8; AAGUID_LEN],
    /// 被主密钥包裹的 DEK（60 字节）。
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
    /// 私钥密文（`nonce(12) || tag(16) || ct(N)`）。
    pub priv_ciphertext: Vec<u8>,
}

impl Envelope {
    /// 整段字节。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            HEADER_LEN
                + self.rp_id.len()
                + AAGUID_LEN
                + WRAPPED_DEK_LEN
                + self.priv_ciphertext.len(),
        );
        out.extend_from_slice(&self.header);
        out.extend_from_slice(self.rp_id.as_bytes());
        out.extend_from_slice(&self.aaguid);
        out.extend_from_slice(&self.wrapped_dek);
        out.extend_from_slice(&self.priv_ciphertext);
        out
    }

    /// 头里的 `ciphertext_len` 字段（= `priv_ciphertext` 总长 = N + 28）。
    pub fn ciphertext_len(&self) -> u32 {
        u32::from_be_bytes([
            self.header[12],
            self.header[13],
            self.header[14],
            self.header[15],
        ])
    }
}

/// 封信封所需的参数。
#[derive(Debug, Clone)]
pub struct SealParams<'a> {
    /// rp_id（UTF-8，字节长度写进头里）。
    pub rp_id: &'a str,
    /// 本次签名的标志位快照（取 authData 的 u8 flags 拓宽到 u16）。
    pub flags: u8,
    /// 包裹 DEK 用的服务端主密钥（32 字节）。
    pub master_key: &'a [u8; MASTER_KEY_LEN],
    /// 数据加密密钥（32 字节）。
    pub dek: &'a [u8; DEK_LEN],
    /// 要加密的私钥明文（标准 PKCS#8 DER）。
    pub private_key_pkcs8: &'a [u8],
}

/// 构造固定头。
fn build_header(
    rp_id: &str,
    flags: u8,
    wrapped_dek_len: u32,
    ciphertext_len: u32,
    rp_id_len: u16,
) -> Result<[u8; HEADER_LEN], Error> {
    let rp_id_bytes = rp_id.as_bytes();
    if rp_id_bytes.len() > usize::from(u16::MAX) {
        return Err(Error::InvalidLength {
            expected: usize::from(u16::MAX),
            actual: rp_id_bytes.len(),
        });
    }
    let mut header = [0u8; HEADER_LEN];
    header[0..4].copy_from_slice(&ENVELOPE_MAGIC.to_be_bytes());
    header[4..8].copy_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    header[8..12].copy_from_slice(&wrapped_dek_len.to_be_bytes());
    header[12..16].copy_from_slice(&ciphertext_len.to_be_bytes());
    header[16..20].copy_from_slice(&(AAGUID_LEN as u32).to_be_bytes());
    header[20..22].copy_from_slice(&rp_id_len.to_be_bytes());
    header[22..24].copy_from_slice(&(u16::from(flags)).to_be_bytes());
    Ok(header)
}

/// 封一个信封。
///
/// 步骤：
/// 1. 先算 `priv_ciphertext` 的总长（N + 28）⇒ 填 `ciphertext_len`；
/// 2. 用完整 header（24 + rp_id_len 字节）作 AAD 加密私钥；
/// 3. 用主密钥包裹 DEK ⇒ `nonce(12) || tag(16) || ct(32)` = 60 字节。
///
/// ⚠️ **熵注入点**：`entropy` 依次提供 priv 密文 nonce（12 字节）与
/// wrapped_dek nonce（12 字节）⇒ 固定熵 ⇒ 输出完全确定。
pub fn seal(params: &SealParams<'_>, entropy: &mut impl Entropy) -> Result<Envelope, Error> {
    let rp_id_bytes = params.rp_id.as_bytes();
    let rp_id_len = u16::try_from(rp_id_bytes.len()).map_err(|_| Error::InvalidLength {
        expected: usize::from(u16::MAX),
        actual: rp_id_bytes.len(),
    })?;
    let ciphertext_len = params
        .private_key_pkcs8
        .len()
        .checked_add(PRIV_OVERHEAD)
        .ok_or(Error::InvalidLength {
            expected: 0,
            actual: params.private_key_pkcs8.len(),
        })?;
    let ciphertext_len_u32 = u32::try_from(ciphertext_len).map_err(|_| Error::InvalidLength {
        expected: u32::MAX as usize,
        actual: ciphertext_len,
    })?;

    let header = build_header(
        params.rp_id,
        params.flags,
        WRAPPED_DEK_LEN as u32,
        ciphertext_len_u32,
        rp_id_len,
    )?;
    // AAD = header 全部字节（24 + rp_id_len）。
    let mut aad = Vec::with_capacity(HEADER_LEN + rp_id_bytes.len());
    aad.extend_from_slice(&header);
    aad.extend_from_slice(rp_id_bytes);

    // 私钥密文。
    let mut priv_nonce = [0u8; NONCE_LEN];
    entropy.fill(&mut priv_nonce)?;
    let priv_ct = gcm_seal(params.dek, &priv_nonce, params.private_key_pkcs8, &aad)?;
    // 契约 §1.2.1：`priv_ciphertext = nonce(12) || tag(16) || ct(N)`（tag 在前）。
    // aes-gcm 的原生输出是 `ct || tag` ⇒ 这里重排成契约布局。
    let mut priv_ciphertext = Vec::with_capacity(priv_ct.len());
    priv_ciphertext.extend_from_slice(&priv_nonce);
    priv_ciphertext.extend_from_slice(&priv_ct[priv_ct.len() - TAG_LEN..]);
    priv_ciphertext.extend_from_slice(&priv_ct[..priv_ct.len() - TAG_LEN]);

    // DEK 包裹（服务端主密钥）。
    let mut wrap_nonce = [0u8; NONCE_LEN];
    entropy.fill(&mut wrap_nonce)?;
    let wrapped = gcm_seal(params.master_key, &wrap_nonce, params.dek, &[])?;
    let mut wrapped_dek = [0u8; WRAPPED_DEK_LEN];
    // `gcm_seal` 的输出是 `ct || tag` = 32 + 16 = 48 字节；nonce 单独拼在最前
    // ⇒ 契约布局 `nonce(12) || tag(16) || ct(32)` 共 60 字节。
    if wrapped.len() != WRAPPED_DEK_LEN - NONCE_LEN {
        return Err(Error::InvalidLength {
            expected: WRAPPED_DEK_LEN - NONCE_LEN,
            actual: wrapped.len(),
        });
    }
    // 契约 §1.2.1：`wrapped_dek = nonce(12) || tag(16) || ciphertext(32)`（tag 在前）。
    wrapped_dek[0..NONCE_LEN].copy_from_slice(&wrap_nonce);
    wrapped_dek[NONCE_LEN..NONCE_LEN + TAG_LEN]
        .copy_from_slice(&wrapped[wrapped.len() - TAG_LEN..]);
    wrapped_dek[NONCE_LEN + TAG_LEN..].copy_from_slice(&wrapped[..wrapped.len() - TAG_LEN]);

    Ok(Envelope {
        header,
        rp_id: params.rp_id.to_owned(),
        aaguid: [0u8; AAGUID_LEN],
        wrapped_dek,
        priv_ciphertext,
    })
}

/// 拆开信封（只做结构解析，不解密）。
pub fn parse(bytes: &[u8]) -> Result<Envelope, Error> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::InvalidLength {
            expected: HEADER_LEN,
            actual: bytes.len(),
        });
    }
    let mut header = [0u8; HEADER_LEN];
    header.copy_from_slice(&bytes[0..HEADER_LEN]);
    if u32::from_be_bytes([header[0], header[1], header[2], header[3]]) != ENVELOPE_MAGIC {
        return Err(Error::EnvelopeBadMagic);
    }
    let version = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    if version != ENVELOPE_VERSION {
        return Err(Error::EnvelopeVersion {
            expected: ENVELOPE_VERSION,
            got: version,
        });
    }
    let wrapped_dek_len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    if wrapped_dek_len != WRAPPED_DEK_LEN as u32 {
        return Err(Error::EnvelopeLength {
            declared: wrapped_dek_len as usize,
            actual: WRAPPED_DEK_LEN,
        });
    }
    let ciphertext_len =
        u32::from_be_bytes([header[12], header[13], header[14], header[15]]) as usize;
    let aaguid_len = u32::from_be_bytes([header[16], header[17], header[18], header[19]]) as usize;
    if aaguid_len != AAGUID_LEN {
        return Err(Error::EnvelopeLength {
            declared: aaguid_len,
            actual: AAGUID_LEN,
        });
    }
    let rp_id_len = u16::from_be_bytes([header[20], header[21]]) as usize;
    let rp_start = HEADER_LEN;
    let rp_end = rp_start + rp_id_len;
    let aaguid_end = rp_end + AAGUID_OFFSET_FROM_RP;
    let wrapped_end = aaguid_end + WRAPPED_DEK_LEN;
    let ct_end = wrapped_end + ciphertext_len;
    if bytes.len() != ct_end {
        return Err(Error::EnvelopeLength {
            declared: ct_end,
            actual: bytes.len(),
        });
    }
    let rp_id = std::str::from_utf8(&bytes[rp_start..rp_end])
        .map_err(|_| Error::InvalidLength {
            expected: rp_id_len,
            actual: 0,
        })?
        .to_owned();
    let mut aaguid = [0u8; AAGUID_LEN];
    aaguid.copy_from_slice(&bytes[rp_end..aaguid_end]);
    let mut wrapped_dek = [0u8; WRAPPED_DEK_LEN];
    wrapped_dek.copy_from_slice(&bytes[aaguid_end..wrapped_end]);
    Ok(Envelope {
        header,
        rp_id,
        aaguid,
        wrapped_dek,
        priv_ciphertext: bytes[wrapped_end..ct_end].to_vec(),
    })
}

/// 解开信封：先验签解包 DEK，再解私钥。
///
/// 认证失败一律 [`Error::EnvelopeAuthFailed`]（fail-closed，不回退明文）。
pub fn open(
    envelope: &Envelope,
    master_key: &[u8; MASTER_KEY_LEN],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut wrap_nonce = [0u8; NONCE_LEN];
    wrap_nonce.copy_from_slice(&envelope.wrapped_dek[0..NONCE_LEN]);
    // wrapped_dek 布局是 `nonce || tag || ct` ⇒ 送进 aes-gcm 前换回 `ct || tag`。
    let mut wrapped_ct = Vec::with_capacity(WRAPPED_DEK_LEN - NONCE_LEN);
    wrapped_ct.extend_from_slice(&envelope.wrapped_dek[NONCE_LEN + TAG_LEN..]);
    wrapped_ct.extend_from_slice(&envelope.wrapped_dek[NONCE_LEN..NONCE_LEN + TAG_LEN]);
    let dek = gcm_open(master_key, &wrap_nonce, &wrapped_ct, &[])?;
    if dek.len() != DEK_LEN {
        return Err(Error::InvalidLength {
            expected: DEK_LEN,
            actual: dek.len(),
        });
    }
    let mut dek_array = [0u8; DEK_LEN];
    dek_array.copy_from_slice(&dek);

    let mut aad = Vec::with_capacity(HEADER_LEN + envelope.rp_id.len());
    aad.extend_from_slice(&envelope.header);
    aad.extend_from_slice(envelope.rp_id.as_bytes());

    let ct = &envelope.priv_ciphertext;
    if ct.len() < PRIV_OVERHEAD {
        return Err(Error::InvalidLength {
            expected: PRIV_OVERHEAD,
            actual: ct.len(),
        });
    }
    let mut priv_nonce = [0u8; NONCE_LEN];
    priv_nonce.copy_from_slice(&ct[0..NONCE_LEN]);
    // priv_ciphertext 布局是 `nonce || tag || ct` ⇒ 送进 aes-gcm 前换回 `ct || tag`。
    let mut priv_ct = Vec::with_capacity(ct.len() - NONCE_LEN);
    priv_ct.extend_from_slice(&ct[NONCE_LEN + TAG_LEN..]);
    priv_ct.extend_from_slice(&ct[NONCE_LEN..NONCE_LEN + TAG_LEN]);
    let plain = gcm_open(&dek_array, &priv_nonce, &priv_ct, &aad)?;
    Ok(Zeroizing::new(plain))
}

/// AES-256-GCM 密封，产出 `ct || tag`（aes-gcm 的原生布局）。
fn gcm_seal(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    plain: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidLength {
        expected: 32,
        actual: key.len(),
    })?;
    cipher
        .encrypt(nonce.into(), Payload { msg: plain, aad })
        .map_err(|_| Error::EnvelopeAuthFailed)
}

/// AES-256-GCM 解封，输入须是 `ct || tag` 布局。
fn gcm_open(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    ct_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    if ct_tag.len() < TAG_LEN {
        return Err(Error::InvalidLength {
            expected: TAG_LEN,
            actual: ct_tag.len(),
        });
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidLength {
        expected: 32,
        actual: key.len(),
    })?;
    cipher
        .decrypt(nonce.into(), Payload { msg: ct_tag, aad })
        .map_err(|_| Error::EnvelopeAuthFailed)
}
