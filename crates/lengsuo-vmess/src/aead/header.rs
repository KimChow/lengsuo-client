//! 请求头的封装与解封（`SealVMessAEADHeader` / `OpenVMessAEADHeader`）。
//!
//! 语义来源：参考 `proxy/vmess/aead/encrypt.go`，固定 commit `d2758a02`。
//! 头部两段 AEAD 恒为 AES-128-GCM（AAD = AuthID），安全档不参与分派。

use crate::consts::{
    CONNECTION_NONCE_LEN, KDF_SALT_VMESS_HEADER_LEN_AEAD_IV, KDF_SALT_VMESS_HEADER_LEN_AEAD_KEY,
    KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV, KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY,
};
use crate::{Error, Result};

use super::internal::{aes128gcm_open, aes128gcm_seal, kdf12, kdf16_paths};
use super::HEADER_NONCE_LEN;

/// 头部 AEAD 的算法档位。
///
/// 参考把头部 AEAD 写死为 AES-128-GCM（`proxy/vmess/aead/encrypt.go`），
/// 因此本枚举只有「支持」与「显式拒绝 ChaCha」两态：列出 ChaCha 是为了让
/// 调用方**显式**表达「我以为头部也走 ChaCha」，从而得到一条清晰的
/// fail-closed 错误，而不是一次静默的算法错配。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderSuite {
    /// AES-128-GCM（参考唯一支持的档位）。
    Aes128Gcm,
    /// ChaCha20-Poly1305：参考**不支持**用于头部。
    ChaCha20Poly1305,
}

impl HeaderSuite {
    /// 校验该档位是否被参考支持；不支持即 fail-closed。
    pub fn require_supported(self) -> Result<()> {
        match self {
            Self::Aes128Gcm => Ok(()),
            Self::ChaCha20Poly1305 => Err(Error::Unsupported {
                feature: "chacha20-poly1305 for vmess header AEAD (reference uses AES-128-GCM)",
            }),
        }
    }
}

/// 按 `SealVMessAEADHeader` 封装请求头：随机 AuthID 与 8B 连接 nonce 由本函数
/// 生成（系统 CSPRNG，失败 fail-closed）。
///
/// `cmd_key` 是账号 ID 的 CmdKey（16 字节）；`payload` 是请求头明文
/// （版本+IV+key+响应种子+选项+安全+命令+地址+padding+FNV1a 校验，见
/// [`crate::request`]）。返回完整线上字节。
pub fn seal_vmess_aead_header(cmd_key: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    seal_vmess_aead_header_with(cmd_key, payload, HeaderSuite::Aes128Gcm)
}

/// **显式安全档**的请求头封装入口。
///
/// ⚠️ **安全档不改变头部 AEAD 的算法**——参考
/// `proxy/vmess/aead/encrypt.go` 的 `SealVMessAEADHeader` 与
/// `OpenVMessAEADHeader` 两侧都写死 `crypto.NewAesGcm`，头部两段恒为
/// AES-128-GCM；安全档只作用于**数据段**（见 [`crate::bodyframe`]）。
/// 本函数因此只接受 `HeaderSuite::Aes128Gcm`；`ChaCha20Poly1305` 显式拒绝
/// （fail-closed），**不会**把头部悄悄降级成 ChaCha 或明文。
///
/// `None` 档同样不影响头部（参考的 `SecurityType_NONE` 只改数据段）。
pub fn seal_vmess_aead_header_with(
    cmd_key: &[u8],
    payload: &[u8],
    suite: HeaderSuite,
) -> Result<Vec<u8>> {
    suite.require_supported()?;
    if payload.len() > u16::MAX as usize {
        return Err(Error::BadLength {
            declared: payload.len(),
            got: u16::MAX as usize,
        });
    }
    // AuthID 明文里的时间戳由本函数取当前时间；随机段 CSPRNG。
    let mut random = [0u8; 4];
    crate::fill_random(&mut random)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Random)?
        .as_secs() as i64;
    let auth = crate::authid::create_auth_id_with(cmd_key, now, &random);
    let mut connection_nonce = [0u8; CONNECTION_NONCE_LEN];
    crate::fill_random(&mut connection_nonce)?;
    Ok(seal_header_with(
        cmd_key,
        auth.as_bytes(),
        &connection_nonce,
        payload,
    ))
}

/// 确定性封装（测试/向量）：AuthID 与连接 nonce 由调用方提供。
///
/// # Panics
/// 不 panic；长度异常走 [`Error::BadLength`]。
#[must_use]
pub fn seal_header_with(
    cmd_key: &[u8],
    auth_id: &[u8; 16],
    connection_nonce: &[u8; HEADER_NONCE_LEN],
    payload: &[u8],
) -> Vec<u8> {
    let paths = [auth_id.as_slice(), connection_nonce.as_slice()];
    // 长度段：2 字节 BE16 明文 + tag，AAD = AuthID。
    let length_key = kdf16_paths(
        cmd_key,
        KDF_SALT_VMESS_HEADER_LEN_AEAD_KEY.as_bytes(),
        &paths,
    );
    let length_iv = kdf12(
        cmd_key,
        KDF_SALT_VMESS_HEADER_LEN_AEAD_IV.as_bytes(),
        &paths,
    );
    let length_plain = (payload.len() as u16).to_be_bytes();
    let length_ct = aes128gcm_seal(&length_key, &length_iv, &length_plain, auth_id);

    // 载荷段。
    let payload_key = kdf16_paths(
        cmd_key,
        KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY.as_bytes(),
        &paths,
    );
    let payload_iv = kdf12(
        cmd_key,
        KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV.as_bytes(),
        &paths,
    );
    let payload_ct = aes128gcm_seal(&payload_key, &payload_iv, payload, auth_id);

    let mut wire = Vec::with_capacity(16 + length_ct.len() + 8 + payload_ct.len());
    wire.extend_from_slice(auth_id);
    wire.extend_from_slice(&length_ct);
    wire.extend_from_slice(connection_nonce);
    wire.extend_from_slice(&payload_ct);
    wire
}

/// `OpenVMessAEADHeader` 的切片版：输入 = 18B 长度密文 + 8B nonce + 载荷密文。
/// AuthID 由调用方从线上前 16 字节取出传入（参考签名里它单独传递）。
///
/// 成功返回明文；任何认证失败 fail-closed。`read_exact` 式截断用
/// [`Error::Truncated`] 报告（need/got 均为线上字节计数）。
pub fn open_vmess_aead_header(cmd_key: &[u8], auth_id: &[u8; 16], wire: &[u8]) -> Result<Vec<u8>> {
    open_vmess_aead_header_with(cmd_key, auth_id, wire, HeaderSuite::Aes128Gcm)
}

/// **显式安全档**的请求头解封装入口。
///
/// 同 [`seal_vmess_aead_header_with`]：参考头部 AEAD 恒为 AES-128-GCM，
/// `ChaCha20Poly1305` 显式 fail-closed，不会静默按 AES 解。
pub fn open_vmess_aead_header_with(
    cmd_key: &[u8],
    auth_id: &[u8; 16],
    wire: &[u8],
    suite: HeaderSuite,
) -> Result<Vec<u8>> {
    suite.require_supported()?;
    open_vmess_aead_header_inner(cmd_key, auth_id, wire)
}

fn open_vmess_aead_header_inner(
    cmd_key: &[u8],
    auth_id: &[u8; 16],
    wire: &[u8],
) -> Result<Vec<u8>> {
    const LENGTH_CT: usize = 18;
    if wire.len() < LENGTH_CT + HEADER_NONCE_LEN {
        return Err(Error::Truncated {
            need: LENGTH_CT + HEADER_NONCE_LEN,
            got: wire.len(),
        });
    }
    let length_ct = &wire[..LENGTH_CT];
    let nonce: [u8; HEADER_NONCE_LEN] = wire[LENGTH_CT..LENGTH_CT + HEADER_NONCE_LEN]
        .try_into()
        .expect("8 字节");
    let payload_ct = &wire[LENGTH_CT + HEADER_NONCE_LEN..];

    let paths = [auth_id.as_slice(), nonce.as_slice()];
    let length_key = kdf16_paths(
        cmd_key,
        KDF_SALT_VMESS_HEADER_LEN_AEAD_KEY.as_bytes(),
        &paths,
    );
    let length_iv = kdf12(
        cmd_key,
        KDF_SALT_VMESS_HEADER_LEN_AEAD_IV.as_bytes(),
        &paths,
    );
    let length_plain = aes128gcm_open(&length_key, &length_iv, length_ct, auth_id)?;
    if length_plain.len() != 2 {
        return Err(Error::BadLength {
            declared: length_plain.len(),
            got: 2,
        });
    }
    let payload_len = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;
    if payload_ct.len() < payload_len + 16 {
        return Err(Error::Truncated {
            need: payload_len + 16,
            got: payload_ct.len(),
        });
    }
    // 声明长度之后有多余字节：参考 io.Reader 流式读取不会出现；切片输入按
    // 严格消费处理（调用方应把载荷之后的应用字节另行分帧）。
    if payload_ct.len() != payload_len + 16 {
        return Err(Error::BadLength {
            declared: payload_len + 16,
            got: payload_ct.len(),
        });
    }
    let payload_key = kdf16_paths(
        cmd_key,
        KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY.as_bytes(),
        &paths,
    );
    let payload_iv = kdf12(
        cmd_key,
        KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV.as_bytes(),
        &paths,
    );
    aes128gcm_open(&payload_key, &payload_iv, payload_ct, auth_id)
}

/// 从完整线上头部提取 AuthID（前 16 字节）；不足即截断。
pub fn parse_auth_id_from_header(wire: &[u8]) -> Result<[u8; 16]> {
    if wire.len() < 16 {
        return Err(Error::Truncated {
            need: 16,
            got: wire.len(),
        });
    }
    Ok(wire[..16].try_into().expect("16 字节"))
}
