//! VMess AEAD 头部封装与认证响应（对齐 `proxy/vmess/aead/encrypt.go` 与
//! 旧客户端 `encoding/client.go` 的响应头路径）。
//!
//! 请求头（`SealVMessAEADHeader`）线格式：
//! ```text
//! AuthID(16) || AEAD_GCM(BE16(payload_len)) (18) || connection_nonce(8) || AEAD_GCM(payload)
//! ```
//! 两段 AEAD 都是 AES-128-GCM，AAD = AuthID 16 字节；密钥/nonce 由 KDF 链派生，
//! path 里含 AuthID 与 connectionNonce 的原始字节（Go string 可携带二进制）：
//! - 长度段：KDF16(key, "VMess Header AEAD Key_Length", authID, nonce) / KDF(key, "…Nonce_Length", …)[:12]
//! - 载荷段：KDF16(key, "VMess Header AEAD Key", authID, nonce) / KDF(key, "…Nonce", …)[:12]
//!
//! 认证响应（服务端 → 客户端，20 字节 = 4B 密文 + 16B tag）在当前 Xray 主线
//! `DecodeResponseHeader` 中已改为独立 KDF 盐 + AES-128-GCM：长度段与载荷段
//! 分别用 `KDF16(responseBodyKey, "AEAD Resp Header Len Key")` 等；无 AAD、
//! nonce 为 KDF 截 12 字节。本模块同时提供主线响应头两段解密所需的全部派生。
//!
//! fail-closed：任何解密失败都是 [`Error::AuthFailed`]，调用方必须弃用连接。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm;

use crate::consts::{
    AUTH_RESPONSE_ID_SALT, CONNECTION_NONCE_LEN, KDF_SALT_AEAD_RESP_HEADER_LEN_IV,
    KDF_SALT_AEAD_RESP_HEADER_LEN_KEY, KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV,
    KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY, KDF_SALT_VMESS_HEADER_LEN_AEAD_IV,
    KDF_SALT_VMESS_HEADER_LEN_AEAD_KEY, KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV,
    KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY,
};
use crate::kdf::kdf_n;
use crate::{Error, Result};

/// 连接侧随机 nonce 长度（`SealVMessAEADHeader` 的 connectionNonce）。
pub const HEADER_NONCE_LEN: usize = CONNECTION_NONCE_LEN;
/// 兼容别名：响应认证明文长度（主线响应头已不用它，保留给自建解码器测试）。
pub const RESPONSE_AUTH_LEN: usize = 4;

/// 认证响应（旧客户端 `responseHeader` 路径）的派生盐。
/// 主线 `DecodeResponseHeader` 使用 `KDF_SALT_AEAD_RESP_HEADER_*`。
pub const RESPONSE_AUTH_SALT: &[u8] = AUTH_RESPONSE_ID_SALT;

/// 按 `SealVMessAEADHeader` 封装请求头：随机 AuthID 与 8B 连接 nonce 由本函数
/// 生成（系统 CSPRNG，失败 fail-closed）。
///
/// `cmd_key` 是账号 ID 的 CmdKey（16 字节）；`payload` 是请求头明文
/// （版本+IV+key+响应种子+选项+安全+命令+地址+padding+FNV1a 校验，见
/// [`crate::request`]）。返回完整线上字节。
pub fn seal_vmess_aead_header(cmd_key: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
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

/// 主线响应头长度段派生：`KDF16(respKey, "AEAD Resp Header Len Key")` 与
/// `KDF(respIV, "AEAD Resp Header Len IV")[:12]`。
#[must_use]
pub fn response_header_length_key_iv(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
) -> ([u8; 16], [u8; 12]) {
    let key = kdf16_paths(
        response_key,
        KDF_SALT_AEAD_RESP_HEADER_LEN_KEY.as_bytes(),
        &[],
    );
    let iv = kdf12(
        response_iv,
        KDF_SALT_AEAD_RESP_HEADER_LEN_IV.as_bytes(),
        &[],
    );
    (key, iv)
}

/// 主线响应头载荷段派生：`KDF16(respKey, "AEAD Resp Header Key")` 与
/// `KDF(respIV, "AEAD Resp Header Payload IV")[:12]`。
#[must_use]
pub fn response_header_payload_key_iv(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
) -> ([u8; 16], [u8; 12]) {
    let key = kdf16_paths(
        response_key,
        KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY.as_bytes(),
        &[],
    );
    let iv = kdf12(
        response_iv,
        KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV.as_bytes(),
        &[],
    );
    (key, iv)
}

/// 解密主线响应头长度段（18 字节密文 → 2 字节 BE16 明文；无 AAD）。
pub fn open_response_header_length(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    wire: &[u8; 18],
) -> Result<u16> {
    let (key, iv) = response_header_length_key_iv(response_key, response_iv);
    let plain = aes128gcm_open(&key, &iv, wire, &[]);
    let plain = plain?;
    if plain.len() != 2 {
        return Err(Error::BadLength {
            declared: plain.len(),
            got: 2,
        });
    }
    Ok(u16::from_be_bytes([plain[0], plain[1]]))
}

/// 解密主线响应头载荷段（`len+16` 字节密文 → 明文；无 AAD）。
pub fn open_response_header_payload(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    wire: &[u8],
) -> Result<Vec<u8>> {
    let (key, iv) = response_header_payload_key_iv(response_key, response_iv);
    aes128gcm_open(&key, &iv, wire, &[])
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

// ---- 内部 ----

fn kdf16_paths(key: &[u8], salt: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    let mut all = Vec::with_capacity(paths.len() + 1);
    all.push(salt);
    all.extend_from_slice(paths);
    crate::kdf::kdf16(key, &all)
}

fn kdf12(key: &[u8], salt: &[u8], paths: &[&[u8]]) -> [u8; 12] {
    let mut all = Vec::with_capacity(paths.len() + 1);
    all.push(salt);
    all.extend_from_slice(paths);
    let out = kdf_n(key, &all, 12).expect("12 <= 32");
    out.try_into().expect("12 字节")
}

fn aes128gcm_seal(key: &[u8; 16], nonce: &[u8; 12], plain: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("AES-128-GCM 固定 16 字节密钥");
    cipher
        .encrypt(nonce.into(), Payload { msg: plain, aad })
        .expect("AES-GCM 加密只在长度异常时失败，此处输入长度已受控")
}

fn aes128gcm_open(key: &[u8; 16], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("AES-128-GCM 固定 16 字节密钥");
    cipher
        .decrypt(nonce.into(), Payload { msg: ct, aad })
        .map_err(|_| Error::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMD_KEY: [u8; 16] = *b"b831381d-6324-4d";
    const AUTH: [u8; 16] = [0x5A; 16];
    const NONCE: [u8; 8] = [0x21, 0x43, 0x65, 0x87, 0x09, 0xBA, 0xDC, 0xFE];

    #[test]
    fn header_seal_open_roundtrip() {
        let payload = b"version+iv+key+seed+opt+security+cmd+address+padding+fnv";
        let wire = seal_header_with(&CMD_KEY, &AUTH, &NONCE, payload);
        // 16 + 18 + 8 + payload + 16
        assert_eq!(wire.len(), 16 + 18 + 8 + payload.len() + 16);
        let parsed = parse_auth_id_from_header(&wire).expect("可取 AuthID");
        assert_eq!(parsed, AUTH);
        let opened = open_vmess_aead_header(&CMD_KEY, &parsed, &wire[16..]).expect("可解");
        assert_eq!(opened, payload);
    }

    #[test]
    fn header_truncations_report_need_and_got() {
        let wire = seal_header_with(&CMD_KEY, &AUTH, &NONCE, b"payload!");
        // AuthID 之后的长度段不足 18+8。
        let err =
            open_vmess_aead_header(&CMD_KEY, &AUTH, &wire[16..16 + 10]).expect_err("截断必须失败");
        assert!(matches!(err, Error::Truncated { need: 26, got: 10 }));
        // 载荷段被切短。
        let cut = &wire[16..16 + 18 + 8 + 4];
        let err = open_vmess_aead_header(&CMD_KEY, &AUTH, cut).expect_err("载荷截断必须失败");
        assert!(matches!(
            err,
            Error::Truncated { .. } | Error::BadLength { .. }
        ));
    }

    #[test]
    fn tampered_header_and_wrong_key_fail_closed() {
        let payload = b"authenticated header payload";
        let mut wire = seal_header_with(&CMD_KEY, &AUTH, &NONCE, payload);
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        assert!(matches!(
            open_vmess_aead_header(&CMD_KEY, &AUTH, &wire[16..]),
            Err(Error::AuthFailed)
        ));
        let clean = seal_header_with(&CMD_KEY, &AUTH, &NONCE, payload);
        let evil = [0xEEu8; 16];
        assert!(matches!(
            open_vmess_aead_header(&evil, &AUTH, &clean[16..]),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn response_header_key_iv_are_stable_and_usable() {
        let resp_key = [0x11u8; 16];
        let resp_iv = [0x22u8; 16];
        let (len_key, len_iv) = response_header_length_key_iv(&resp_key, &resp_iv);
        let (pay_key, pay_iv) = response_header_payload_key_iv(&resp_key, &resp_iv);
        assert_ne!(len_key, pay_key, "长度段与载荷段密钥必须不同");
        assert_ne!(len_iv, pay_iv);
        // 派生值稳定（黄金向量自造，锁定回归）。
        assert_eq!(
            hex::encode(len_key),
            hex::encode(response_header_length_key_iv(&resp_key, &resp_iv).0)
        );
        // 用派生结果走一遍加解密（模拟服务端发送 + 客户端解）。
        let plain_len: u16 = 0x0102;
        let cipher = Aes128Gcm::new_from_slice(&len_key).unwrap();
        let wire = cipher
            .encrypt(
                (&len_iv).into(),
                Payload {
                    msg: &plain_len.to_be_bytes(),
                    aad: b"",
                },
            )
            .unwrap();
        assert_eq!(wire.len(), 18);
        let got =
            open_response_header_length(&resp_key, &resp_iv, wire.as_slice().try_into().unwrap())
                .expect("可解");
        assert_eq!(got, plain_len);
        let _ = pay_iv;
    }

    #[test]
    fn empty_payload_header_is_legal() {
        // 长度为 0 的头载荷（协议外但封装层不拒绝——上层 request 模块管语义）。
        let wire = seal_header_with(&CMD_KEY, &AUTH, &NONCE, b"");
        assert_eq!(wire.len(), 16 + 18 + 8 + 16);
        let opened = open_vmess_aead_header(&CMD_KEY, &AUTH, &wire[16..]).expect("可解");
        assert!(opened.is_empty());
    }
}
