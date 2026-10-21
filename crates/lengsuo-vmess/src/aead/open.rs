//! 服务端侧的分段/流式解头（`OpenVMessAEADHeader` 的服务端变体）。
//!
//! 语义来源：参考 `proxy/vmess/aead/encrypt.go` 的 `OpenVMessAEADHeader`，
//! 固定 commit `d2758a02`。与客户端切片版不同：这里按「先读 18B 长度密文、
//! 再读 8B 连接 nonce、再读 len+16B 载荷密文」的分段语义暴露给服务端，
//! 并用 [`OpenHeaderError`] 区分**两段 tag 失败**（参考 shouldDrain=true）
//! 与**读取不足**（参考 shouldDrain=false，直接断连）。

use crate::consts::{
    KDF_SALT_VMESS_HEADER_LEN_AEAD_IV, KDF_SALT_VMESS_HEADER_LEN_AEAD_KEY,
    KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV, KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY,
};

use super::internal::{aes128gcm_open, kdf12, kdf16_paths};

/// 服务端分段解头第一步：只解长度段（`length_ct` = 18B 长度密文，`nonce` =
/// 8B 连接 nonce）。异步服务端自行 read_exact 后调用；失败分类同流式版。
pub fn open_request_header_length(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    length_ct: &[u8; 18],
    nonce: &[u8; 8],
) -> std::result::Result<u16, OpenHeaderError> {
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
    let plain = aes128gcm_open(&length_key, &length_iv, length_ct, auth_id)
        .map_err(|_| OpenHeaderError::LengthTag)?;
    if plain.len() != 2 {
        return Err(OpenHeaderError::Truncated {
            need: 2,
            got: plain.len(),
        });
    }
    Ok(u16::from_be_bytes([plain[0], plain[1]]))
}

/// 服务端分段解头第二步：解载荷段（`ct` = `长度段声明的明文长度 + 16` 字节）。
pub fn open_request_header_payload(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    nonce: &[u8; 8],
    ct: &[u8],
) -> std::result::Result<Vec<u8>, OpenHeaderError> {
    let paths = [auth_id.as_slice(), nonce.as_slice()];
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
    aes128gcm_open(&payload_key, &payload_iv, ct, auth_id).map_err(|_| OpenHeaderError::PayloadTag)
}

/// 服务端流式解头的失败分类（对齐 `OpenVMessAEADHeader` 的 `(shouldDrain, err)`
/// 语义：两段 tag 失败参考置 shouldDrain=true，读取不足为 false）。
#[derive(Debug, thiserror::Error)]
pub enum OpenHeaderError {
    /// 长度段 AEAD 认证失败（参考 shouldDrain=true）。
    #[error("vmess header length AEAD tag invalid")]
    LengthTag,

    /// 载荷段 AEAD 认证失败（参考 shouldDrain=true）。
    #[error("vmess header payload AEAD tag invalid")]
    PayloadTag,

    /// 解出的长度明文不是 2 字节（不可达防御分支）。
    #[error("vmess header length plaintext malformed: need {need}, got {got}")]
    Truncated { need: usize, got: usize },

    /// 读取不足/连接断（参考 shouldDrain=false，直接断连）。
    #[error("io error: {0}")]
    Io(String),
}

/// `OpenVMessAEADHeader` 的流式版（服务端）：从 `reader` 依次读 18B 长度密文、
/// 8B 连接 nonce、`len+16`B 载荷密文并解密。返回 `(明文, 已读字节数)`。
///
/// `bytes_read` 对应参考的 bytesRead（供上层 drainer 的 AcknowledgeReceive 抵扣）；
/// 读取中途失败时不计入半读字节数（std `read_exact` 不上报部分读量，且本 crate
/// 的 drain 只需上界）。
pub fn open_vmess_aead_header_stream<R: std::io::Read>(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    reader: &mut R,
) -> std::result::Result<(Vec<u8>, usize), OpenHeaderError> {
    let mut bytes_read = 0usize;
    let mut length_ct = [0u8; 18];
    stream_read_full(reader, &mut length_ct, &mut bytes_read)?;
    let mut nonce = [0u8; 8];
    stream_read_full(reader, &mut nonce, &mut bytes_read)?;

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
    let length_plain = aes128gcm_open(&length_key, &length_iv, &length_ct, auth_id)
        .map_err(|_| OpenHeaderError::LengthTag)?;
    if length_plain.len() != 2 {
        return Err(OpenHeaderError::Truncated {
            need: 2,
            got: length_plain.len(),
        });
    }
    let length = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;

    let mut payload_ct = vec![0u8; length + 16];
    stream_read_full(reader, &mut payload_ct, &mut bytes_read)?;

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
    let plain = aes128gcm_open(&payload_key, &payload_iv, &payload_ct, auth_id)
        .map_err(|_| OpenHeaderError::PayloadTag)?;
    Ok((plain, bytes_read))
}

fn stream_read_full<R: std::io::Read>(
    reader: &mut R,
    buf: &mut [u8],
    bytes_read: &mut usize,
) -> std::result::Result<(), OpenHeaderError> {
    reader
        .read_exact(buf)
        .map_err(|e| OpenHeaderError::Io(format!("{:?}", e.kind())))?;
    *bytes_read += buf.len();
    Ok(())
}
