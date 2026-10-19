//! VMess 服务端响应头封装（对齐 `proxy/vmess/encoding/server.go` 的
//! `EncodeResponseHeader`，固定 commit d2758a02）。
//!
//! 响应密钥派生（server.go:330-333，客户端 `client.go` 对称实现）：
//! ```text
//! responseBodyKey = SHA256(requestBodyKey)[:16]
//! responseBodyIV  = SHA256(requestBodyIV)[:16]
//! ```
//! 响应头明文 = `responseHeader(1B，请求头字节 33 原样回带) || Option(1B) || 0x00 || 0x00`
//! ——后两个零字节是参考 `MarshalCommand(nil)` 返回 ErrUnknownCommand 后的兜底
//! 写入（server.go:343-346）；本层不实现 switch 命令，恒走该兜底分支。
//!
//! 线格式（两段独立 AES-128-GCM，无 AAD，nonce = KDF 截 12 字节）：
//! ```text
//! AEAD(BE16(明文长度))(18B) || AEAD(明文)(4B+16B)
//! ```
//! 共 38 字节。数据段密钥也换用 responseBodyKey/IV（见 [`response_key_iv`]）。

use sha2::{Digest, Sha256};

use crate::aead::{
    response_header_length_key_iv, response_header_payload_key_iv, seal_response_header_length,
    seal_response_header_payload,
};
use crate::{Error, Result};

/// 响应头明文长度（本层恒 4 字节：seed + option + 两个兜底零字节）。
pub const RESPONSE_HEADER_PLAINTEXT_LEN: usize = 4;
/// 响应头线上总长：18B 长度段 + (4B 明文 + 16B tag) 载荷段。
pub const RESPONSE_HEADER_WIRE_LEN: usize = 18 + RESPONSE_HEADER_PLAINTEXT_LEN + 16;

/// 响应头字段（switch 命令不在本层，见模块文档）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseHeader {
    /// 响应选项字节（回填进明文第 2 字节）。
    pub option: u8,
}

impl ResponseHeader {
    /// option = 0 的常规响应。
    #[must_use]
    pub const fn new() -> Self {
        ResponseHeader { option: 0 }
    }
}

impl Default for ResponseHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// `responseBodyKey/IV = SHA256(requestBodyKey/IV)[:16]`（响应头与响应体共用）。
#[must_use]
pub fn response_key_iv(
    request_body_key: &[u8; 16],
    request_body_iv: &[u8; 16],
) -> ([u8; 16], [u8; 16]) {
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&Sha256::digest(request_body_key)[..16]);
    iv.copy_from_slice(&Sha256::digest(request_body_iv)[..16]);
    (key, iv)
}

/// 封装完整响应头并写入 `out`（追加 `RESPONSE_HEADER_WIRE_LEN` 字节）。
///
/// `response_seed` 是解码请求时得到的响应头种子（必须原样回带，客户端以此
/// 校验响应归属）。确定性纯函数：不引入随机性（AEAD nonce 由 KDF 派生）。
pub fn encode_response_header(
    response_seed: u8,
    request_body_key: &[u8; 16],
    request_body_iv: &[u8; 16],
    header: &ResponseHeader,
    out: &mut Vec<u8>,
) -> Result<()> {
    let (resp_key, resp_iv) = response_key_iv(request_body_key, request_body_iv);
    let plaintext = [response_seed, header.option, 0x00, 0x00];

    let (length_key, length_nonce) = response_header_length_key_iv(&resp_key, &resp_iv);
    out.extend_from_slice(&seal_response_header_length(
        &length_key,
        &length_nonce,
        plaintext.len() as u16,
    ));

    let (payload_key, payload_nonce) = response_header_payload_key_iv(&resp_key, &resp_iv);
    out.extend_from_slice(&seal_response_header_payload(
        &payload_key,
        &payload_nonce,
        &plaintext,
    ));
    if out.len() < RESPONSE_HEADER_WIRE_LEN {
        // 不可达：两段 seal 输出长度恒定；防御性检查避免未来改动悄悄变短。
        return Err(Error::BadLength {
            declared: out.len(),
            got: RESPONSE_HEADER_WIRE_LEN,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::{open_response_header_length, open_response_header_payload};

    const REQ_KEY: [u8; 16] = [0x11u8; 16];
    const REQ_IV: [u8; 16] = [0x22u8; 16];
    const SEED: u8 = 0xAB;

    #[test]
    fn wire_layout_is_38_bytes_and_roundtrips() {
        let mut wire = Vec::new();
        encode_response_header(SEED, &REQ_KEY, &REQ_IV, &ResponseHeader::new(), &mut wire)
            .expect("可封装");
        assert_eq!(wire.len(), RESPONSE_HEADER_WIRE_LEN);

        let (resp_key, resp_iv) = response_key_iv(&REQ_KEY, &REQ_IV);
        let length_ct: [u8; 18] = wire[..18].try_into().expect("18 字节");
        let plain_len =
            open_response_header_length(&resp_key, &resp_iv, &length_ct).expect("长度段可解");
        assert_eq!(plain_len as usize, RESPONSE_HEADER_PLAINTEXT_LEN);
        let plain =
            open_response_header_payload(&resp_key, &resp_iv, &wire[18..]).expect("载荷段可解");
        assert_eq!(plain, vec![SEED, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn response_key_iv_differs_from_request_key_material() {
        let (resp_key, resp_iv) = response_key_iv(&REQ_KEY, &REQ_IV);
        assert_ne!(resp_key, REQ_KEY, "响应密钥必须是 SHA256 派生而非原样");
        assert_ne!(resp_iv, REQ_IV);
        // 确定性：同输入同输出。
        assert_eq!(resp_key, response_key_iv(&REQ_KEY, &REQ_IV).0);
    }
}
