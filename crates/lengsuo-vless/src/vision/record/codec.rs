//! 记录头与长度的编解码：对齐 `common.go` 的 `EncodeLength` / `DecodeLength` /
//! `EncodeHeader` / `DecodeHeader`。
//!
//! 从 [`super`] 拆出以保持单文件 ≤400 行（软约束）；纯函数、无状态。

use super::Error;

/// 记录头魔数（`EncodeHeader`：`h[0]=23, h[1]=3, h[2]=3`）。
pub const MAGIC: [u8; 3] = [23, 3, 3];
/// 记录头长度：3 字节魔数 + BE16 记录体长度前缀。
pub const HEADER_LEN: usize = 5;
/// 记录体最小长度（`DecodeHeader` 的 `l < 17` 判据，即 1 字节明文 + 16 字节 tag）。
pub const MIN_BODY_LEN: usize = 17;
/// 记录体最大长度（TLS 1.3 16384 + 256，RFC 8446 §5.2）。
pub const MAX_BODY_LEN: usize = 16640;

/// 参考 `EncodeLength`：BE16 长度。
pub fn encode_length(length: usize) -> [u8; 2] {
    [(length >> 8) as u8, length as u8]
}

/// 参考 `DecodeLength`。
pub fn decode_length(bytes: &[u8]) -> usize {
    (usize::from(bytes[0]) << 8) | usize::from(bytes[1])
}

/// 参考 `EncodeHeader`：`h[0..3] = 23,3,3` + BE16 记录体长度。
pub fn encode_header(header: &mut [u8; HEADER_LEN], body_len: usize) {
    header[0] = MAGIC[0];
    header[1] = MAGIC[1];
    header[2] = MAGIC[2];
    header[3] = (body_len >> 8) as u8;
    header[4] = body_len as u8;
}

/// 参考 `DecodeHeader`：魔数不符或长度越界即失败；成功返回记录体长度。
pub fn decode_header(header: &[u8; HEADER_LEN]) -> Result<usize, Error> {
    let mut body_len = decode_length(&header[3..5]);
    if header[..3] != MAGIC {
        // 参考把长度清 0 后继续；0 < 17 必然落入越界分支，此处直接报非法头。
        body_len = 0;
    }
    if !(MIN_BODY_LEN..=MAX_BODY_LEN).contains(&body_len) {
        return Err(Error::InvalidHeader);
    }
    Ok(body_len)
}
