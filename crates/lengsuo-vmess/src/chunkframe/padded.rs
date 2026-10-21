// ---- GlobalPadding 版分帧（对齐 common/crypto/auth.go 的 Reader/Writer）----
//
// 与无 padding 版的关键差异（不可混用同一条掩码流）：
// - 每 chunk 的掩码流消耗顺序是 **先 NextPaddingLen(2B) 后 Encode/Decode(2B)**
//   （`AuthenticationWriter.seal` 与 `AuthenticationReader.readSize` 一致）；
// - padding 是**明文**随机字节，追加在 AEAD 密文之后，不参与认证；
// - 声明长度 = 载荷密文长度（含 tag）+ paddingLen；
// - EOF 帧 = `AEAD(空)`（即仅 tag）+ padding，声明长度 = overhead + paddingLen。

use crate::{Error, Result};

use super::cipher::{cipher_overhead, DataCipher};
use super::size::DataSizeParser;
use super::MAX_CHUNK_PAYLOAD;

/// 读端第一步：从 2 字节线上 size 还原 `(声明长度, 本 chunk 的 paddingLen)`。
/// 与写端逐 chunk 的掩码流消耗保持同步（先 padding 后 mask）。
#[must_use]
pub fn read_padded_size(mask: &mut DataSizeParser, size_wire: [u8; 2]) -> (u16, u16) {
    let padding = mask.next_padding_len();
    let declared = mask.decode_size(size_wire);
    (declared, padding)
}

/// 读端第二步：解密一个已完整读入的 chunk（`wire` = 声明长度的载荷字节，
/// 即 `载荷密文 || padding`）。`Ok(None)` = EOF 帧（声明长度恰为
/// `overhead + padding`）。
pub fn open_padded_chunk(
    cipher: &mut DataCipher,
    wire: &[u8],
    padding_len: u16,
) -> Result<Option<Vec<u8>>> {
    let overhead = cipher_overhead(cipher);
    let padding = padding_len as usize;
    if wire.len() < padding + overhead {
        return Err(Error::Truncated {
            need: padding + overhead,
            got: wire.len(),
        });
    }
    let ct_len = wire.len() - padding;
    if ct_len == overhead {
        // 参考判据：size == overhead + padding 即 EOF（空载荷帧）。
        return Ok(None);
    }
    let plain = cipher.open_payload(&wire[..ct_len], ct_len - overhead)?;
    Ok(Some(plain))
}

/// 写端：封一个带 padding 的 chunk（size 段 + 载荷密文 + 明文 padding）。
/// 空 `payload` 即 EOF 帧。
pub fn seal_padded_chunk(
    cipher: &mut DataCipher,
    mask: &mut DataSizeParser,
    out: &mut Vec<u8>,
    payload: &[u8],
) -> Result<()> {
    if payload.len() > MAX_CHUNK_PAYLOAD {
        return Err(Error::BadLength {
            declared: payload.len(),
            got: MAX_CHUNK_PAYLOAD,
        });
    }
    let padding = mask.next_padding_len() as usize;
    let ct = cipher.seal_payload(payload)?;
    let declared = ct.len() + padding;
    let declared = u16::try_from(declared).map_err(|_| Error::BadLength {
        declared,
        got: u16::MAX as usize,
    })?;
    out.extend_from_slice(&mask.encode_size(declared));
    out.extend_from_slice(&ct);
    let mut pad_bytes = vec![0u8; padding];
    crate::fill_random(&mut pad_bytes)?;
    out.extend_from_slice(&pad_bytes);
    Ok(())
}
