//! 无 GlobalPadding 的数据段分帧（同步单帧语义）。
//!
//! 语义来源：参考 `common/crypto/auth.go` 的 `AuthenticationWriter` /
//! `AuthenticationReader`（`PlainChunkSizeParser` / `ShakeSizeParser` 两种
//! 长度段形态），固定 commit `d2758a02`。

use crate::{Error, Result};

use super::cipher::{cipher_overhead, DataCipher};
use super::size::{plain_size_encode, DataSizeParser};
use super::MAX_CHUNK_PAYLOAD;

/// 同步写出单个 chunk 到内存缓冲（`AuthenticationWriter` 的单帧语义）。
/// `size_parser` 为 `Some` 时启用 chunkMasking；写 EOF（空载荷）产生
/// "声明长度 0" 帧。
pub fn seal_data_chunk(
    cipher: &mut DataCipher,
    size_parser: Option<&mut DataSizeParser>,
    out: &mut Vec<u8>,
    payload: &[u8],
) -> Result<()> {
    if payload.len() > MAX_CHUNK_PAYLOAD {
        return Err(Error::BadLength {
            declared: payload.len(),
            got: MAX_CHUNK_PAYLOAD,
        });
    }
    let ct = cipher.seal_payload(payload)?;
    let declared = u16::try_from(ct.len()).map_err(|_| Error::BadLength {
        declared: ct.len(),
        got: u16::MAX as usize,
    })?;
    let size_wire = match size_parser {
        Some(parser) => parser.encode_size(declared),
        None => plain_size_encode(declared),
    };
    out.extend_from_slice(&size_wire);
    out.extend_from_slice(&ct);
    Ok(())
}

/// 终止帧：声明长度 0（掩码后），无载荷。
pub fn write_data_eof(
    cipher: &mut DataCipher,
    size_parser: Option<&mut DataSizeParser>,
    out: &mut Vec<u8>,
) -> Result<()> {
    seal_data_chunk(cipher, size_parser, out, &[])
}

/// 同步读取单个 chunk（`AuthenticationReader` 单帧语义）。`Ok(None)` = EOF 帧。
/// 输入缓冲必须恰好包含一帧（由调用方按需切片）。
pub fn open_data_chunk(
    cipher: &mut DataCipher,
    size_parser: Option<&mut DataSizeParser>,
    wire: &[u8],
) -> Result<Option<Vec<u8>>> {
    if wire.len() < 2 {
        return Err(Error::Truncated {
            need: 2,
            got: wire.len(),
        });
    }
    let declared = match size_parser {
        Some(parser) => parser.decode_size([wire[0], wire[1]]),
        None => u16::from_be_bytes([wire[0], wire[1]]),
    };
    if declared == 0 {
        return Ok(None);
    }
    let body = &wire[2..];
    if body.len() < declared as usize {
        return Err(Error::Truncated {
            need: declared as usize,
            got: body.len(),
        });
    }
    if body.len() != declared as usize {
        return Err(Error::BadLength {
            declared: declared as usize,
            got: body.len(),
        });
    }
    let plain_len = declared as usize - cipher_overhead(cipher);
    let plain = cipher.open_payload(body, plain_len)?;
    if plain.is_empty() {
        return Ok(None);
    }
    Ok(Some(plain))
}
