//! 数据段的异步读写（流式写端 / 读端）。
//!
//! 语义与 [`super::frame`] 的同步单帧版本同源（参考
//! `common/crypto/auth.go` 的 `AuthenticationReader` / `AuthenticationWriter`），
//! 只是 I/O 换成 tokio 的 `AsyncRead` / `AsyncWrite`。

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Error, Result};

use super::cipher::{cipher_overhead, DataCipher};
use super::frame::seal_data_chunk;
use super::size::DataSizeParser;

/// 异步写出单个 chunk（流式写端版）。
pub async fn write_data_chunk<W: AsyncWrite + Unpin>(
    cipher: &mut DataCipher,
    size_parser: Option<&mut DataSizeParser>,
    writer: &mut W,
    payload: &[u8],
) -> Result<()> {
    let mut frame = Vec::with_capacity(cipher.wire_len(payload.len()));
    seal_data_chunk(cipher, size_parser, &mut frame, payload)?;
    writer
        .write_all(&frame)
        .await
        .map_err(|error| Error::Io(format!("{:?}", error.kind())))
}

/// 异步写出终止帧。
pub async fn write_eof<W: AsyncWrite + Unpin>(
    cipher: &mut DataCipher,
    size_parser: Option<&mut DataSizeParser>,
    writer: &mut W,
) -> Result<()> {
    write_data_chunk(cipher, size_parser, writer, &[]).await
}

/// 异步读取单个 chunk（带总超时语义由调用方包裹）。`Ok(None)` = EOF。
pub async fn read_data_chunk<R: AsyncRead + Unpin>(
    cipher: &mut DataCipher,
    size_parser: Option<&mut DataSizeParser>,
    reader: &mut R,
) -> Result<Option<Vec<u8>>> {
    let mut size_wire = [0u8; 2];
    reader
        .read_exact(&mut size_wire)
        .await
        .map_err(|error| crate::io_err(&error))?;
    let declared = match size_parser {
        Some(parser) => parser.decode_size(size_wire),
        None => u16::from_be_bytes(size_wire),
    };
    if declared == 0 {
        // 线上声明 0 只在 none 安全下出现（无 tag 可解）；按 EOF 处理。
        return Ok(None);
    }
    let mut body = vec![0u8; declared as usize];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|error| crate::io_err(&error))?;
    let plain_len = declared as usize - cipher_overhead(cipher);
    let plain = cipher.open_payload(&body, plain_len)?;
    if plain.is_empty() {
        // 参考语义：解出的明文长度 0 = 流终止（AuthenticationReader EOF）。
        return Ok(None);
    }
    Ok(Some(plain))
}

/// [`read_data_chunk`] 的写进缓冲版。
pub async fn read_data_chunk_into<R: AsyncRead + Unpin>(
    cipher: &mut DataCipher,
    size_parser: Option<&mut DataSizeParser>,
    reader: &mut R,
    out: &mut Vec<u8>,
) -> Result<bool> {
    match read_data_chunk(cipher, size_parser, reader).await? {
        Some(plain) => {
            out.extend_from_slice(&plain);
            Ok(true)
        }
        None => Ok(false),
    }
}
