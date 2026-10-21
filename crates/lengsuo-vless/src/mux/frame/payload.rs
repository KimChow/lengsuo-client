//! 帧数据段：同步/异步的 `BE16 长度 || 数据` 读写与整帧写出。
//!
//! 从父模块拆出以保持单文件 ≤400 行（软约束）。语义逐条对齐参考
//! `common/mux/frame.go` 的 `PacketReader` / `NewStreamReader` / `writeMetaWithFrame`。

use std::io::Read;

use super::meta::{FrameError, FrameMetadata};
use super::{DATA_LIMIT, MAX_META_LEN, STREAM_CHUNK_SIZE};

/// 会话数据段读端（`PacketReader.ReadMultiBuffer` / `NewStreamReader`）：
/// `BE16 长度 || 数据`。
///
/// `stream` 为 true 时语义等价 `buf.SplitSize(mb, 8192)` 的一帧：长度 1..=8192；
/// 为 false 时等价 `PacketReader`：长度 1..=buf.Size(8192)，且**每帧独立**（参考
/// `r.eof = true`：单会话数据方向只读一帧）。两路上限一致，参考在 `size > buf.Size`
/// 时才报错，故 0 长度在参考中同样被接受（空 multi-buffer 由上层 `IsEmpty` 处理）。
pub fn read_data<R: Read>(reader: &mut R, stream: bool) -> Result<Vec<u8>, FrameError> {
    let mut len_wire = [0u8; 2];
    read_exact(reader, &mut len_wire)?;
    let size = u16::from_be_bytes(len_wire);
    let limit = if stream {
        STREAM_CHUNK_SIZE
    } else {
        DATA_LIMIT
    } as u16;
    if size > limit {
        return Err(FrameError::PacketTooLarge { size });
    }
    let mut body = vec![0u8; usize::from(size)];
    read_exact(reader, &mut body)?;
    Ok(body)
}

/// 会话数据段写端：`BE16 长度 || 数据`（参考 `serial.WriteUint16(frame, data.Len())`）。
pub fn encode_data_into(out: &mut Vec<u8>, payload: &[u8]) -> Result<(), FrameError> {
    let len =
        u16::try_from(payload.len()).map_err(|_| FrameError::PacketTooLarge { size: u16::MAX })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// 异步版 [`FrameMetadata::decode_from`]：直接在 tokio 流上读一个完整帧头。
///
/// 语义与同步版逐条一致（同一 `decode_meta`），仅读入方式不同。参考在
/// `buf.BufferedReader` 上工作，本仓为 tokio 调用方提供等价入口。
pub async fn decode_from_async<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    read_source_and_local: bool,
) -> Result<FrameMetadata, FrameError> {
    use tokio::io::AsyncReadExt;
    let meta_len = usize::from(reader.read_u16().await.map_err(io_error)?);
    if meta_len > MAX_META_LEN {
        return Err(FrameError::MetaTooLong);
    }
    let mut body = vec![0u8; meta_len];
    reader.read_exact(&mut body).await.map_err(io_error)?;
    FrameMetadata::decode_meta(&body, read_source_and_local)
}

/// 异步版 [`read_data`]：读 `BE16 长度 || 数据`，上限同同步版。
pub async fn read_data_async<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    stream: bool,
) -> Result<Vec<u8>, FrameError> {
    use tokio::io::AsyncReadExt;
    let size = reader.read_u16().await.map_err(io_error)?;
    let limit = if stream {
        STREAM_CHUNK_SIZE
    } else {
        DATA_LIMIT
    } as u16;
    if size > limit {
        return Err(FrameError::PacketTooLarge { size });
    }
    let mut body = vec![0u8; usize::from(size)];
    reader.read_exact(&mut body).await.map_err(io_error)?;
    Ok(body)
}

/// 异步写：把一个完整帧（元数据 + 可选数据段）写入 tokio 流。
pub async fn write_frame_async<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    meta: &FrameMetadata,
    payload: Option<&[u8]>,
) -> Result<(), FrameError> {
    use tokio::io::AsyncWriteExt;
    let mut wire = Vec::with_capacity(64 + payload.map_or(0, <[u8]>::len));
    meta.encode_into(&mut wire)?;
    if let Some(payload) = payload {
        encode_data_into(&mut wire, payload)?;
    }
    writer.write_all(&wire).await.map_err(io_error)?;
    writer.flush().await.map_err(io_error)
}

fn io_error(error: std::io::Error) -> FrameError {
    FrameError::Io(format!("{:?}", error.kind()))
}

/// 读满 `buf`；EOF / 短读都映射为 [`FrameError::Io`]（错误文本与拆分前一致）。
pub(super) fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), FrameError> {
    reader
        .read_exact(buf)
        .map_err(|error| FrameError::Io(format!("{:?}", error.kind())))
}
