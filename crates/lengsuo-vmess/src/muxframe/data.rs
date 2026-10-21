//! Mux 会话的数据段读写（`NewStreamReader` + `PacketReader`）。
//!
//! 线格式：`BE16 长度 || 数据`。

use std::io::Read;

use super::error::FrameError;
use super::meta::SESSION_CHUNK_SIZE;

/// 会话数据段读端（`NewStreamReader` + `PacketReader`）：`BE16 长度 || 数据`。
///
/// `stream` 为 true 时语义等价 `buf.SplitSize(mb, 8192)` 的一帧（长度 1..=8192）；
/// 为 false 时等价 `PacketReader`（长度 1..=buf.Size，且**每帧独立**。
/// 由调用方按会话 transferType 选择。
pub fn read_data<R: Read>(reader: &mut R, stream: bool) -> Result<Vec<u8>, FrameError> {
    let mut len_wire = [0u8; 2];
    read_exact(reader, &mut len_wire)?;
    let size = u16::from_be_bytes(len_wire);
    let limit = if stream { SESSION_CHUNK_SIZE } else { 8192 } as u16;
    if size > limit {
        return Err(FrameError::PacketTooLarge { size });
    }
    let mut body = vec![0u8; usize::from(size)];
    read_exact(reader, &mut body)?;
    Ok(body)
}

/// 会话数据段写端：`BE16 长度 || 数据`。
pub fn encode_data_into(out: &mut Vec<u8>, payload: &[u8]) -> Result<(), FrameError> {
    let len =
        u16::try_from(payload.len()).map_err(|_| FrameError::PacketTooLarge { size: u16::MAX })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

pub(super) fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), FrameError> {
    reader
        .read_exact(buf)
        .map_err(|error| FrameError::Io(format!("{:?}", error.kind())))
}
