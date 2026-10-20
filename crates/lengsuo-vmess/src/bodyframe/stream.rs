//! 无 AEAD 的 **chunk-stream** 分帧（参考 `common/crypto/chunk.go` 的
//! `ChunkStreamReader` / `ChunkStreamWriter`）。
//!
//! 什么时候走这条路径（参考 `proxy/vmess/encoding/{client,server}.go` 的
//! `SecurityType_NONE` 分支）：
//! ```text
//! if request.Option.Has(ChunkStream) {
//!     if command.TransferType() == TransferTypeStream {   // TCP
//!         return crypto.NewChunkStreamReader(sizeParser, reader), nil
//!     }
//!     … NoOpAuthenticator 的 AuthenticationReader（UDP 路径）…
//! }
//! return buf.NewReader(reader), nil                        // 无 ChunkStream：裸流
//! ```
//! 即 **`none` 档 + `ChunkStream` + TCP** 走本模块；`none` 档不带
//! `ChunkStream` 时参考退化成**无分帧裸流**（本模块不覆盖该形态，调用方不得
//! 使用）。
//!
//! 线格式（与 `AuthenticationReader/Writer` 的关键差异）：
//! ```text
//! BE16(载荷长度) || 明文载荷            （无掩码，PlainChunkSizeParser）
//! Shake128(iv) 掩码的 BE16(长度) || 明文载荷（chunkMasking，ShakeSizeParser）
//! ```
//! - **无 AEAD**：载荷是明文（`none` 档本就没有加密）。
//! - **无 padding**：`ChunkStreamReader/Writer` 从不调用 `NextPaddingLen`。
//! - 终止：长度段为 0 即 EOF（参考 `ChunkStreamReader.readSize` 的
//!   `nextSize == 0 → io.EOF`）。
//! - 单片上限 8192 字节（参考 `ChunkStreamWriter.WriteMultiBuffer` 的
//!   `const sliceSize = 8192`）。
//!
//! 长度段的掩码形态由 option 的 `ChunkMasking` 位决定；`AuthenticatedLength`
//! 在本路径**无效**（参考的 NONE 分支根本不看该选项）。

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::bodyframe::SizeMode;
use crate::chunkframe::DataSizeParser;
use crate::{Error, Result};

/// 参考 `ChunkStreamWriter.WriteMultiBuffer` 的单片上限（8192 字节）。
pub const CHUNK_STREAM_SLICE: usize = 8192;

/// chunk-stream 帧上下文：长度段形态 + 掩码流。
///
/// 不实现 `Debug`（内含掩码流状态，且与密钥派生相关）。
pub struct ChunkStreamFrame {
    mode: SizeMode,
    mask: Option<DataSizeParser>,
}

impl ChunkStreamFrame {
    /// 构造上下文。`mask` 传 `Some` 表示开启了 chunk 掩码（内部保存 Shake 状态）。
    #[must_use]
    pub fn new(mode: SizeMode, mask: Option<DataSizeParser>) -> Self {
        ChunkStreamFrame { mode, mask }
    }

    /// 按 option 字节构造（`ChunkMasking` 决定长度段是否掩码）。
    ///
    /// `AuthenticatedLength`（0x10）在本路径无效（参考的 NONE 分支不看它），
    /// 因此这里的 `mode` 只会是 `Plain` 或 `Masked`。
    pub fn for_option(option: u8) -> Self {
        const OPT_CHUNK_MASKING: u8 = 0x04;
        let masked = option & OPT_CHUNK_MASKING != 0;
        let mode = if masked {
            SizeMode::Masked
        } else {
            SizeMode::Plain
        };
        ChunkStreamFrame {
            mode,
            mask: masked.then(|| DataSizeParser::new(&[0u8; 16])),
        }
    }

    /// 用给定的 IV 播种掩码流（`NewShakeSizeParser(iv)`）。
    ///
    /// 掩码流的种子是**本方向**的 body IV：请求方向用 `requestBodyIV`，
    /// 响应方向用 `responseBodyIV`（参考 `EncodeResponseBody` /
    /// `DecodeResponseBody` 各自 `NewShakeSizeParser(s.responseBodyIV)`）。
    #[must_use]
    pub fn with_iv(option: u8, iv: &[u8; 16]) -> Self {
        const OPT_CHUNK_MASKING: u8 = 0x04;
        let masked = option & OPT_CHUNK_MASKING != 0;
        let mode = if masked {
            SizeMode::Masked
        } else {
            SizeMode::Plain
        };
        ChunkStreamFrame {
            mode,
            mask: masked.then(|| DataSizeParser::new(iv)),
        }
    }

    /// 长度段在线上的字节数（本路径恒 2）。
    #[must_use]
    pub const fn len_wire_len(&self) -> usize {
        2
    }

    /// 封一片：长度段 + **明文**载荷，追加到 `out`。
    ///
    /// `payload` 超过 [`CHUNK_STREAM_SLICE`] 时按参考的切分方式分成多片。
    pub fn seal(&mut self, out: &mut Vec<u8>, payload: &[u8]) -> Result<()> {
        for piece in payload.chunks(CHUNK_STREAM_SLICE) {
            let size = u16::try_from(piece.len()).map_err(|_| Error::BadLength {
                declared: piece.len(),
                got: u16::MAX as usize,
            })?;
            let size_wire = match self.mode {
                SizeMode::Masked => {
                    let mask = self.mask.as_mut().ok_or(Error::Unsupported {
                        feature: "masked size without chunk masking",
                    })?;
                    mask.encode_size(size)
                }
                _ => size.to_be_bytes(),
            };
            out.extend_from_slice(&size_wire);
            out.extend_from_slice(piece);
        }
        Ok(())
    }

    /// 封终止片：长度段为 0（掩码后）。
    pub fn seal_eof(&mut self, out: &mut Vec<u8>) -> Result<()> {
        let size_wire = match self.mode {
            SizeMode::Masked => {
                let mask = self.mask.as_mut().ok_or(Error::Unsupported {
                    feature: "masked size without chunk masking",
                })?;
                mask.encode_size(0)
            }
            _ => 0u16.to_be_bytes(),
        };
        out.extend_from_slice(&size_wire);
        Ok(())
    }

    /// 解一片（输入是「长度段 + 载荷」的完整字节）。`Ok(None)` = 终止片。
    pub fn open(&mut self, wire: &[u8]) -> Result<Option<Vec<u8>>> {
        if wire.len() < 2 {
            return Err(Error::Truncated {
                need: 2,
                got: wire.len(),
            });
        }
        let size = self.decode_size([wire[0], wire[1]])?;
        if size == 0 {
            return Ok(None);
        }
        let body = &wire[2..];
        if body.len() < size as usize {
            return Err(Error::Truncated {
                need: size as usize,
                got: body.len(),
            });
        }
        Ok(Some(body[..size as usize].to_vec()))
    }

    /// 从字节流同步解一片：读长度段 → 按长度读载荷。
    ///
    /// `Ok(None)` = 终止片；字节不足 = [`Error::Truncated`]。
    pub fn open_from(&mut self, stream: &mut &[u8]) -> Result<Option<Vec<u8>>> {
        if stream.len() < 2 {
            return Err(Error::Truncated {
                need: 2,
                got: stream.len(),
            });
        }
        let size = self.decode_size([stream[0], stream[1]])?;
        let total = 2 + size as usize;
        if stream.len() < total {
            return Err(Error::Truncated {
                need: total,
                got: stream.len(),
            });
        }
        let body = &stream[2..total];
        *stream = &stream[total..];
        if size == 0 {
            return Ok(None);
        }
        Ok(Some(body.to_vec()))
    }

    /// 解长度段（掩码流消耗 2 字节）。
    fn decode_size(&mut self, wire: [u8; 2]) -> Result<u16> {
        Ok(match self.mode {
            SizeMode::Masked => {
                let mask = self.mask.as_mut().ok_or(Error::Unsupported {
                    feature: "masked size without chunk masking",
                })?;
                mask.decode_size(wire)
            }
            _ => u16::from_be_bytes(wire),
        })
    }

    /// 异步写一片（明文载荷）。
    pub async fn write_to<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        payload: &[u8],
    ) -> Result<()> {
        let mut frame = Vec::with_capacity(payload.len() + 2);
        self.seal(&mut frame, payload)?;
        writer
            .write_all(&frame)
            .await
            .map_err(|error| crate::io_err(&error))
    }

    /// 异步写终止片。
    pub async fn write_eof<W: AsyncWrite + Unpin>(&mut self, writer: &mut W) -> Result<()> {
        let mut frame = Vec::with_capacity(2);
        self.seal_eof(&mut frame)?;
        writer
            .write_all(&frame)
            .await
            .map_err(|error| crate::io_err(&error))
    }

    /// 异步读一片。`Ok(None)` = 终止片；读端关闭/截断 = [`Error::Io`]。
    pub async fn read_from<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Vec<u8>>> {
        let mut size_wire = [0u8; 2];
        reader
            .read_exact(&mut size_wire)
            .await
            .map_err(|error| crate::io_err(&error))?;
        let size = self.decode_size(size_wire)?;
        if size == 0 {
            return Ok(None);
        }
        let mut body = vec![0u8; size as usize];
        reader
            .read_exact(&mut body)
            .await
            .map_err(|error| crate::io_err(&error))?;
        Ok(Some(body))
    }

    /// **同步**读一片（阻塞式 `Read`）。
    pub fn read_sync<R: std::io::Read>(&mut self, reader: &mut R) -> Result<Option<Vec<u8>>> {
        let mut size_wire = [0u8; 2];
        read_exact_sync(reader, &mut size_wire)?;
        let size = self.decode_size(size_wire)?;
        if size == 0 {
            return Ok(None);
        }
        let mut body = vec![0u8; size as usize];
        read_exact_sync(reader, &mut body)?;
        Ok(Some(body))
    }
}

/// 同步读满 `buf`；不足即 [`Error::Io`]（`UnexpectedEof`）。
fn read_exact_sync<R: std::io::Read>(reader: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader
            .read(&mut buf[filled..])
            .map_err(|error| crate::io_err(&error))?;
        if n == 0 {
            return Err(Error::Io("UnexpectedEof".to_string()));
        }
        filled += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const IV: [u8; 16] = *b"request-body-iv!";

    #[test]
    fn plain_roundtrip() {
        let mut seal = ChunkStreamFrame::with_iv(0x00, &IV);
        let mut open = ChunkStreamFrame::with_iv(0x00, &IV);
        let mut wire = Vec::new();
        seal.seal(&mut wire, b"hello").expect("可写");
        seal.seal_eof(&mut wire).expect("EOF 可写");
        let mut cursor = &wire[..];
        assert_eq!(
            open.open_from(&mut cursor).expect("可解").as_deref(),
            Some(&b"hello"[..])
        );
        assert!(open.open_from(&mut cursor).expect("可解").is_none());
        assert!(cursor.is_empty());
    }

    #[test]
    fn masked_roundtrip_and_iv_binding() {
        let mut seal = ChunkStreamFrame::with_iv(0x04, &IV);
        let mut open = ChunkStreamFrame::with_iv(0x04, &IV);
        let mut wire = Vec::new();
        seal.seal(&mut wire, b"masked").expect("可写");
        seal.seal_eof(&mut wire).expect("EOF 可写");
        // 换 IV 解不出来（掩码流种子不同）。
        let other = [0x11u8; 16];
        let mut wrong = ChunkStreamFrame::with_iv(0x04, &other);
        let mut wrong_cursor = &wire[..];
        assert!(wrong.open_from(&mut wrong_cursor).is_err());
        let mut cursor = &wire[..];
        assert_eq!(
            open.open_from(&mut cursor).expect("可解").as_deref(),
            Some(&b"masked"[..])
        );
        assert!(open.open_from(&mut cursor).expect("可解").is_none());
    }

    #[test]
    fn payload_is_plaintext_on_the_wire() {
        // `none` 档没有 AEAD：载荷必须是明文。
        let mut seal = ChunkStreamFrame::with_iv(0x00, &IV);
        let mut wire = Vec::new();
        seal.seal(&mut wire, b"PLAINTEXT").expect("可写");
        assert!(
            wire.windows(9).any(|w| w == b"PLAINTEXT"),
            "载荷必须以明文出现：{wire:?}"
        );
    }

    #[test]
    fn oversized_payload_is_split_into_slices() {
        let mut seal = ChunkStreamFrame::with_iv(0x00, &IV);
        let payload = vec![0x41u8; CHUNK_STREAM_SLICE + 10];
        let mut wire = Vec::new();
        seal.seal(&mut wire, &payload).expect("可写");
        let mut open = ChunkStreamFrame::with_iv(0x00, &IV);
        let mut cursor = &wire[..];
        let first = open.open_from(&mut cursor).expect("可解").expect("有片");
        let second = open.open_from(&mut cursor).expect("可解").expect("有片");
        assert_eq!(first.len(), CHUNK_STREAM_SLICE);
        assert_eq!(second.len(), 10);
    }
}
